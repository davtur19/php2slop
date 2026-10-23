# Moodle as a stock consumer of the PHP-FPM `BG(serialize)` stale-state UAF

**Status:** negative for a normal Moodle request. The normal consumer path reaches
`php_add_var_hash()` with the Moodle session object/reference values, but it does so
**after** `PHP_RINIT(basic)` has reset `BG(serialize)`. A preceding producer can leave a
fully populated stale table, yet the normal Moodle request starts with a fresh serializer.
The exact blocker is the request-lifecycle ordering, plus the absence of a stock producer
inside the body caps. No stock producer/consumer chain was found.

This report does **not** claim a working stock chain. It records the measured negative and
the source-verified reason, and it separates a deliberately artificial diagnostic producer
from the stock claim.

---

## 1. Bottom line

1. **Normal Moodle request (8.5.11):** HTTP 200, 19,595-byte body. Moodle creates/updates a
   688-byte file session containing `USER|O:8:"stdClass":...` and
   `SESSION|O:8:"stdClass":...`. GDB on the single worker shows:
   - `php_request_startup`: `lock=0 level=0 data=0`
   - `php_session_flush` / `php_var_serialize_init`: `lock=0 level=0 data=0`
   - first `php_add_var_hash`: fresh `data`, `ht.nNumUsed=0`
   - `php_var_serialize_destroy`: `level=1`, then `level=0`
   - response 200, worker alive.
2. **Artificial stale-state producer (diagnostic only, not stock):** a standalone script
   that OOMs inside `serialize()` leaves the worker alive with
   `lock=0 level=1 data=<request-heap pointer>, ht.nNumUsed=16, ht.nTableSize=16`.
   This is the strongest possible stale state (a full table), i.e. the same condition that
   makes the pre-RINIT upload-progress consumer crash.
3. **Normal Moodle request after that producer (8.5.11):** at `php_request_startup` the
   stale state is still present (`level=1`, `nNumUsed=16`); by the time
   `php_session_flush` and `php_var_serialize_init` run, it is `level=0 data=0`. The
   first `php_add_var_hash` uses a **fresh** table (`nNumUsed=0`). HTTP 200, worker alive,
   session file rewritten.
4. **8.5.12 fixed control:** the same producer returns 500 but leaves
   `lock=0 level=0 data=0` in the idle worker; the following normal Moodle request is 200
   and `php_var_serialize_init` sees `level=0`. The fixed build adds
   `php_basic_early_rinit()` before `sapi_activate()` (and also changed its OOM handling);
   the measured control is clean regardless of which of those mechanisms removes the
   stale state.
5. **Exact blocker:** `PHP_RINIT(basic)` in 8.5.11 resets `BG(serialize)` after
   `sapi_activate()` and before the script runs. Moodle's session write is a normal
   end-of-request shutdown action (`core_shutdown_manager` -> `manager::write_close`), so
   it is always post-RINIT. Only PHP's eager pre-RINIT multipart upload-progress callback
   can read the stale table before the reset; a normal Moodle request does not set the two
   fields that callback requires, and the upload-progress scalar consumer is explicitly
   out of scope for the final stock claim.

---

## 2. Lab and constraints

| Item | Value |
|---|---|
| Moodle | 5.0.10+ (Build 20261002), full tree, `moodle/` |
| Database | MariaDB 11.4.5, `127.0.0.1:13306`, database `moodle` |
| PHP 8.5.11 | `/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm` |
| PHP 8.5.12 | `/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.12/php-fpm` |
| FPM | single static worker, `pm.max_children=1`, `127.0.0.1:19500` |
| ASLR | `/proc/sys/kernel/randomize_va_space = 2` |
| Pool limits | `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`, `display_errors=Off` |
| Session | Moodle file handler under `moodledata/sessions`; `session.serialize_handler=php` |
| Other | `max_input_vars=5000` (more permissive than stock PHP default 1000; kept for Moodle install) |

Final 8.5.11 process for the stale-state test: master PID **215904**, worker PID
**215909**. 8.5.12 control: master PID **164112**, worker PID **164117**.

### Stock-tree disclosure

The Moodle tree is stock except for `admin/environment.xml`, where the `zip`, `gd`, and
`sodium` extension requirements were relaxed from `required` to `optional` because the
full PHP build available in this lab lacks those shared extensions. The session code,
HTTP routing, and lifecycle were not modified. The original file is preserved as
`evidence/environment.xml.stock2`; the current file parses as valid XML. A login POST
reaches `core\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES` because `sodium` is absent, so the
normal-request test uses a guest session on `/login/index.php`; Moodle creates the same
`USER`/`SESSION` stdClass objects and the same references for a guest. This limitation
does not affect the serializer lifecycle result, which is determined by PHP RINIT/shutdown
ordering.

`max_input_vars=5000` and the lack of `zip`/`gd`/`sodium` are the only non-stock
environment details relevant to this test. They make the producer search **more**
permissive (more input variables), not less.

---

## 3. Normal Moodle request (clean worker, 8.5.11)

Request:

```text
GET /login/index.php
Cookie: MoodleSession=b4dc8152224101380aa9a2ed45b059bd
```

Measured result:

- HTTP 200, body 19,595 bytes (`evidence/moodle_final_stale_traced.raw`,
  `evidence/moodle_8512_after_producer.raw` for the control).
- Session file `moodledata/sessions/sess_b4dc8152224101380aa9a2ed45b059bd`, 688 bytes,
  SHA-256 after the traced request:
  `464ae9572fd749e1a71358c80cdcd2618d17a10eefd1f79bc5763a4016de61f0`.
- File prefix:

```text
USER|O:8:"stdClass":6:{s:2:"id";i:0;...}
SESSION|O:8:"stdClass":...
```

The GDB trace (`evidence/gdb_moodle_normal_raw.log`, clean worker before the producer)
showed:

```text
TRACE reqstart#1        lock=0 level=0 data=0x0
TRACE session_flush#1   lock=0 level=0 data=0x0
TRACE ser_init#1        lock=0 level=0 data=0x0
TRACE addvar#1          lock=0 level=1 data=<fresh> ht.nNumUsed=0 ht.nTableSize=16
TRACE ser_destroy#1     lock=0 level=1 data=<fresh> ht.nNumUsed=8
TRACE accept-detach     lock=0 level=0 data=0x0
```

The `php_add_var_hash` stack is the Moodle session path:

```text
php_add_var_hash
php_var_serialize_intern
php_var_serialize
ps_srlzr_encode_php
php_session_flush
zif_session_write_close
user_shutdown_function_call
zend_hash_apply
```

This is the normal session-write path. It does call `php_add_var_hash()` for the Moodle
`USER`/`SESSION` values, but only on a newly allocated `php_serialize_data`.

Source for the Moodle reference wiring:

- `moodle/lib/classes/session/manager.php:185-186`:
  `$GLOBALS['USER'] = $_SESSION['USER']; $_SESSION['USER'] =& $GLOBALS['USER'];`
  and the same for `SESSION`.
- `moodle/lib/classes/session/manager.php:292,310-311`:
  `init_empty_session()` creates `new \stdClass()` and assigns the same references.
- `moodle/lib/setup.php:907`: `\core\session\manager::start();`
- `moodle/lib/classes/shutdown_manager.php:56`: registers the shutdown handler;
  `:204-205`: calls `\core\session\manager::write_close()`.
- `moodle/lib/classes/session/manager.php:687-734`: `write_close()` delegates to the
  session handler, which calls PHP's session write/`php_session_encode()`.

---

## 4. Diagnostic producer and post-producer Moodle request (8.5.11)

The producer is **not stock** and is not part of the final stock claim. It is the proven
primitive from the FPM logic lab, copied temporarily into the Moodle docroot as
`probe_producer.php`, then moved to `evidence/probe_producer.php` and removed from the
docroot before the final clean request. It is a standalone script that builds 8 objects and
60 MiB of strings and calls `serialize($a)` under `memory_limit=128M`, causing an OOM
inside `serialize()`.

Request:

```text
GET /probe_producer.php?k=8&n=60
```

Measured result:

- HTTP 500, no body (`evidence/producer_8511_final2.raw`).
- Worker 215909 survives.
- Idle state immediately after the producer (`fpm/inspect_bg.gdb`):

```text
IDLE lock=0 level=1 data=0x7fc2d6b83000
IDLE-HT nNumUsed=16 nTableSize=16 arData=0x7fc2d6b79080
```

This is the full-table stale state: `level=1`, 16 used buckets of a 16-bucket table, a
freed request-heap `arData` pointer. It is exactly the condition that the pre-RINIT
upload-progress consumer turned into a crash in the primitive lab.

### Consumer request on the same worker

```text
GET /login/index.php
Cookie: MoodleSession=b4dc8152224101380aa9a2ed45b059bd
```

Key GDB trace (`evidence/gdb_moodle_final_stale.log`):

```text
TRACE reqstart#1      lock=0 level=1 data=0x7fc2d6b83000 ht.nNumUsed=16 ht.nTableSize=16 ht.arData=0x7fc2d6b79080
TRACE reqshutdown#1   lock=0 level=0 data=0x0
TRACE session_flush#1 lock=0 level=0 data=0x0
TRACE ser_init#1      lock=0 level=0 data=0x0
TRACE addvar#1        lock=0 level=1 data=0x7fc2ca2fff40 ht.nNumUsed=0 ht.nTableSize=16 ht.arData=0x5621d70dff48
TRACE ser_destroy#1   lock=0 level=1 data=0x7fc2ca2fff40 ht.nNumUsed=8 ht.nTableSize=16 ht.arData=0x7fc2ca21d300
TRACE accept-detach   lock=0 level=0 data=0x0
```

Measured result:

- HTTP 200, body 19,595 bytes (`evidence/moodle_final_stale_traced.raw`).
- Worker 215909 alive after the response.
- Session file rewritten (same 688 bytes; hash changed to
  `464ae9572fd749e1a71358c80cdcd2618d17a10eefd1f79bc5763a4016de61f0` after this trace).
- At `php_request_startup` the stale table is visible; by `php_request_shutdown` it is
  gone, and the session serializer gets a **fresh** `data` pointer with an empty table.
  `php_add_var_hash` cannot dereference the stale `arData`.

This is the central measurement: the strongest possible stale state does not affect the
normal Moodle consumer because the RINIT reset happens first.

---

## 5. 8.5.12 fixed control

The same producer and the same normal Moodle request were repeated on the 8.5.12 build.

- Producer: HTTP 500, worker 164117 survives
  (`evidence/producer_8512.raw`, `evidence/producer_8512.client.log`).
- Idle state immediately after the producer:
  `IDLE lock=0 level=0 data=0x0` (no stale table).
- Normal `GET /login/index.php`: HTTP 200, body 19,595 bytes
  (`evidence/moodle_8512_after_producer.raw`).
- GDB trace (`evidence/gdb_moodle_8512_after_producer.log`):

```text
TRACE reqstart#1      lock=0 level=0 data=0x0
TRACE reqshutdown#1   lock=0 level=0 data=0x0
TRACE session_flush#1 lock=0 level=0 data=0x0
TRACE ser_init#1      lock=0 level=0 data=0x0
TRACE addvar#1        lock=0 level=1 data=<fresh> ht.nNumUsed=0
TRACE accept-detach   lock=0 level=0 data=0x0
```

- Worker 164117 alive after the request.

Source: 8.5.12 calls `php_basic_early_rinit()` before `sapi_activate()`:

- `main/main.c:1938-1940`:
  `zend_activate(); php_basic_early_rinit(); sapi_activate();`
- `ext/standard/basic_functions.c:491-500`: the function resets
  `BG(serialize_lock)`, `BG(serialize)`, and `BG(unserialize)`, with the comment that the
  session upload-progress handler can (un)serialize before RINIT.

---

## 6. Why a normal Moodle request cannot consume the stale state

### 6.1 The reset is before the script, but after the eager multipart parse in 8.5.11

PHP 8.5.11 `main/main.c:1872-1943` orders request startup as:

```text
zend_activate();
sapi_activate();          // eager multipart/_POST handling can run here
...
php_hash_environment();
zend_activate_modules();  // PHP_RINIT(basic) runs here
```

`PHP_RINIT(basic)` (`ext/standard/basic_functions.c:387-393`) does:

```c
BG(serialize_lock) = 0;
memset(&BG(serialize), 0, sizeof(BG(serialize)));
memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
```

Therefore, by the time any Moodle script executes and by the time Moodle writes its
session at request shutdown, `BG(serialize)` is zero. The only window in which a stock
8.5.11 request can see the previous request's table is inside the eager pre-RINIT
`sapi_activate()` multipart handling.

### 6.2 Moodle's session write is post-RINIT

- `moodle/lib/classes/shutdown_manager.php:56` registers
  `core_shutdown_manager::shutdown_handler` as a user shutdown function.
- `shutdown_handler()` at `:171-205` raises the memory limit (`:174-175`) and then calls
  `\core\session\manager::write_close()` (`:204-205`).
- `manager::write_close()` (`moodle/lib/classes/session/manager.php:687-734`) asks the
  handler to write, which reaches `php_session_encode()` ->
  `ps_srlzr_encode_php()` -> `php_var_serialize_init()`.

This is always after `zend_activate_modules()`/RINIT. It is the same path measured in
section 4.

### 6.3 Moodle's shutdown handler also raises the memory limit

`shutdown_manager.php:174-175` calls `raise_memory_limit(MEMORY_UNLIMITED)` before the
session write. If a Moodle request had OOMed earlier, the shutdown handler would run with
an unlimited limit, so the session `serialize()` is not a reliable producer at all; and
even if it reused a stale table left by the earlier OOM, the request heap is still alive
during shutdown, so that reuse is not a cross-request UAF. The next request's RINIT resets
again.

### 6.4 The only pre-RINIT consumer needs two special multipart fields

`ext/session/session.c:3178-3260` (`php_session_rfc1867_callback`) handles the eager
multipart events. At `MULTIPART_EVENT_FILE_START` it explicitly does nothing unless:

```c
if (!Z_TYPE(progress->sid) || !progress->key.s) {
    break;
}
```

`progress->sid` is set only by a form field whose name equals the session name, and
`progress->key` only by a form field named `PHP_SESSION_UPLOAD_PROGRESS`. A normal Moodle
form/upload does not set those fields, and Moodle uses a cookie for the session. The
pre-RINIT upload-progress consumer is therefore not a normal Moodle request; it is the
primitive lab's dedicated consumer and is explicitly excluded from this stock claim.

---

## 7. Stock producer search and bounds

### 7.1 Moodle `serialize()` sites

A full-tree search of Moodle 5.0.10 (excluding tests/vendor/third-party JS) found the
usual application serialization sites, for example:

| Site | What is serialized | Why it is not a stock 1 MiB producer |
|---|---|---|
| `cache/stores/file/lib.php:1099-1109` | cache value | proportional to the cache payload; a request body is ≤1 MiB and the cache value is not amplified to 128 MiB |
| `cache/classes/cache.php:918,1401` | cache/static acceleration value | same bound |
| `cache/stores/static/lib.php:241-245` | static cache value | same bound |
| `lib/navigationlib.php:6275,6303` | navigation cache info stored in session | generated from site structure, not from a 1 MiB body; session write is post-RINIT |
| `mod/lesson/pagetypes/essay.php:156,233` | lesson essay answer | 1 MiB answer serializes to ~1 MiB; no 128 MiB live set |
| `question/type/ddwtos/questiontype.php:49` | question output | question-authoring data, small |
| `admin/tool/xmldb/index.php:70` | XMLDB editor object | admin-only feature; not a normal stock request, and the input is an XML file, not a 1 MiB scalar amplification |
| `mod/data/locallib.php:271` | `unserialize(serialize($field))` | single field; bounded by request field |

None of these takes the whole 1 MiB request and expands it to a >128 MiB PHP structure
before `serialize()`. The diagnostic producer in section 4 is deliberately outside this
set.

### 7.2 Input/memory bound

With `max_input_vars=5000` (lab) and a stock nginx `client_max_body_size 1m`:

- the smallest serialized array element is about `i:0;i:0;` (8 bytes), so 1 MiB is at most
  ~131k elements; PHP array/zval/hash overhead is on the order of ~10 MiB, not 128 MiB;
- even an 8 MiB body (the `post_max_size`) is ~1M minimal elements and remains in the
  tens of MiB; a stock nginx 1 MiB front end blocks it anyway;
- strings, nested arrays, and `max_input_nesting_level` do not change the order of
  magnitude; an application-specific decompression/zip-bomb path would be needed, and no
  stock path was found in the time-boxed search.

This is an inferred bound, not a proof over every Moodle plugin; it is consistent with the
MediaWiki measurement at the 8 MiB `post_max_size` (peak 104.9 MB, 29 MB below the 128 MiB
limit).

### 7.3 MediaWiki residual (already measured, not re-run)

The prior MediaWiki report remains valid:
`/tmp/opencode/research/mw_109619_20261023T010708Z/report_final.md`.

- PHP 8.3.35, 8,168,673-byte username: HTTP 500; OOM at
  `includes/Session/Session.php:545` (`openssl_decrypt`) and then
  `includes/ObjectCache/SqlBagOStuff.php:1486` (`serialize($value)`); worker survives.
- The line-557 `unserialize()` is never the first OOM: the decrypt stage's concurrent
  live set is at least as large; the measured boundary is 8,168,672 bytes completes at
  exactly 128 MiB, 8,168,673 fails at line 545.
- The encode-side `serialize()` OOM does leave stale `BG(serialize)`, but the ~300-byte
  upload-progress consumer's session data is scalar-only and never dereferences the freed
  `data->ht`; C0 and C1 are byte-identical and the worker survives.
- A stock nginx `client_max_body_size 1m` blocks the 8.17 MB producer; `post_max_size=8M`
  blocks it even without nginx. This is the same producer-side blocker as in the present
  report.

No other stock application was exhaustively tested; per the task they are lower priority.

---

## 8. Exact blocker

There is **no stock producer/consumer chain** in the tested Moodle/MediaWiki paths:

1. **Producer side:** no stock Moodle request within 1 MiB (or even 8 MiB) creates a
   >128 MiB live structure and bails out inside `serialize()`. The only measured
   application producer with a real serializer bailout is MediaWiki's 8.17 MB login, which
   is unreachable behind stock nginx and exceeds `post_max_size=8M`.
2. **Consumer side:** a normal Moodle request's only `php_add_var_hash` traversal is the
   post-RINIT session write. The stale table is reset by `PHP_RINIT(basic)` before the
   script and before the shutdown handler. The only pre-RINIT consumer is the
   `PHP_SESSION_UPLOAD_PROGRESS` multipart callback, which is not a normal Moodle request
   and is excluded from the final stock claim.
3. Therefore, even the strongest artificial stale state (`level=1`, full 16/16 table) does
   not crash a normal Moodle request; it is reset and replaced by a fresh serializer.

The remaining theoretical route would require a stock **pre-RINIT** consumer that reads a
Moodle session with objects/references (the upload-progress path) or a stock producer that
can be reached under the same caps. Neither was found.

---

## 9. Evidence index

Root: `/tmp/opencode/research/moodle_consumer_20261023T060000Z/`

| Path | Contents |
|---|---|
| `evidence/gdb_moodle_final_stale.log` | 8.5.11: stale at `reqstart`, zero at shutdown, fresh `ser_init`/`addvar`, 200 |
| `evidence/gdb_moodle_normal_raw.log` | 8.5.11: clean normal request trace |
| `evidence/gdb_moodle_8512_after_producer.log` | 8.5.12: clean control trace |
| `evidence/moodle_final_stale_traced.raw` | 8.5.11 normal Moodle response after producer (200) |
| `evidence/moodle_8512_after_producer.raw` | 8.5.12 normal Moodle response after producer (200) |
| `evidence/producer_8511_final2.raw` | 8.5.11 diagnostic producer (500) |
| `evidence/producer_8512.raw` | 8.5.12 diagnostic producer (500) |
| `evidence/probe_producer.php` | diagnostic producer, moved out of the Moodle docroot |
| `fpm/trace_raw.gdb` | GDB breakpoints and raw `BG` state reader (offsets verified) |
| `fpm/inspect_bg.gdb` | idle stale-state inspector |
| `fpm/offsets.c`, `fpm/offsets512.c` | compiled offset helpers for 8.5.11/8.5.12 |
| `moodledata/sessions/sess_b4dc8152224101380aa9a2ed45b059bd` | guest Moodle session, 688 bytes, objects |
| `evidence/environment.xml.stock2` | original `admin/environment.xml` |
| `moodle/admin/environment.xml` | current tree (zip/gd/sodium optional; session code untouched) |
| `log/fpm8511-stdout2.log` | 8.5.11 FPM startup |
| `log/fpm8512-stdout.log` | 8.5.12 control FPM startup |

Source citations:

- PHP 8.5.11 `ext/standard/basic_functions.c:387-393` (RINIT reset).
- PHP 8.5.11 `main/main.c:1872-1943` (`sapi_activate` before `zend_activate_modules`).
- PHP 8.5.11 `ext/standard/var.c:750-806` (`php_add_var_hash` -> `zend_hash_index_find`),
  `:1346-1361` (`php_var_serialize_init` reuse condition), `:1364-1373`
  (`php_var_serialize_destroy` reset).
- PHP 8.5.11 `ext/session/session.c:271-280` (`php_session_encode`), `:3178-3260`
  (`php_session_rfc1867_callback`, pre-RINIT multipart).
- PHP 8.5.12 `main/main.c:1938-1940` and
  `ext/standard/basic_functions.c:491-500` (`php_basic_early_rinit` before
  `sapi_activate`).
- Moodle `lib/classes/session/manager.php:185-186,292,310-311,687-734`.
- Moodle `lib/classes/shutdown_manager.php:56,171-205`.
- Moodle `lib/setup.php:907`.

Reproduction commands are the `fcgi.py` invocations recorded in the corresponding
`*.client.log` files, with `FPM_HOST=127.0.0.1`, `FPM_PORT=19500`,
`DOCROOT=<lab>/moodle`. The FPM process was left running as the lab's own single worker
(master 215904); no shared service was restarted.

---

## 10. Caveats

- The diagnostic producer is **not stock**. It is used only to prove that the normal
  Moodle consumer is immune even to a full stale table. It has been removed from the
  docroot.
- Moodle's login POST is blocked by the missing `sodium` extension in this lab; the
  normal-request evidence is a guest GET on `/login/index.php`. The guest session uses the
  same `manager::start()` reference wiring and the same `USER`/`SESSION` stdClass objects
  as an authenticated session, and the trace confirms `php_add_var_hash` is reached.
- The producer search is time-boxed and not a proof over every Moodle plugin or every
  other PHP application. It is a source-and-measurement-based negative for the tested
  stock paths.
- `max_input_vars=5000` and the extension-level edits are disclosed above; both make the
  producer search more permissive, not less.
