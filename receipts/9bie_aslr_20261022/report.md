# 9bie `php2shell-bypass-aslr-exp` — ASLR-bypass analysis and 8.4.26/8.5.11 lab verification

**Receipt:** `/tmp/opencode/research/9bie_aslr_20261022T095015Z`
**Date:** 2026-10-22 (UTC)
**PoC:** <https://github.com/9bie/php2shell-bypass-aslr-exp> @ `4586f5cc120c82fd468b17469202bac629810ad9` (2026-10-21)
**Prior receipt (same HEAD):** `phpshell/receipts/9bie_1022` — 8.4.26 only; multi-worker/rotation/Off sweeps
**Targets:** official `php:8.4.26-apache` and `php:8.5.11-apache` (both built 2026-10-21), Apache 2.4.69, prefork + mod_php, Debian 12
**Isolation:** ten new loopback-only containers on `127.0.0.1:18230–18239`; no host mounts, no privileged containers, no shared services, no non-loopback targets

---

## 0. Direct answers

| Question | Answer |
|---|---|
| Does the repo require `display_errors=On`? | **Yes, for the full chain.** The warning output is required to set `SG(headers_sent)=1` before `php_session_send_cookie()`, so that `send_cookie` fails and `PS(send_cookie)=1` survives. With `display_errors=Off` the classic chain dies at stage 1. |
| Does it use error output as the leak? | **No.** The leak is the out-of-bounds `Set-Cookie: PHPSESSID=<url_encode(stale PS(id))>` read. The warning text is only a trigger; its contents are not leaked. |
| Does the repo's `display_errors=Off` branch give RCE? | **No.** It is a separate OOM-in-cookie primitive that only reaches a Zend MM chunk-base leak (repo: 4000 B / 47 pointers). Stage 2/3 under `display_errors=0` are explicitly left unresolved in `DISPLAY_ERRORS_OFF.md` (§6.2/§6.4). On the official images the published A shape did not reproduce the intended OOM point (see §3.4). |
| Does any technique here unblock our `display_errors=Off` blocker? | **No.** No libphp leak and no RCE under Off, only a heap-chunk leak primitive. |
| Does it unblock the FPM blocker? | **No evidence.** The repo is mod_php/Apache prefork only: Apache SIGABRT + prefork refork rotation, Apache request-startup warning output, and a mod_php heap. No FPM transport, config, calibration or test is shipped. Our FPM path remains the separate `g2_chain.py` G2/G6 route. |
| Does it unblock the 8.2.34 blocker? | **Not as shipped.** 8.2.34 is inside the CVE-affected range (`<8.2.35`) so the bug is present, but the repo ships only 8.4.26 calibration. All stage counts, heap offsets and libphp offsets would need re-derivation. Not tested in this receipt. |
| Does it unblock the 7.x blocker? | **No.** 7.x is not in the CVE-2026-109618 affected ranges and the repo has no 7.x profile. |
| Is this a repackaging of our G2/G6 chain? | **No.** It is a distinct mod_php exploitation path for the same CVE class: two pure-HTTP `Set-Cookie` OOB leaks + fake `HashTable::pDestructor = zif_system`. G2/G6 is FPM, `.data` serializer decode-slot overwrite, profile-supplied addresses. |

**Lab headline:** the unmodified public chain reproduces **one-shot end-to-end, ASLR on, single worker**, on both official images:

* PHP 8.4.26, `display_errors=On`, `memory_limit=8M`: **3/3** RCE, stage 1/2/3 all first attempt.
* PHP 8.5.11, same config: **3/3** RCE, stage 1/2/3 all first attempt.
* Both at `memory_limit=16M` (12 MB OOM field): **2/2** RCE each, same calibration.
* `display_errors=Off`: **0/2** classic chain at 8M and **0/2** at 16M for both versions (stage 1 always `0x0`).
* `memory_limit=128M`, default 12 MB field: no OOM, stage 1 fails. With a 63 MB field: stage 1/2 leaks still work **2/2** on both versions, but stage 3 fails **0/2** — the leaks are memory-limit-robust, the fake-HashTable placement is not.

---

## 1. What the repository contains

`4586f5cc` is a compact research repository, not a product:

| Area | Files |
|---|---|
| End-to-end exploit | `exploit.py` (stages, bookworm/lab profiles, rotation, proof checks), `docker/offsets.py` |
| Lab A/B senders | `tools/send_a_*.py`, `tools/send_b_*.py`, `tools/trial_ab.sh`, `tools/trial_bins.sh` |
| Docs | `README.md`, `readme_en.md`, `HTTP_HEAP_LEAK.md`, `ASLR_PURE_HTTP.md`, `DISPLAY_ERRORS_OFF.md`, `NO_DISPLAY_ERRORS.md`, `NOTES.md`, `NOASLR_REPORT.md`, `ASLR_PATHS.md` |
| Lab config | `docker/php.ini`, `docker/apache.conf`, `docker/docker-compose.yml` |

The clone has **293 tracked files (294 in the working tree) and no `SHA256SUMS`**;
this receipt generates its own.

Shipped boundary conditions (`docker/php.ini`, README):

```text
display_errors=On, display_startup_errors=On, error_reporting=E_ALL
memory_limit=8M, post_max_size=64M, upload_max_filesize=64M
session.save_path=/tmp, session.use_strict_mode=0, session.use_cookies=1
session.upload_progress.enabled=On, session.upload_progress.cleanup=On
max_input_vars=1000
single-worker prefork, MaxConnectionsPerChild=0
```

Target page is only `<?php echo "OK\n"; ?>`; no `session_start()` and no application code.

---

## 2. ASLR-bypass mechanism (static analysis)

### 2.1 Root cause

The vulnerable surface is `session.upload_progress` session initialization, which runs **before RINIT**, during multipart request parsing:

```text
multipart FILE_START -> php_session_rfc1867_update()
    -> php_session_initialize()
        -> s_open()
        -> s_create_sid() / PS(id)
        -> php_session_reset_id()
            -> php_session_send_cookie()
        -> php_session_track_init()   // PS(http_session_vars)
```

An out-of-memory `zend_bailout` inside this pre-RINIT path skips the normal cleanup. The request dies, but `PS(id)`, `PS(send_cookie)` and `PS(http_session_vars)` can survive into the next request handled by the same worker. The next multipart request re-enters `php_session_initialize()` and dereferences that stale state.

This is the CVE-2026-109618 class (“OOM bailout leaves request memory in an uninitialized state; the subsequent request cleanup may read or branch on this memory”). The fix adds `php_rinit_session_globals()` at `MULTIPART_EVENT_START` and replaces the OOM bailout with `UnwindExit`; affected ranges are `<8.2.35`, `<8.3.36`, `<8.4.27`, `<8.5.12`. PHP 8.5.11 still lacks the multipart-start reset (source line 3193 in `ext/session/session.c`).

### 2.2 Request A: make `send_cookie` dangle

A sends:

1. 1001 ordinary fields (`p0000…`) so `main/php_variables.c:557` emits
   `PHP Warning: Input variables exceeded 1000…`.
   With `display_errors=On` the warning is written to the SAPI output, and
   `main/SAPI.c:885` sets `SG(headers_sent)=1`.
2. `PHPSESSID=\x00`, so `php_session_initialize()` creates a random 32-char id and sets
   `PS(send_cookie)=1`.
3. A file part, so `MULTIPART_EVENT_FILE_START` calls `php_session_initialize()`.
4. A 12 MB field, so the request OOMs after the session state was created.

`php_session_reset_id()` then calls `php_session_send_cookie()`:

```c
if (SG(headers_sent)) {
    php_error_docref(NULL, E_WARNING, "Session cookie cannot be sent after headers have already been sent");
    return FAILURE;
}
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

The `headers_sent` check returns `FAILURE`, so `PS(send_cookie)` is **not** cleared:

```c
if (PS(use_cookies) && PS(send_cookie)) {
    zend_result cookies_sent = php_session_send_cookie();
    if (UNEXPECTED(cookies_sent == FAILURE)) return FAILURE;
    PS(send_cookie) = 0;          /* skipped on the warning path */
}
```

A then OOMs; `PS(id)` points at a freed/reusable 32-character id `zend_string`, and
`PS(send_cookie)` is still 1.

### 2.3 Request B: `Set-Cookie` OOB read

B is a second multipart POST with no file part. Its pre-RINIT
`MULTIPART_EVENT_END -> php_session_rfc1867_cleanup() -> php_session_initialize()`
sees the stale id and `send_cookie=1`, and calls `php_session_send_cookie()` while
this request's headers are still unsent. The attacker's B fields reclaim the freed
id block with a forged `zend_string` header:

```text
PS(id)+0x00  gc / type
PS(id)+0x10  forged len (0x1000 for stage 1)
PS(id)+0x18  data
```

`php_url_encode()` (`ext/standard/url.c:449,457`) reads `len` bytes starting at
`data`, so the response carries up to 4096 bytes of adjacent heap in
`Set-Cookie: PHPSESSID=...`. Stage 1 uses 892/841 48-byte values and one 79-byte
raw value (bookworm: 841) to place the forged header exactly on the stale block.
The decoded cookie contains 98 pointers whose 2 MiB-aligned mode is the Zend MM
chunk base.

Stage 2 uses a different B shape: 983 arrays `a0000..a0982`, with `a0443` expanded
to 16 elements. The stale `PS(id)` lands on a 56-byte `HashTable` page; the forged
length becomes `nTableSize|nInternalPointer = 16`, and the 16-byte read window
covers `nNextFreeElement | pDestructor`. `pDestructor` is `ZVAL_PTR_DTOR`
(`zval_ptr_dtor`) in libphp, so the libphp base follows by subtraction. The code
accepts 4 KiB alignment (the official image maps libphp at a 4 KiB boundary, not
2 MiB).

### 2.4 Stage 3: fake HashTable, `pDestructor = zif_system`

Stage 3's A uses a **valid** `Cookie: PHPSESSID=<32 a's>` instead of `\x00`, so
`send_cookie=0` and B's initialization does not allocate a `Set-Cookie` header at
`R0+0x10` (which would clobber the fake reference type). A's 6 pad fields
(31-byte name / 31-byte value) pin the stale reference `R0` at
`chunk+0x24e0`; the 12 MB field OOMs after `php_session_track_init()` created
`PS(http_session_vars)`.

B writes a 15-byte carrier over `PS(http_session_vars)` (gc=`rc=1, IS_REFERENCE`,
low 7 bytes of `val.value` = fake HashTable address) and places a 167-byte fake
HashTable in a live string at `chunk+0x690d8`. The fake table has
`pDestructor = libphp+zif_system` and a crafted fake `execute_data` at
`arData = ht+0x20`, with arg 1 at `ht+0x50` pointing to a fake `zend_string` at
`ht+0x80` whose data is the command (`id>/tmp/p1`, 11 bytes; carrier limit 14).

On the next request's session initialization, `php_session_track_init()` runs:

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)   # zif_system
```

Only libphp’s `zif_system` is used; no libc base is needed.

### 2.5 Worker rotation and address stability

Stages must run on a fresh worker because the stale pointers/offsets are
calibrated to the worker's first request. The repo rotates over HTTP:

* `A_bigfields`: 1001 fields (3000-byte values) + 12 MB OOM, leaving a corrupted
  Zend MM heap.
* `B`: a session-initializing multipart request with no file part; the pre-RINIT
  cleanup walks the corrupted heap and the child aborts (`zend_mm_heap corrupted`,
  `child pid … exit signal Abort (6)`).
* Apache prefork immediately forks a new child. All children inherit the master's
  randomized `libphp` mappings; the Zend MM chunk base is also stable for fresh
  children of the same master.

This is why the leak values in one container are identical across worker rotation,
while different containers have different high-entropy bases. It does **not** mean
ASLR is off; see §4.4.

### 2.6 Source anchors

| Anchor | 8.4.26 line | 8.5.11 line | Relevance |
|---|---|---|---|
| `ext/session/session.c` | 108 | 111 | `php_rinit_session_globals()` (resets id/status/mod_data) |
| `ext/session/session.c` | 419 | 431 | `php_session_initialize()` |
| `ext/session/session.c` | 455-460 | 469-483 | new id + `PS(send_cookie) = 1` |
| `ext/session/session.c` | 475 | 487 | `php_session_reset_id()` failure branch |
| `ext/session/session.c` | 1426-1447 | 1373-1394 | `php_session_send_cookie()`; `SG(headers_sent)` check (1432/1379) before `php_url_encode` |
| `ext/session/session.c` | 1552-1569 | 1594-1610 | `php_session_reset_id()`; clears `send_cookie` only on success |
| `ext/session/session.c` | 3196/3211 | 3153/3168 | `php_session_rfc1867_update()` / `cleanup()` call `php_session_initialize()` |
| `ext/session/session.c` | 3236 | 3193 | `MULTIPART_EVENT_START` (neither version resets session globals here) |
| `main/php_variables.c` | 557 | 557 | max_input_vars warning |
| `main/SAPI.c` | 885 | 903 | `SG(headers_sent) = 1` |
| `ext/standard/url.c` | 449, 457 | 450, 542 | `php_url_encode_impl()` / `zend_string_safe_alloc(3, len, 0, 0)` |
| `Zend/zend_alloc.c` | — | — | 2 MiB Zend MM chunks, 4 KiB pages, small bins |

The line numbers were checked in both local source trees (`src/php-8.4.26`,
`src/php-8.5.11`). The full mapping is in `lab/logs/source-anchors-8.5.11.txt`;
8.5.11 shifts the session paths by tens of lines but keeps the same control flow
and the same heap/geometry constants.

---

## 3. Exact `display_errors` semantics

### 3.1 Why `On` is required

It is **not** “the error text is the leak”. It is a state-machine dependency:

1. The `max_input_vars` warning must be **output** during request startup.
2. Output sets `SG(headers_sent)=1` (`main/SAPI.c:885`).
3. `php_session_send_cookie()` returns `FAILURE` before clearing `send_cookie`.
4. `PS(send_cookie)` remains 1 and `PS(id)` remains stale.
5. The next request can send the stale id through `php_url_encode()` and leak.

With `display_errors=Off`, the same warning is still generated and written to the
Apache error log (`log_errors=On`), but it produces no output; `headers_sent` stays
0; `send_cookie` succeeds, clears `send_cookie`, and the stale-id path is gone.

The same effect should be producible by **any** output before `send_cookie` (for
example an application `echo`), because the check is `SG(headers_sent)`, not the
ini value. That is an inference from the source, not a measurement in this
receipt. The repo’s own trigger is the max_input_vars warning, and its shipped
configuration requires `display_errors=On`.

### 3.2 Measured gate (raw stage-1 pair)

`lab/capture_stage1.py` wraps the repo’s `Exploit` class and prints each response
without parsing:

| Container | A status | A `Set-Cookie` | B status | B decoded cookie | stage 1 |
|---|---|---|---|---|---|
| 8.4.26 On 8M | 200 (warning body, 693 B) | **none** | 200 | **4096 B, 11118 wire chars** | `0x7f4648e00000` |
| 8.5.11 On 8M | 200 (warning body) | **none** | 200 | **4096 B, 11386 wire chars** | `0x7f6a9c200000` |
| 8.4.26 Off 8M | **500** (no warning body) | **32 B, normal id** | 200 | **none** | `0x0` |
| 8.5.11 Off 8M | **500** | **32 B, normal id** | 200 | **none** | `0x0` |

Apache error-log signature:

```text
On : "Input variables exceeded 1000"  +  "Session cookie cannot be sent after headers have already been sent"
Off: "Input variables exceeded 1000"  +  (no session-cookie warning)
```

The Off A response is a 500 with a *normal* 32-byte `PHPSESSID` cookie: the OOM
happened after `send_cookie` had already succeeded. B then has no stale
`send_cookie` and returns no cookie. This is the exact reason the classic chain
fails at stage 1.

### 3.3 The repo's Off-only variant

`DISPLAY_ERRORS_OFF.md` / `NO_DISPLAY_ERRORS.md` describe a different A:
instead of relying on the warning, the attacker exhausts the Zend MM bins/pages so
that the 121-byte `zend_string_safe_alloc(3, 32, 0, 0)` inside
`php_session_send_cookie()` itself OOMs. `PS(send_cookie)=1` survives without any
output; B then has to walk a stale `PS(mod_data)` and a page-511 forge.

The repo explicitly reports only the **chunk-base leak** for this variant:

```text
decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000   # no-ASLR
decoded=4000 ptrs=47 chunk_base=0x7f9acd000000   # ASLR-on
```

and states that stage 2/3 under `display_errors=0` are still unresolved. So the Off
branch is a **heap-leak research primitive**, not a full ASLR bypass or RCE.

### 3.4 Our probe of the published Off A/B shape

Using the repo’s own `send_a_oom5.py 0 62 235 15000 208 0 4000 103` and
`send_b_open.py 160 231` (with `BB1_LEN=1048551 BF_P1=256 BF_READ=4000`), only
patching the loopback port/output path:

* PHP 8.5.11 Off 8M: A returned 500 with a **normal 32-byte cookie**; the OOM was
  `tried to allocate 24576 bytes`, i.e. after `send_cookie`, not inside
  `php_url_encode`. B returned 200 with no OOB cookie.
* PHP 8.4.26 Off 8M: the same A shape produced **200, no OOM** (the shape is
  calibrated for the author’s minimal Apache 2.4.68 lab, not the official image).
* None of the tested NB/X variants moved the OOM to the 121-byte allocation; B
  never leaked more than 32 bytes.

This matches the prior receipt’s conclusion (`9bie_1022`), which swept the
published Off shapes on the official 8.4.26 image and also got no OOB cookie. We
did not repeat that full sweep; see `9bie_1022/evidence/display_errors_off/`.

---

## 4. Lab verification

### 4.1 Images and matrix

| Port | Container | PHP | `display_errors` | `memory_limit` | Role |
|---:|---|---|---|---|---|
| 18230 | `9bieaslr-8426-on-8M` | 8.4.26 | On | 8M | full chain, n=3 |
| 18231 | `9bieaslr-8426-off-8M` | 8.4.26 | Off | 8M | gate, n=2 + raw capture |
| 18232 | `9bieaslr-8426-on-16M` | 8.4.26 | On | 16M | full chain, n=2 |
| 18233 | `9bieaslr-8426-off-16M` | 8.4.26 | Off | 16M | gate, n=2 |
| 18234 | `9bieaslr-8426-on-def` | 8.4.26 | On | 128M | 12 MB / 63 MB boundary, n=2 each |
| 18235 | `9bieaslr-8511-on-8M` | 8.5.11 | On | 8M | full chain, n=3 |
| 18236 | `9bieaslr-8511-off-8M` | 8.5.11 | Off | 8M | gate, n=2 + raw capture + Off probe |
| 18237 | `9bieaslr-8511-on-16M` | 8.5.11 | On | 16M | full chain, n=2 |
| 18238 | `9bieaslr-8511-off-16M` | 8.5.11 | Off | 16M | gate, n=2 |
| 18239 | `9bieaslr-8511-on-def` | 8.5.11 | On | 128M | 12 MB / 63 MB boundary, n=2 each |

Images and digests are in `metadata.txt`. Configs are `repo/docker/php.ini` with
`log_errors=On` and `max_input_vars=1000` made explicit, a per-container
`memory_limit` override (8M/16M/128M), `display_errors=On|Off`, and a single-worker
prefork (`MaxRequestWorkers=1`, `ServerLimit=1`, `StartServers=1`,
`MaxConnectionsPerChild=0`). The exact files are `lab/configs/*.ini`,
`mpm_prefork.conf` and `apache-single.conf`.

### 4.2 Method

* `lab/driver_one.py` imports the repo’s own `Exploit` class and calls its
  `rotate()`, `stage1()`, `stage2()`, `stage3()` with the same payload shapes,
  offsets and stage order as `exploit.py`.
* The only difference is proof detection: after each `stage3()`, the driver runs
  `docker exec <container> cat /tmp/p1` (no host mount) instead of checking a host
  path. This is necessary because the unmodified `exploit.py --proof-file ''`
  cannot see a file created inside the container and reports
  `EXPLOIT_FAILED` even when the command ran.
* The unmodified `exploit.py` control (`lab/run_exploit.sh`, run 1,
  `lab/logs/8426-on-8M/run1.log`) did execute the command
  (`PROOF: uid=33(www-data)…` read from the container), while exiting 1 because
  its proof file was host-local. All reported one-shot numbers therefore use the
  driver, not the misleading exit code.
* Runs on one container are strictly sequential. Six early runs were launched
  concurrently on the same two containers by mistake; they were moved to
  `lab/logs/_invalid_concurrent/` and are not used.
* `n` is small (2–3 per row); these are existence/one-shot measurements, not
  reliability rates.

### 4.3 Matrix results

Source of truth: `lab/logs/results.json` (parsed from the `RESULT {...}` lines).

| PHP | `display_errors` | `memory_limit` | huge field | n | stage 1 one-shot | stage 2 one-shot | stage 3 one-shot | RCE |
|---|---|---|---|---:|---|---|---|---|
| 8.4.26 | On | 8M | 12 MB | 3 | **3/3** | **3/3** | **3/3** | **3/3** |
| 8.5.11 | On | 8M | 12 MB | 3 | **3/3** | **3/3** | **3/3** | **3/3** |
| 8.4.26 | On | 16M | 12 MB | 2 | **2/2** | **2/2** | **2/2** | **2/2** |
| 8.5.11 | On | 16M | 12 MB | 2 | **2/2** | **2/2** | **2/2** | **2/2** |
| 8.4.26 | On | 128M | 12 MB | 2 | 0/2 | 0/2 | — | 0/2 |
| 8.5.11 | On | 128M | 12 MB | 2 | 0/2 | 0/2 | — | 0/2 |
| 8.4.26 | On | 128M | 63 MB | 2 | **2/2** | **2/2** | 0/2 (3 attempts each) | 0/2 |
| 8.5.11 | On | 128M | 63 MB | 2 | **2/2** | **2/2** | 0/2 (3 attempts each) | 0/2 |
| 8.4.26 | Off | 8M | 12 MB | 2 | 0/2 | — | — | 0/2 |
| 8.5.11 | Off | 8M | 12 MB | 2 | 0/2 | — | — | 0/2 |
| 8.4.26 | Off | 16M | 12 MB | 2 | 0/2 | — | — | 0/2 |
| 8.5.11 | Off | 16M | 12 MB | 2 | 0/2 | — | — | 0/2 |

Notes:

* “One-shot” means the stage succeeded on its **first** attempt. The exploit
  driver uses `--retries 1` for stages 1/2, so a miss is recorded as failure;
  stage 3 is allowed 3 attempts (`retries+2`).
* Every successful RCE wrote `uid=33(www-data) gid=33(www-data)` to
  `/tmp/p1` inside the container.
* The 16M result shows `memory_limit=8M` is **not a literal requirement** for the
  shipped 12 MB field: the field’s realloc peak still OOMs at a 16M limit
  (allocation sizes 6,296,371 / 4,197,581 B in the log), and the heap geometry at
  the OOM point stays compatible with the bookworm calibration.
* At 128M with the default 12 MB field there is no OOM; stage 1 returns `0x0`.
  At 63 MB the field’s realloc peak OOMs at `tried to allocate 65016420 bytes`;
  stages 1/2 still work, but `HTDATA=chunk+0x690d8` is no longer the live 167-byte
  string location, so stage 3 fails. This is an uncalibrated geometry result, not
  a proof that 128M is impossible.

### 4.4 ASLR ground truth

Host: `kernel.randomize_va_space=2`, container `personality=00000000`
(`ADDR_NO_RANDOMIZE` not set). The leaked libphp base was compared with
`/proc/1/maps` of the Apache parent (same randomized mapping as every forked
worker). The comparison below was re-captured at the end of the run and is stored
in `lab/logs/aslr-groundtruth.txt`:

| Container | Leaked chunk base | Leaked libphp base | `/proc/1/maps` libphp base | Match |
|---|---|---|---|---|
| 8426 On 8M | `0x7f4648e00000` | `0x7f464a9ca000` | `7f464a9ca000` | yes |
| 8511 On 8M | `0x7f6a9c200000` | `0x7f6a9de00000` | `7f6a9de00000` | yes |
| 8426 On 16M | `0x7faf02200000` | `0x7faf03ed4000` | `7faf03ed4000` | yes |
| 8511 On 16M | `0x7fa897600000` | `0x7fa899200000` | `7fa899200000` | yes |
| 8426 On 128M/63MB | `0x7ff97da00000` | `0x7ff97f757000` | `7ff97f757000` | yes |
| 8511 On 128M/63MB | `0x7fcc70000000` | `0x7fcc71a00000` | `7fcc71a00000` | yes |

The bases are different in every container, and all are high-entropy
`0x7f…` mappings. Within one container, repeated runs and worker rotations return
the same values because prefork children are forked from the same master and
inherit its mappings; the exploit reads the live address instead of brute-forcing.
The chunk-base leak is independently confirmed operationally: stage 3 only
executes when `HTDATA = leaked_chunk + 0x690d8` is correct.

### 4.5 Worker survival and rotation

* Each successful stage 1/2/3 ends with the worker alive; the driver's
  `stage2()`/`stage3()` succeed on the same container immediately after.
* The rotation requests produce the expected
  `zend_mm_heap corrupted` + `child pid … exit signal Abort (6)` in the Apache log,
  followed by a new child. The gdb-free exploit path never sends signals.
* After the last successful runs, all six On containers answered `GET /index.php`
  with HTTP 200 and had exactly one Apache child each (`pgrep -x apache2` = 2
  including the parent). Off containers likewise survived; their stage 1 simply
  returns no leak. The end-of-run check is in `lab/logs/aslr-groundtruth.txt`.

---

## 5. Comparison with the prior receipt and with our G2/G6 chain

### 5.1 Prior receipt `9bie_1022`

Same repo at the same HEAD, official 8.4.26 image, ports 18088–18091:

* 8.4.26 On 8M: 3/3 one-shot (reproduced here again).
* Off: chain fails; the published OOM-in-cookie variant produced no OOB cookie
  on the official image in any published shape.
* Default multi-worker prefork: 1/5 end-to-end; `MaxConnectionsPerChild=1`: 0/3.

This receipt does **not** re-run multi-worker or `MaxConnectionsPerChild=1`;
those results remain the prior receipt’s. New here: 8.5.11, 16M/128M, the exact
On/Off raw gate, the `/proc/1/maps` ground truth, and the `display_errors=Off`
probe on 8.5.11.

### 5.2 Our G2/G6 FPM chain (`phpshell/tool/modules/g2_chain.py`)

| Dimension | 9bie repo | G2/G6 |
|---|---|---|
| SAPI / process model | Apache prefork + mod_php, single worker | FPM (`php-fpm`), worker pool |
| Root cause | OOM bailout in pre-RINIT `session.upload_progress` leaves `PS(id)`, `PS(send_cookie)`, `PS(http_session_vars)` stale | Controlled bailout leaves a stale `BG(unserialize)` dtor chain; pre-RINIT upload-progress session decode reuses it |
| Address source | Two pure-HTTP `Set-Cookie` OOB reads (Zend MM chunk, libphp `ZVAL_PTR_DTOR`) | Profile-supplied absolute bases (G2/G6 plans; `.data` slot addresses) |
| Write target | Fake `HashTable::pDestructor` in a live 167-byte string | `ps_serializers[2].decode` (or active serializer decode slot) in `.data` |
| Terminal | `zif_system` called as `pDestructor(&bucket->val)` with fake `execute_data` | `zif_system` / `zif_passthru` called as serializer decode with session record as `rdi` |
| Worker handling | HTTP-triggered SIGABRT + prefork refork | FPM worker recycle/respawn; `.data` poison is worker-local |
| Code overlap | None | None |

They are both in the CVE-2026-109618 family (OOM bailout + session upload
progress), but they are **different exploitation paths**, not a repackaging.
The 9bie repo adds a pure-HTTP ASLR leak and a mod_php terminal; it does not
replace or improve our FPM G2/G6 route.

---

## 6. Blocker verdicts

### `display_errors=Off`

**Not unblocked.** The classic chain needs output before `send_cookie` to set
`headers_sent`. The Off branch replaces that with an OOM inside
`php_session_send_cookie()`, but:
* it only reaches a chunk-base heap leak (repo: 4000 B/47 pointers);
* stage 2 (libphp) and stage 3 (RCE) are explicitly left unresolved;
* on the official images the published A shape does not hit the intended
  121-byte allocation (8.4.26: no OOM at the published shape; 8.5.11: OOM at
  24,576 B after `send_cookie`), so B never sees a stale `send_cookie`.

If a target had `display_errors=Off` **and** an independent libphp/chunk address
oracle, the stage-3 request shape might still be usable (stage 3 does not itself
need the warning), but that is not an ASLR bypass and is not what the repo ships.
No Off RCE was demonstrated here or in the prior receipt.

### FPM

**No evidence of unblock.** The repo is mod_php/Apache prefork:
* `php_session_send_cookie()` behavior and `SG(headers_sent)` are SAPI-level, but
  the shipped trigger (request-startup warning output) and its `headers_sent`
  effect were only demonstrated under mod_php here;
* worker rotation is Apache `SIGABRT` + prefork refork;
* the fake HashTable/reference offsets are calibrated for the mod_php request heap.

The underlying CVE is in PHP core and could in principle affect FPM, but this
repo provides no FPM request transport, no FPM calibration, and no FPM test. Our
FPM route remains `g2_chain.py` G2/G6.

### PHP 8.2.34

**Affected by version, not unblocked as-is.** 8.2.34 < 8.2.35 is in the
CVE-2026-109618 affected range, so the bug class is present. But every heap
offset, stage count and libphp symbol offset in this repo is 8.4.26-specific;
8.2.34 would need re-derivation and a fresh lab. Not tested here.

### PHP 7.x

**No.** 7.x is not listed in the CVE affected ranges, and the repo has no 7.x
profile. Nothing in this receipt changes the 7.x blocker.

---

## 7. Limitations

* Small n (2–3 per row); no reliability claim beyond “all attempted runs were
  one-shot” for the On 8M/16M rows.
* Only official Apache images were tested. Custom builds change libphp offsets and
  heap geometry; the repo itself says re-calibration is required.
* 128M stage 3 is uncalibrated; the failure is measured with the shipped
  `HTDATA=chunk+0x690d8`, not proof of impossibility.
* `display_errors=Off` was tested with the classic chain and the published Off
  A/B shape plus an NB/X sweep; the full Off sweep lives in the prior receipt,
  not here.
* Multi-worker and `MaxConnectionsPerChild=1` were not re-tested; see `9bie_1022`.
* FPM, 8.2.34 and 7.x were not run in this receipt.
* No host process was used for exploitation; all requests went to
  `127.0.0.1` in disposable containers.

---

## 8. Reproduction and artifacts

### 8.1 Key commands

```bash
# End-to-end (driver with in-container proof check), 8.4.26 On 8M
python3 lab/driver_one.py \
  --container 9bieaslr-8426-on-8M \
  --url http://127.0.0.1:18230/index.php \
  --zif 0x465370 --dtor 0x65eb60 --huge-mb 12 --retries 1

# 8.5.11 On 8M
python3 lab/driver_one.py \
  --container 9bieaslr-8511-on-8M \
  --url http://127.0.0.1:18235/index.php \
  --zif 0x5996e0 --dtor 0x7b47a0 --huge-mb 12 --retries 1

# display_errors gate, raw A/B capture
python3 lab/capture_stage1.py http://127.0.0.1:18230/index.php 0x465370 0x65eb60
python3 lab/capture_stage1.py http://127.0.0.1:18231/index.php 0x465370 0x65eb60

# Off published shape probe (8.5.11)
cd lab/off
A_ARGS="0 62 235 15000 208 0 4000 103" \
  TARGET_PORT=18236 python3 off_try.py 18236 probe ../logs/8511-off-8M
```

The exact unmodified exploit control is `lab/run_exploit.sh`; it exits 1 because
its proof path is host-local, but the container proof is present in
`lab/logs/8426-on-8M/run1.log`.

### 8.2 Files

| Path | Contents |
|---|---|
| `report.md` | this report |
| `README.md` | one-page index and verdict |
| `metadata.txt` | commit, images/digests, container IDs, offsets, CVE facts |
| `SHA256SUMS` | checksums of the receipt files |
| `lab/driver_one.py` | repo-`Exploit` wrapper with in-container proof |
| `lab/capture_stage1.py` | raw On/Off stage-1 A/B capture |
| `lab/run_exploit.sh` | unmodified-exploit control wrapper |
| `lab/off/` | repo `send_a_oom5.py`/`send_b_open.py` copies, loopback-port patched |
| `lab/configs/` | php.ini variants, prefork/single-worker Apache configs, index/probe pages |
| `lab/logs/results.json` | machine-readable matrix |
| `lab/logs/*/driver-*.log`, `gate*.log`, `hm*.log`, `classic*.log` | authoritative run logs |
| `lab/logs/8426-on-8M/run1.log` | unmodified-exploit control |
| `lab/logs/*/capture-stage1.txt` | raw On/Off response lengths |
| `lab/logs/display_errors_gate.txt` | Apache log signature On vs Off |
| `lab/logs/env.txt`, `isolation.txt` | image/PHP/ASLR/port/mount facts |
| `lab/logs/aslr-groundtruth.txt` | end-of-run `/proc/1/maps` bases, personality, child counts, HTTP status |
| `lab/logs/source-anchors-8.5.11.txt` | 8.4.26 ↔ 8.5.11 source line mapping |
| `lab/logs/*/docker.log` | full Apache logs per container |
| `lab/logs/_invalid_concurrent/` | discarded concurrent runs (not used) |
| `lab/logs/8511-off-8M/off-probe/` | exploratory published-Off-shape probes (not used as proof) |

Repo clone, PHP source trees and the lab `libphp` binaries are not included in the
checksum set; the exact commit, image digests and libphp SHA-256 values are in
`metadata.txt`.

---

## Appendix A — offsets and CVE facts

| Symbol / constant | 8.4.26 | 8.5.11 |
|---|---|---|
| `zif_system` | `0x465370` (`t`) | `0x5996e0` (`t`) |
| `zval_ptr_dtor` | `0x65eb60` (`T`) | `0x7b47a0` (`T`) |
| bookworm `HTDATA` | `chunk+0x690d8` | `chunk+0x690d8` (verified) |
| stage1 filler count | 841 | 841 (verified) |
| stage2 target array / value | `a0443`, 16 | `a0443`, 16 (verified) |
| stage3 pads | 6 × (name 31, value 31) | same (verified) |
| libphp PT_LOAD min vaddr | 0 | 0 |

CVE-2026-109618 (published 2026-10-21; CNA CVSS 4.0 9.2, NVD CVSS 3.1 9.8): OOM
`longjmp` exits a context without unwinding request state; later request cleanup
may read/branch on uninitialized memory, leading to RCE. Affected: 8.2.<35,
8.3.<36, 8.4.<27, 8.5.<12. The public fix (`fix.patch`, commit `3584a98b…`) adds
`php_rinit_session_globals()` at `MULTIPART_EVENT_START` and replaces the OOM
bailout with `UnwindExit`; 8.5.11’s `session.c:3193` still lacks the reset, and
the 8.5.11 lab run is the operational confirmation.

## Appendix B — log index

| Log | Meaning |
|---|---|
| `lab/logs/8426-on-8M/driver-serial{1,2,3}.log` | 8.4.26 On 8M one-shot, 3/3 |
| `lab/logs/8511-on-8M/driver-serial{1,2,3}.log` | 8.5.11 On 8M one-shot, 3/3 |
| `lab/logs/8426-on-16M/gate{1,2}.log` | 8.4.26 On 16M, 2/2 |
| `lab/logs/8511-on-16M/gate{1,2}.log` | 8.5.11 On 16M, 2/2 |
| `lab/logs/8426-on-def/hm12-*.log` | 8.4.26 128M, 12 MB: no OOM, stage 1 0x0 |
| `lab/logs/8426-on-def/hm63-*.log` | 8.4.26 128M, 63 MB: stage 1/2 ok, stage 3 no proof |
| `lab/logs/8511-on-def/hm12-*.log`, `hm63-*.log` | 8.5.11 128M equivalents |
| `lab/logs/8426-off-8M/classic*.log`, `8511-off-8M/classic*.log` | classic chain Off 8M, 0/2 each |
| `lab/logs/8426-off-16M/classic*.log`, `8511-off-16M/classic*.log` | classic chain Off 16M, 0/2 each |
| `lab/logs/*/capture-stage1.txt` | raw On/Off stage-1 response lengths |
| `lab/logs/display_errors_gate.txt` | warning signature On vs Off |
| `lab/logs/aslr-groundtruth.txt` | end-of-run `/proc/1/maps` libphp bases (six On containers) |
| `lab/logs/source-anchors-8.5.11.txt` | 8.4.26 ↔ 8.5.11 anchor mapping |
| `lab/logs/8426-on-8M/run1.log` | unmodified exploit control (proof present, exit 1) |
