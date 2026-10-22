# PHP-level session injection + POP chains — stock-config assessment

Date: 2026-10-22
Scope: `session.upload_progress` write format, request-init decode timing, PHPGGC chain
inventory, and a stock PoC outline. No repo writes. All tests ran in a private lab on
loopback only (ports 9101/9102/9183–9187), then all lab processes were stopped.
The shared WP lab (28891/28893) and all other subagents' labs were not touched.

## TL;DR — answers

1. **Raw serialized-object injection via `PHP_SESSION_UPLOAD_PROGRESS` is not possible in
   any single-handler stock config.** The attacker controls the session *key*
   (`upload_progress_` + POST value, `session.c:3318`), but the `php` serializer refuses
   any key containing `|` (`session.c:1112`) and the write degrades to an empty file
   (`session.c:532–547`, verified: 0-byte `sess_*`). All attacker strings that end up in
   the *value* (upload filename, etc.) are length-prefixed by `serialize()`, so `|`,
   newlines and quotes inside them are inert (verified).
   The real primitive is a **serializer mismatch between writer and reader** — exactly the
   class documented in PHP bug #71101 ("serialize_handler must not be switched for existing
   sessions", 2015). Two variants were verified to reach `__destruct`: `php_serialize` →
   `php`, and `php` → `php_binary`.

2. **At upload-progress auto-start, decode runs pre-RINIT with no app autoloader**
   (`session.c:3229`), so only classes already present in the process are reachable:
   internal classes and `opcache.preload` classes. Since the 2026-10-21 security release
   (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), the decode additionally runs in
   `incomplete_classes_only` mode (**new**, `session.c:970–985`, `var_unserializer.re:1260`):
   *no class lookup at all* — no autoload, no `unserialize_callback_func`, no
   `__wakeup`/`__unserialize`. Verified A/B: 8.2.32 (pre-patch) fires a preloaded
   `__wakeup` and an `unserialize_callback_func`; 8.4.27 does neither, even with the class
   preloaded. No core internal class has `__destruct` at all, and the internal
   `__wakeup` set (Exception, Error, DateTime\*, SplFixedArray) has no dangerous gadget, so
   there is **no native/internal-only POP chain** (PHPGGC has none either).

3. **PHPGGC** (f8aebde, 2025-09-29): 170 chains total — Laravel 23, Symfony 19,
   WordPress 18 (incl. 2 WooCommerce plugin chains), Drupal 11, Joomla 1, Magento 4,
   **native/PHP-internal 0**. WordPress/RCE2 is a one-class gadget
   (`WP_HTML_Token::__destruct` → `call_user_func`), but WordPress core never calls
   `session_start()` (verified on 7.1.3), so a session-file injection cannot trigger it.
   Laravel never uses PHP's session module either (`Store::loadSession` → `unserialize()`,
   own file handler). Symfony and Joomla do call `session_start()`, but only read the ini
   `save_path` if their runtime config points there.

4. **A complete PHP-level chain exists, but it is deployment-level, not a stock single
   app.** Verified end-to-end on patched PHP 8.4.27 with default `cleanup=1`:
   slow multipart upload to a `php_serialize` pool (shared `save_path`) → mid-upload the
   session file contains `a:1:{s:52:"upload_progress_x|O:4:"Evil":…` → concurrent GET to a
   `php`-handler app whose autoloader is registered before `session_start()` → object
   injection → `Evil::__destruct` fired (`cmd=id`). Prerequisites and blockers in §5.

---

## 1. Method and environment

| Component | Version | How obtained |
|---|---|---|
| PHP (test target) | **8.4.27** (fpm-fcgi/cgi, NTS, Debian) | `apt-get download php8.4-{cli,cgi,fpm,common,opcache}` from trixie-security, `dpkg -x` into a private prefix |
| PHP (pre-patch control) | **8.2.32** (cgi-fcgi, Debian bookworm) | `deb.debian.org/debian/pool/main/p/php8.2/…8.2.32-1~deb12u1…` |
| Web server | nginx 1.30.1 (private instance, loopback 9186/9187) | `/opt/nginx-1.30.1` |
| PHPGGC | f8aebde (2025-09-29) | `git clone --depth 1` |
| WordPress | 7.1.3 | `wordpress.org/latest.tar.gz` (source inspection only) |

Why 8.4.27 matters: 2026-10-21 was a PHP security release (8.2.35 / 8.3.36 / 8.4.27 /
8.5.12). The upload-progress decode path changed in that release (see §3). The lab
therefore tested both a pre-patch build (8.2.32) and the patched build (8.4.27).

All requests were byte-exact multipart bodies built by hand (Python), not curl `-F`, so
quotes, `|`, control bytes and filename bytes were fully controlled.
Scripts: `labfpm/cgitest.py`, `labfpm/client.py`, inline capstone script (transcript in
`labfpm/TRANSCRIPT.md`).

---

## 2. Q1 — what the upload-progress handler actually writes

### 2.1 Write format (observed, `cleanup=0`)

Request: multipart POST, `PHP_SESSION_UPLOAD_PROGRESS=hello`, one file `a.txt`,
`Cookie: PHPSESSID=cginormal1`, script does **not** call `session_start()`.

`php` handler (stock default), 347 bytes:

```
upload_progress_hello|a:5:{s:10:"start_time";i:1792633825;s:14:"content_length";i:213;
s:15:"bytes_processed";i:213;s:4:"done";b:1;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";
s:1:"f";s:4:"name";s:5:"a.txt";s:8:"tmp_name";s:27:"/tmp/php…";s:5:"error";i:0;
s:4:"done";b:1;s:10:"start_time";i:…;s:15:"bytes_processed";i:1;}}}
```

- The key is `session.upload_progress.prefix` (default `upload_progress_`) concatenated with
  the **raw POST value** (`session.c:3318`).
- The session file is created by the upload callback alone; the script contained no
  `session_start()` and still produced the file. Same result through nginx+FPM.
- The upload filename is stored verbatim but **inside a length-prefixed serialized string**
  (`s:5:"a.txt"`), so `|`/quotes/newlines inside it are data, not syntax.

`php_serialize` handler, 391 bytes:

```
a:1:{s:52:"upload_progress_x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}";a:5:{…}}
```

`php_binary`: `\xNN<key><serialized value>` (length byte + key, no delimiter).

### 2.2 The delimiter check, and what happens when it trips

`ext/session/session.c` (8.4.27), `PS_SERIALIZER_ENCODE_FUNC(php)`:

```c
smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {   /* line 1112 */
    … fail = true; break;
}
smart_str_appendc(&buf, PS_DELIMITER);
```

On failure `php_session_encode()` returns NULL and the write path writes an empty string
(`session.c:532–547`): `s_write(…, ZSTR_EMPTY_ALLOC(), …)`.

Verified (`php` handler, progress value `x|O:4:"Evil":1:{…}`):

```
FILE: 0 bytes        # sess_cgipipe1
response: "B session keys:" (empty)
```

So the injection attempt is not only neutralised, it **erases the session file**.

The check is old, not a recent hardening: present in PHP 5.3, 5.4, 5.6, 7.0–7.4 and
8.0–8.5 sources (`session_PHP-*.c` in this receipt).

### 2.3 Values do not break out either

Progress value `p`, upload filename `x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}`, `php` handler:

```
upload_progress_p|a:5:{…s:4:"name";s:6:"x|O:4:";…}
```

Two independent reasons: the multipart quoted-string filename is cut at the second `"`
(PHP stores `x|O:4:`), and even a fully controlled value stays inside `s:<len>:"…"`.
Reading that session with the same handler yields the literal string, no object
(control test: no `__destruct`).

### 2.4 The actual primitive: writer/reader serializer mismatch

Bug #71101 (bugs.php.net, 2015) documents that switching `session.serialize_handler`
between writing and reading a session injects data. Two variants were reproduced:

**(a) `php_serialize` write → `php` read.** File starts
`a:1:{s:52:"upload_progress_x|O:4:"Evil":…`; the `php` decoder splits at the **first**
`|` (inside the serialized key), then `unserialize()`s from `O:4:"Evil":1:{…}`.
Observed: `POP_FIRED: class=Evil cmd=id` (the trailing container data is ignored; the
object is created regardless of the later decode failure).

**(b) `php` write → `php_binary` read.** No `|` needed: key =
`upload_progress_` (16 bytes) + `A`×102 + payload, so file offset 118 is the payload start.
`php_binary` reads `namelen = ord('u') = 117`, then unserializes at offset 118.
Observed: `POP_FIRED: class=Evil cmd=id`.

**Same-handler controls:** `php_serialize` both sides → key/value round-trips as a string,
no object; `php` both sides → no write at all for `|`; `php_binary` both sides →
length-prefixed, no object. None fired `__destruct`.

**Q1 conclusion:** no, not in a stock single-serializer config; yes, as a cross-serializer
confusion primitive. This is configuration-dependent, not attacker-only.

---

## 3. Q2 — autoload timing and what can be instantiated pre-RINIT

### 3.1 Timing

`php_session_rfc1867_update()` runs from the multipart parser, before RINIT:

```c
/* Runs before RINIT: no user code may be invoked, see php_session_unserialize_init() */
PS(in_rfc1867_update) = true;
if (php_session_initialize() == FAILURE || …) …
```

(`session.c:3229`). At that point the application's `spl_autoload_register`/Composer
autoloader does not exist yet; `auto_prepend_file` also runs later (RINIT). The only user
code that can have run is `opcache.preload` (master start).

### 3.2 Patched releases: no class is resolved at all

New in the 2026-10-21 release (absent in 8.4.26, 8.2.34, 8.1.34, 8.5.11 — verified by
tag diff):

```c
static void php_session_unserialize_init(php_unserialize_data_t *var_hash) {
    PHP_VAR_UNSERIALIZE_INIT(*var_hash);
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
}
```

and in `ext/standard/var_unserializer.re`:

```c
if ((*var_hash)->incomplete_classes_only) {
    /* Do not look the class up at all, so that no user code can run. */
    … incomplete_class = 1; ce = PHP_IC_ENTRY; break;
}
```

Result: every object in the session file becomes `__PHP_Incomplete_Class`, is written
back unchanged, and no magic method runs. `$_SESSION` is then deleted at
`MULTIPART_EVENT_END` (`session.c:3446`).

**Verified (8.4.27, opcache.preload defines `Evil::__wakeup` and `evil_cb`):**
session files `upload_progress_x|O:4:"Evil":0:{}` and `…"Nope"…`, then an upload request
with the same SID:

```
PRELOAD_MARK.txt: NONE   (no __wakeup, no unserialize_callback_func)
```

### 3.3 Pre-patch: already-loaded classes only

Same test on 8.2.32 (pre-patch), with the same preload:

```
wakeup:Evil
wakeup:Evil
callback:Nope
callback:Nope
PHP Warning: PHP Request Startup: Function evil_cb() hasn't defined the class it was called for …
```

(`__wakeup` twice because the progress callback initialises/decodes the session on both
FILE_START and END updates.) So before the patch, an object of an **already loaded** class
was instantiated and its `__wakeup`/`unserialize_callback_func` ran pre-RINIT. The app's
autoloader still never participates.

### 3.4 Which classes exist pre-RINIT, and can any form a chain?

Reflection over a bare PHP 8.4.27 (core + date + SPL + random) found 33 internal classes
with magic methods:

- `__destruct`: **none**.
- `__wakeup`: `Exception`, `Error`, `DateTime`, `DateTimeImmutable`, `DateTimeZone`,
  `DateInterval`, `DatePeriod`, `SplFixedArray`.
- `__unserialize`: `HashContext`, `Random\Engine\*`, `Random\Randomizer`, `ArrayObject`,
  `ArrayIterator`, `SplDoublyLinkedList`, `SplObjectStorage`.
- `__toString`: Reflection\*, `SplFileInfo`, `SplFileObject`, `DirectoryIterator`,
  `CachingIterator`.
- `__invoke`: `Closure`. `__call`: none of interest.

None of these execute a command, write a file, or include a path. The only IO-capable one
(`SplFileObject::__toString`) needs a caller that stringifies the object, i.e. a real POP
chain, which does not exist in core. **PHPGGC has no native/internal chain** (0 rows).

`unserialize_callback_func` is only invoked when the class is undefined
(`var_unserializer.re:1331`), and the function must already exist — i.e. preloaded or
defined by an extension. Pre-patch it fires (proved); post-patch it is skipped entirely
(proved).

**Q2 conclusion:** without `opcache.preload`, no POP chain is reachable at request-init
decode on any version. With preload, pre-patch versions instantiate preloaded classes
(`__wakeup`/`__destruct`), patched versions do not.

---

## 4. Q3 — PHPGGC inventory and reachability

`./phpggc -l` (170 chains, f8aebde):

| Family | Chains | Notes |
|---|---:|---|
| Laravel | 23 | RCE1–RCE22; gadget classes under `Illuminate\…` (Composer-autoloadable) |
| Symfony | 19 | RCE1–RCE16, FW1/2, FD1; `Symfony\Component\…` |
| WordPress | 18 | 12 non-plugin (RCE1/RCE2 use WP core; the rest vendor Dompdf/Guzzle/PHPExcel) + 6 plugin chains, incl. 2 WooCommerce |
| Drupal | 11 | Drupal/AT1, FD1, SQLI1, SSRF1, XXE1, PsySH; Drupal7 4; Drupal9/RCE1 |
| Joomla | 1 | `Joomla/FW1` (file write, 3.9.0–5.2.1) |
| Magento | 4 | Magento/FW1, SQLI1; Magento2/FD1, FD2 |
| **Native / PHP-internal** | **0** | no chain uses only engine classes |

Representative payloads:

```
WordPress/RCE2 : O:13:"WP_HTML_Token":2:{s:13:"bookmark_name";s:2:"id";s:10:"on_destroy";s:6:"system";}
Laravel/RCE9   : O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{…}
Drupal7/RCE1   : O:11:"SchemaCache":4:{…}
```

Reachability from a *stock* app, with no custom code and no served session file:

- **WordPress**: core (7.1.3) never calls `session_start()` — the only matches are strings
  in a Site Health message about other plugins. WP does not use PHP sessions at all, so the
  upload-progress session file is never read by core. The `WP_HTML_Token` one-class gadget
  is real but needs an app-side `unserialize()` sink (plugin), not this vector.
- **Laravel**: does not use PHP's session module. `Illuminate\Session\Store::loadSession()`
  calls `unserialize()` (Store.php:121) on data from its own handler
  (`storage/framework/sessions`), and `StartSession` never calls `session_start()`.
  PHP's `save_path` file written by upload-progress is never read.
- **Symfony** (`NativeSessionStorage.php`) and **Joomla** (`NativeStorage.php`) do call
  `session_start()`. However the rfc1867 write happens at request startup with the *ini*
  handler/save_path; if the app sets its own save_path/handler at runtime (Symfony
  `framework.session.save_path`, Joomla config), the poisoned file is written elsewhere and
  is never read. This is a per-deployment check, not a default.
- **Drupal / Magento**: custom session storage (DB / own files); PHP's upload-progress file
  is not their session store.

So the PHPGGC chains are **trigger-agnostic**: they only describe an object graph. This
vector supplies one specific trigger (`session_start()`), which most stock apps either do
not use or use with a different storage than the one the upload handler writes to.

---

## 5. Q4 — the only working chain, and its prerequisites

### 5.1 Verified end-to-end PoC (patched 8.4.27, default `cleanup=1`)

Deployment: two FPM pools sharing `session.save_path`:
- pool A: `session.serialize_handler=php_serialize`, docroot without `session_start`;
- pool B: default `php`, docroot whose bootstrap registers an autoloader **before**
  `session_start()` (simulating Composer).

Steps (transcript in `labfpm/TRANSCRIPT.md`):

1. Slow multipart POST to A (2 MB file), progress value
   `x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}`, pause after 64 KB.
2. Mid-upload, on disk:
   `a:1:{s:52:"upload_progress_x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}";a:5:{…}}` (368 bytes).
3. Concurrent GET to B with the same `PHPSESSID` → `session_start()` → decode splits at
   `|` → `Evil` object → `POP_FIRED: class=Evil cmd=id`.
4. Upload finishes; default cleanup truncates the file (6 bytes).

The race is real and measurable: with `cleanup=1` the file existed mid-upload (326 bytes)
and was empty after END; with `cleanup=0` it persisted. A pause after only 4 KB did **not**
show the file — the SAPI fills 16 KB blocks before the parser runs — so the window starts
after the first block.

### 5.2 Exact prerequisites

1. **Write side**: a request path whose `session.serialize_handler` differs from the read
   side (`php_serialize` or `php_binary` vs `php`), sharing the same `session.save_path`.
   Per-directory `.user.ini`/`.htaccess` or per-pool FPM config can create this; a single
   stock app cannot.
2. **Attacker-chosen SID that the read app accepts**: `session.use_strict_mode=0` (stock
   default) and a charset-valid id (`[A-Za-z0-9,-]`). No cookie is needed on the write
   request: a body field named `PHPSESSID` sets `progress->sid` even with
   `use_only_cookies=On` (verified: `sess_cgibody1` created without a cookie; source:
   FORMDATA sets `progress->sid`, `early_find_sid()` only checks cookie/GET).
3. **Timing**: with default `cleanup=1`, the poisoned key exists only while the upload is in
   flight; the read request must land in that window (multi-worker SAPI needed). With
   `cleanup=0` the file persists.
4. **Read side**: an app that (a) actually calls PHP's `session_start()`, (b) uses the same
   save_path/handler as the ini at request start, and (c) has the gadget class autoloadable
   when `session_start()` runs. A Composer autoloader registered before the session
   middleware satisfies (c). PHPGGC Laravel/Symfony/WordPress chains can supply the graph
   if the matching library version is installed.
5. **Object graph**: any PHPGGC chain for an installed library (e.g. Laravel/RCE9,
   Symfony/RCE*, WordPress/RCE2 for a plugin that starts sessions and has WP core loaded).
   If the app only has core PHP classes, there is no chain (§3.4).

### 5.3 Blockers (why this is not a stock single-app RCE)

- **No write primitive in a single stock config**: the `|` check + length-prefixed values.
- **No autoloader at request-init**: userland gadgets cannot be loaded at the auto-start
  decode; only preloaded classes (non-stock) or internal classes (no gadget).
- **Patched decode**: 8.2.35+/8.3.36+/8.4.27+/8.5.12 resolve no classes in the
  upload-progress path at all, even preloaded ones.
- **Trigger mismatch**: WordPress and Laravel never call `session_start()`; Drupal/Magento
  use their own storage; Symfony/Joomla may use a different save_path than the ini.
- **cleanup=1 race** required by default; `cleanup=0` is a non-default hardening reversal.
- **`use_strict_mode=1`** (recommended, not default) rejects the attacker SID.
- **Session id charset** `[A-Za-z0-9,-]` blocks path tricks on the save_path.
- PHP ≤ 8.1 is EOL and unpatched for CVE-2026-109618/109619, but it still has no autoloader
  at request-init; preload is required for userland magic methods.

### 5.4 Where it does apply

Shared hosting / multi-app servers where two request paths use different
`session.serialize_handler` values but the same session save path, plus at least one app
that uses PHP-native sessions with an autoloadable gadget library. Also pre-patch
deployments that preload vendor classes (opcache.preload) and expose an upload endpoint:
pre-8.2.35/8.3.36/8.4.27 `__wakeup`/`__destruct` of preloaded classes runs at request
startup.

---

## 6. Side finding: session id from a multipart body field

Verified: with no cookie at all, a body field named `PHPSESSID` created
`sess_<chosen-id>` while `session.use_only_cookies=On` (stock default) and the response
simultaneously set a random cookie (the app's own `session_start()` had no cookie).

Source: `MULTIPART_EVENT_FORMDATA` assigns `progress->sid` from the field before
`php_session_rfc1867_early_find_sid()` runs; that function only overwrites from
cookie/GET and returns early on `use_only_cookies`, leaving the body value intact.

Impact here: the write request can choose the session file name without a cookie. It is
not session fixation against a victim (the victim's browser is not given that id).

---

## 7. Evidence inventory

| File | Content |
|---|---|
| `session.c` | PHP 8.4.27 `ext/session/session.c` (line refs above) |
| `var_unserializer_84.re` | PHP 8.4.27 unserializer (incomplete-class mode) |
| `session_php-8.4.26.c`, `session_php-8.4.27.c`, `session_php-8.2.34.c`, `session_php-8.2.35.c`, `session_php-8.1.34.c`, `session_php-8.5.11.c` | tag diff proving when `incomplete_classes_only` landed |
| `session_PHP-5.3.c … PHP-8.3.c` | delimiter check present since 5.3 |
| `SAPI.c`, `rfc1867.c` | post-reader streaming path (`multipart_buffer_read`) |
| `phpggc_full.txt` | `./phpggc -l`, 170 chains |
| `labfpm/cgitest.py`, `labfpm/client.py` | byte-exact multipart drivers |
| `labfpm/sess/` | raw session files from every test |
| `labfpm/logs/`, `labfpm/nginx/logs/` | FPM/nginx logs |
| `labfpm/TRANSCRIPT.md` | command/output transcript of the key runs |
| `wordpress/` | WordPress 7.1.3 source (session_start grep) |

---

## 8. Citations

- PHP source, 8.4.27: `ext/session/session.c` lines 925 (serialize_handler, PHP_INI_ALL),
  944–954 (upload_progress defaults: enabled=1, cleanup=1, prefix `upload_progress_`,
  name `PHP_SESSION_UPLOAD_PROGRESS`), 970–985 (incomplete-class init), 1112 (delimiter
  check), 1133–1180 (`php` decoder), 1767 (`php_session_flush`), 520–547 (empty write on
  encode failure), 3229 (pre-RINIT), 3318 (key = prefix + raw value), 3446 ($_SESSION
  deleted at END).
  https://github.com/php/php-src/blob/php-8.4.27/ext/session/session.c
- PHP source, 8.4.27: `ext/standard/var_unserializer.re` lines 57–61, 108, 1260–1266
  (no class lookup in incomplete mode), 1331 (`unserialize_callback_func`), 1376.
  https://github.com/php/php-src/blob/php-8.4.27/ext/standard/var_unserializer.re
- PHP bug #71101 — "serialize_handler must not be switched for existing sessions"
  (2015), the canonical description of the cross-serializer injection class.
  https://bugs.php.net/bug.php?id=71101
- PHP manual, `session.upload_progress.*` (enabled/cleanup defaults, prefix/name).
  https://www.php.net/manual/en/session.configuration.php
- HackTricks, "LFI2RCE via PHP_SESSION_UPLOAD_PROGRESS" (session file creation without
  `session_start`, cleanup race, prefix issue).
  https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/via-php_session_upload_progress.html
- NVD CVE-2026-109618 and CVE-2026-109619 (2026-10-21, the memory-corruption chain;
  context for the patch that also added `incomplete_classes_only`).
  https://nvd.nist.gov/vuln/detail/CVE-2026-109618
  https://nvd.nist.gov/vuln/detail/CVE-2026-109619
- PHP 8.4.27 release (2026-10-21). https://www.php.net/releases/
- PHPGGC. https://github.com/ambionics/phpggc
- Laravel `Illuminate\Session\Store::loadSession` (`unserialize` at line 121), no
  `session_start`. https://github.com/laravel/framework/blob/11.x/src/Illuminate/Session/Store.php
- Symfony `NativeSessionStorage` (`session_start`).
  https://github.com/symfony/http-foundation/blob/7.3/Session/Storage/NativeSessionStorage.php
- Joomla session `NativeStorage` (`session_start`).
  https://github.com/joomla-framework/session/blob/3.x-dev/src/Storage/NativeStorage.php

---

## 9. Limitations / not verified

- Real framework deployments were inspected at source level only; no Laravel/Symfony/
  Drupal/Magento instance was run. Claims about their session storage are source-based.
- The pre-patch magic-method test required `opcache.preload` (the only way to have a class
  defined before RINIT); a stock pre-patch deployment without preload would show
  `__PHP_Incomplete_Class`, not `__wakeup`.
- The race was observed with nginx `fastcgi_request_buffering off` and a 2 MB upload;
  timings are environment-specific. The 16 KB block threshold is an inference from the
  observed behaviour, not read from the SAPI source.
- Docker Hub rate-limited the intended container A/B; Debian 8.2.32 from the bookworm pool
  was used as the pre-patch control instead (built 2026-07-03, before the fix).
- Only PHP 8.4.27 and 8.2.32 were executed. Version claims for 8.3/8.5 are from tag diffs.
- Some public write-ups found during research claim filename-based injection and
  `__destruct`-on-decode-failure in a *single*-handler config. The first is false (the
  filename is inside a length-prefixed string; verified), the second is true only because
  of a serializer mismatch (verified) — the second is exactly §2.4.
