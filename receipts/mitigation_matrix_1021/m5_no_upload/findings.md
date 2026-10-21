# "Block file uploads entirely" vs the PHP 8.5.10 multipart-filename OOM arm

Date: 2026-10-21. Scratch source: `/tmp/opencode/no_upload_mitigation_1021/`
(curated copy: this directory). Loopback only, ports 29060-29068 (HTTP) and
29074 (php-cgi FastCGI listener). No service outside this run was touched.

Question: **does "block file uploads entirely" actually mitigate the known
upload-progress OOM arm**, and at what cost?

Short answer: **yes for three of the mechanisms, but only the nginx edge rule
does it without touching the application**. `file_uploads=0` and
`max_file_uploads=0` both make the arm harmless at 8 MiB (the multipart parser
skips file parts before the OOM-triggering allocation), `enable_post_data_reading=0`
disables POST parsing altogether, the nginx `415` rule stops the request before
PHP reads a single body byte, and `post_max_size=0` is **not** a mitigation at
all (0 means *unlimited*).

This block is the **M5 (no-upload application)** lane of the matrix: every
control here is valid only for an application that genuinely does not accept
file uploads. For an app that needs uploads, use the M2/E1 cap-plus-headroom
rules instead (see `docs/mitigation_matrix_1021.md`).

---

## 1. Verdicts

| lane | mechanism | byte-exact 4,983,500 B arm | PHP fatal | verdict |
|---|---|---|---|---|
| **U0** | control: no rule, `memory_limit=8M` | **200**, empty body, worker dies | **yes** `8388608/266240` | baseline, broken |
| **U1** | PHP `file_uploads=0` (php-fpm **and** php-cgi) | **200**, script output, `$_FILES` empty | **no** | **effective for the OOM**, silently breaks every upload; all normal fields still parse |
| **U2** | PHP `enable_post_data_reading=0` | **200**, script output, no POST parsing | **no** | **effective**, but breaks every form/multipart POST (`$_POST`/`$_FILES` empty); `php://input` still readable |
| **U3** | nginx edge `415` on `multipart/form-data` (map + `if`) | **415 before PHP**, 0 FPM log bytes, no session | **no** | **effective and surgical** for no-upload apps; upload endpoints rejected by design |
| **U3b** | refined edge rule: `415` only for `POST/PUT/PATCH` multipart | **415 before PHP** | **no** | **effective**, no false positive on GET; same upload tradeoff |
| **U4** | nginx `client_max_body_size 128k` alone (PHP 8M) | **413 before PHP** | **no** | **effective for this arm at 8M**; under-cap multipart still parses safely; uploads >128k broken |
| **U5** | PHP `max_file_uploads=0` | **200**, startup **warning**, files dropped | **no** (warning only) | **effective for the OOM**, but noisy: the startup warning is emitted before the script, breaking `session_start()`/`header()` |
| **U6** | PHP `post_max_size=0` | **200**, empty body, worker dies | **yes** `8388608/266240` | **ineffective**: 0 = unlimited, POST parsing stays on |

"Effective" = the arm does not produce `Allowed memory size ... exhausted`.
It does not mean "safe for an app that needs uploads" - see the tradeoff column
and section 12.

---

## 2. Environment and arm

| component | value |
|---|---|
| nginx | `/opt/nginx-1.30.1/sbin/nginx` (1.30.1; core only, no njs/lua/modsec) |
| PHP | `/home/davide/ailocal/php/zerodays_1020/install_plain/` - `PHP 8.5.10 (fpm-fcgi)` and `php-cgi` |
| PHP config | `lanes/php.ini` (stock upload INI: `post_max_size=8M`, `upload_max_filesize=8M`, `file_uploads=On`, `max_file_uploads=20`, `session.upload_progress.enabled=1`, `cleanup=0`, `name=PHP_SESSION_UPLOAD_PROGRESS`), per-pool `memory_limit=8M` and `session.save_path` |
| arm | `bin/narm.py:arm_body()`: field `PHPSESSID`, field `PHP_SESSION_UPLOAD_PROGRESS=MMM`, 20 file parts (`filename` = `F`*9 then `F`*262144 x19), terminator. **4,983,500 B**, sha256 `a76bf15d60d2967325dd8985c880c27ea3727a908a50103cfa09fe3443e37d75`, 20 `filename=` occurrences |
| cookie | `PHPSESSID=armsess1021` (fixed 11-char sid keeps the body byte-exact) |
| measurement | `bin/measure.py`: before/after deltas of the FPM error log, FPM access log, nginx access/error log, session dir, worker PIDs and FPM master log |

Harness derived from the reference lab's `bin/narm.py` + `bin/battery.py` +
`conf/{nginx,php-fpm}.conf`; the reference directory was not modified.

Lanes / ports / exact config:

| lane | port | nginx edge | PHP |
|---|---:|---|---|
| U0 | 29060 | `client_max_body_size 8m` (no rule) | `memory_limit=8M` |
| U1 | 29061 | `client_max_body_size 8m` | `php_admin_flag[file_uploads]=off`, 8M |
| U1cgi | 29067 | `client_max_body_size 8m` | `php-cgi -d file_uploads=0`, 8M |
| U2 | 29062 | `client_max_body_size 8m` | `php_admin_flag[enable_post_data_reading]=off`, 8M |
| U3 | 29063 | `map $http_content_type $u3_reject { default 0; "~*^multipart/form-data" 1; }` + `if ($u3_reject) { return 415; }` in `location ~ \.php$` | 8M |
| U3b | 29068 | `map "$request_method:$http_content_type" ... "~*^(POST\|PUT\|PATCH):multipart/form-data" 1` + `return 415` | 8M |
| U4 | 29064 | `client_max_body_size 128k` only | 8M |
| U5 | 29065 | `client_max_body_size 8m` | `php_admin_value[max_file_uploads]=0`, 8M |
| U6 | 29066 | `client_max_body_size 8m` | `php_admin_value[post_max_size]=0`, 8M |

Effective INI (fresh per-lane probes, `results/ini/*_fresh.txt`; `1`/`0` are
PHP's string booleans):

| lane | memory_limit | post_max_size | file_uploads | enable_post_data_reading | max_file_uploads | upload_progress.enabled | cleanup |
|---|---|---|---|---|---|---|---|
| U0 | 8M | 8M | 1 | 1 | 20 | 1 | 0 |
| U1 | 8M | 8M | **0** | 1 | 20 | 1 | 0 |
| U1cgi | 8M | 8M | **0** | 1 | 20 | 1 | 0 |
| U2 | 8M | 8M | 1 | **0** | 20 | 1 | 0 |
| U3 | 8M | 8M | 1 | 1 | 20 | 1 | 0 |
| U3b | 8M | 8M | 1 | 1 | 20 | 1 | 0 |
| U4 | 8M | 8M | 1 | 1 | 20 | 1 | 0 |
| U5 | 8M | 8M | 1 | 1 | **0** | 1 | 0 |
| U6 | 8M | **0** | 1 | 1 | 20 | 1 | 0 |

---

## 3. Results matrix (arm + companion cases)

All rows below are from `results/lanes.jsonl`; the full **46-row** dump is
`results/table.md` (the block has 46 measured rows: U0 3, U1 7, U1cgi 3, U2 5,
U3 7, U3b 7, U4 8, U5 4, U6 2).

| lane / case | body B | HTTP | resp B | `Fatal error` in FPM log | `Unknown on line 0` grep | OOM limit / tried | FPM access line | new session (upload_progress) | worker changed |
|---|---:|---:|---:|---|---|---|---|---|---|
| U0 arm | 4,983,500 | 200 | 351 | **YES** | fatal | **8,388,608 / 266,240** | no | `sess_armsess1021` (**yes**, 330 B) | **YES (exit 70)** |
| U0 small multipart sanity | 1,333 | 200 | 673 | no | - | - | yes | yes | no |
| U1 arm (clean) | 4,983,500 | 200 | 630 | no | - | - | yes | `sess_armsess1021` (no, 0 B) | no |
| U1 arm peak-memory run | 4,983,500 | 200 | 419 | no | - | - | yes | 0 B | no |
| U1 small multipart | 1,333 | 200 | 632 | no | - | - | yes | 0 B | no |
| U1 legit upload | 1,435 | 200 | 300 | no | - | - | yes | - | no |
| U1cgi arm | 4,983,500 | 200 | 633 | no | - | - | n/a (php-cgi) | 0 B | no |
| U1cgi small multipart | 333 | 200 | 635 | no | - | - | n/a | 0 B | no |
| U2 arm | 4,983,500 | 200 | 593 | no | - | - | yes | 0 B | no |
| U2 urlencoded POST | 7 | 200 | 313 | no | - | - | yes | - | no |
| U2 `php://input` | 7 | 200 | 255 | no | - | - | yes | - | no |
| U3 arm | 4,983,500 | **415** | 342 | no | - | - | **no** | **none** | no |
| U3 urlencoded POST | 7 | 200 | 312 | no | - | - | yes | - | no |
| U3 plain GET | 0 | 200 | 1,123 | no | - | - | yes | - | no |
| U3 GET + multipart CT | 0 | **415** | 342 | no | - | - | no | - | no |
| U3 legit multipart upload | 1,435 | **415** | 342 | no | - | - | no | - | no |
| U3 mixed-case multipart CT | 334 | **415** | 342 | no | - | - | no | - | no |
| U3b arm | 4,983,500 | **415** | 342 | no | - | - | no | none | no |
| U3b urlencoded POST | 7 | 200 | 312 | no | - | - | yes | - | no |
| U3b plain GET | 0 | 200 | 1,124 | no | - | - | yes | - | no |
| U3b GET + multipart CT | 0 | **200** | 1,124 | no | - | - | yes | - | no |
| U3b legit upload | 1,435 | 415 | 342 | no | - | - | no | - | no |
| U4 arm | 4,983,500 | **413** | 348 | no | - | - | **no** | **none** | no |
| U4 tiny multipart + progress | 1,332 | 200 | 672 | no | - | - | yes | **yes** (done=1) | no |
| U4 dense 4 x 29,505 B names | 118,713 | 200 | 801 | no | - | - | yes | yes (4 files) | no |
| U4 near cap, 1 x 128,000 B name | 128,328 | 200 | 673 | no | - | - | yes | yes | no |
| U4 exactly at cap | 131,072 | 200 | 677 | no | - | - | yes | yes | no |
| U4 over cap | 140,000 | **413** | 348 | no | - | - | no | none | no |
| U4 legit upload | 1,435 | 200 | 557 | no | - | - | yes | - | no |
| U5 arm | 4,983,500 | 200 | 1,019 | **no** | **warning** see 6.5 | - | yes | none | no |
| U5 two files | 2,458 | 200 | 1,019 | no | warning | - | yes | none | no |
| U5 fields only (no file part) | 178 | 200 | 604 | no | - | - | yes | yes | no |
| U5 legit upload | 1,435 | 200 | 618 | no | warning | - | yes | none | no |
| U6 arm | 4,983,500 | 200 | 351 | **YES** | fatal | **8,388,608 / 266,240** | no | `sess_armsess1021` (**yes**) | **YES (exit 70)** |
| U6 urlencoded POST | 7 | 200 | 311 | no | - | - | yes | - | no |

Notes: `client_max_body_size 128k` = **131,072 B**, and a body of exactly
131,072 B is accepted (measured); 140,000 B is 413. A pre-RINIT fatal writes
**no** FPM access line, so the error log is the authoritative "PHP saw it" signal.

---

## 4. Baseline (U0) - reproduction

Client: `HTTP/1.1 200 OK`, chunked, 351 B on the wire, body is the fatal HTML
(`display_errors=On`) followed by the empty chunk.

FPM pool error log (169-byte delta, `logs/fpm_u0.error.log`):

```
PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted
(tried to allocate 266240 bytes) in Unknown on line 0
```

No FPM access line. Session file `sess_armsess1021` (330 B) **is** created and
contains `upload_progress_MMM` - the parser writes upload-progress state before
it dies. The worker exits (`logs/php-fpm-master.log`):

```
WARNING: [pool u0] child 1068058 exited with code 70 after 7.077900 seconds from start
NOTICE:  [pool u0] child 1068130 started
```

So the arm is an availability event (worker recycle) as well as a 200-with-empty-body
event; both U0 and U6 show it.

---

## 5. Lane 1 - PHP `file_uploads=0` (the classic hardening)

**Measured (php-fpm 8.5.10, `php_admin_flag[file_uploads]=off`, 8 MiB):**

* byte-exact arm -> **HTTP 200**, 630 B script output, **no fatal, no OOM line**,
  FPM access line present, worker stable.
* `$_FILES` is **empty**; `$_POST` still contains the two normal fields
  (`PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS`); **no warning at all** - file
  parts are dropped silently.
* session file is created by `session_start()`, but it is **0 bytes**: no
  `upload_progress_*` payload is written, so the second half of the classic arm
  (session serialisation of the giant filename) is gone too.
* request peak memory (`memory_get_peak_usage`): **1,148,224 B emalloc /
  2,097,152 B real** vs 453,288 B emalloc for a tiny multipart request. The
  parser still copies the 262,144-byte filename (the ~0.66 MiB delta) but never
  reaches the allocation path that requests 266,240 B.
* cross-SAPI confirmation: **php-cgi** `-d file_uploads=0` gives the same result
  (200, 633 B, no fatal, `file_uploads='0'`).

Source-level reason: `main/rfc1867.c:914-915` ("If file_uploads=off, skip the
file part") sets `skip_upload=1`; the code then `efree(param); efree(filename);
continue;` **before** `multipart_buffer_read()` / temp-file creation, which is
the path that makes the 266,240-byte allocation. The parser still consumes the
whole 4.98 MB body to find boundaries (so no bandwidth saving), it just does not
accumulate/duplicate it.

Tradeoffs: every upload is silently discarded (`upload.php` -> `{"ok":false}`,
no warning), so an app with any upload feature loses it with no diagnostic.
`file_uploads` is `PHP_INI_SYSTEM`: it cannot be set with `ini_set()` or
`.user.ini`, only in php.ini/FPM pool config.

**Verdict: effective at preventing the OOM; acceptable only for apps that truly
never accept uploads; otherwise the nginx rule is strictly better (no app change,
no body read).**

---

## 6. Lane 2 - PHP `enable_post_data_reading=0`

**Measured (php-fpm, 8 MiB):**

* byte-exact arm -> **HTTP 200**, 593 B, **no fatal**, FPM access line present,
  worker stable, no upload-progress session payload.
* `$_POST` and `$_FILES` are **empty for every request**: a legitimate
  `application/x-www-form-urlencoded` POST returns 200 but `post_keys=` is empty
  and `v=<unset>`.
* `php://input` is **still readable** (7/7 bytes returned) - so raw-body
  endpoints (JSON APIs that read `php://input` and do not rely on `$_POST`) can
  survive, but every form/multipart endpoint is broken.
* nginx still buffers the body to disk (measured `a client request body is
  buffered to a temporary file`), so no bandwidth/disk saving either.

**Verdict: effective, but the broadest application breakage of the PHP-side
knobs. Only defensible for a service that is known not to use `$_POST`/`$_FILES`
at all; not a general hardening step.**

---

## 7. Lane 3 - nginx edge: reject `multipart/form-data` with 415

Config (U3, all methods):

```nginx
map $http_content_type $u3_reject {
    default 0;
    "~*^multipart/form-data" 1;
}
...
location ~ \.php$ {
    if ($u3_reject) { return 415; }
    include /opt/nginx-1.30.1/conf/fastcgi_params;
    fastcgi_pass unix:/tmp/opencode/no_upload_mitigation_1021/run/fpm_u3.sock;
    ...
}
```

**Measured (U3):**

* arm -> **415**, 342 B nginx error page, **0 bytes delta in the FPM error log
  and 0 in the FPM access log**, **no session file**, worker untouched, and
  `upst=-` (FPM never contacted).
* proof the body was not read: nginx access line `req_len=222` while
  `cl=4983500`; nginx answered after the headers only. This is the key
  difference from the earlier `$request_body` lesson: **the rule reads
  `$http_content_type`, a request header available in the rewrite phase, so it
  fires before the body exists**.
* legitimate `application/x-www-form-urlencoded` POST -> **200**, `$_POST`
  parsed (`v=hello`), FPM access line present.
* plain `GET /probe.php` (no Content-Type) -> **200**.
* mixed-case `Multipart/Form-Data; boundary=...` -> **415** (the `~*` map is
  case-insensitive).
* **coarse-rule false positive:** a `GET` that carries a `multipart/form-data`
  header but no body also gets 415 (header-only rule). Real browsers do not do
  this for GET, but the refined lane U3b fixes it:
  `map "$request_method:$http_content_type" ... "~*^(POST|PUT|PATCH):multipart/form-data" 1`
  -> GET + multipart header = **200**, arm = **415**, urlencoded POST = **200**.
* tradeoff: a legitimate small multipart upload to `/upload.php` gets **415**
  (that is the intent for a no-upload app; it is why this rule cannot be used on
  an app that needs uploads).

**Verdict: effective, the cleanest mitigation of the set: it stops the arm
before PHP, leaves normal POST/GET traffic untouched, and needs no application
or PHP configuration change. Recommended for "no-upload" apps, preferably with
the refined method-scoped map.**

---

## 8. Lane 4 - nginx `client_max_body_size 128k` alone (PHP 8M)

**Measured (U4):**

* arm -> **413**, 348 B, no FPM access line, no session file, worker stable;
  nginx error log: `client intended to send too large body: 4983500 bytes`.
* tiny multipart body (1,332 B) **with the progress field** -> **200**, 672 B,
  no fatal; `$_FILES` has `f0` (1,000 B); session file contains
  `upload_progress_MMM|...done:b:1` -> **the parser path is still hit, and at
  8 MiB a small body is harmless**, exactly as expected.
* filename-dense body under the cap: 4 parts with 29,505-byte filenames
  (118,713 B total) -> **200**, no fatal, all 4 files parsed, upload-progress
  session written.
* worst case under the cap: one 128,000-byte filename (128,328 B total) ->
  **200**, no fatal, `name_len=128000` in `$_FILES`.
* exactly 131,072 B (128k) -> 200; 140,000 B -> 413.
* legitimate 1,435 B upload -> 200, `ok:true`, stored byte-identical.

This is consistent with the reference lab's headroom rule
(`memory_limit >= 6.5 x client_max_body_size + ~1 MiB`): 6.5 x 131,072 ~ 0.85 MB,
so 8 MiB has ample margin. The same rule is why a **2 MiB** cap with 8 MiB
still OOMs (measured in the reference work): 6.5 x 2 MiB ~ 13 MiB.

**Verdict: effective against the 4.98 MB arm and safe at 8 MiB because the cap
is tiny; but it is a size cap, not an upload block. It breaks legitimate
uploads larger than 128 KiB and does nothing about under-cap multipart parsing
(which is safe only because 128k << 8M). Use it as a second layer on top of the
415 rule, not as the upload mitigation by itself.**

---

## 9. Lane 5 - PHP `max_file_uploads=0`

**Measured (php-fpm, 8 MiB):**

* arm -> HTTP 200, 1,019 B, **no fatal and no OOM line**, but the body starts
  with three warnings:

```
Warning:  PHP Request Startup: Maximum number of allowable file uploads has been
          exceeded in Unknown on line 0
Warning:  session_start(): Session cannot be started after headers have already
          been sent in .../index.php on line 4
Warning:  Cannot modify header information - headers already sent in .../index.php on line 5
```

* the startup warning is emitted **before the script runs**, so it is written to
  the response first: `session_start()` then fails, `sid=` is empty, **no
  session file is created**, `$_FILES` is empty, and any script that sets
  headers/uses sessions is visibly broken for that request (HTTP status is
  still 200).
* the warning is emitted only when the body actually contains a file part: a
  multipart body with fields only (178 B) parses normally with no warning and a
  working session (`sessions/u5/sess_nofilepart01`).
* a legitimate upload gets the same warning and `{"ok":false}`.
* `err_delta` 502 chars; worker stable.

Important detection gotcha: `grep "Unknown on line 0"` **matches this warning**,
but there is no `Fatal error` and no OOM. A monitor that greps only
`Unknown on line 0` would misclassify it.

**Verdict: prevents the OOM (skip_upload path, same as `file_uploads=0`) but is
the noisiest option: every request carrying a file part gets a pre-script
warning that breaks sessions/headers. Prefer `file_uploads=0` or the edge rule.**

---

## 10. Lane 6 - PHP `post_max_size=0` (semantics check)

**Measured:** the arm produces the **identical baseline fatal**
(`8388608 / 266240`, 351 B, no access line, upload-progress session written,
worker exit 70). A normal urlencoded POST still works (`post_max=0`,
`$_POST['v']=hello`).

So `post_max_size=0` **does not disable POST**; it removes the size limit
(source: `main/rfc1867.c` checks `if (post_max_size > 0 && content_length >
post_max_size)`, so 0 bypasses the check; PHP >= 5.6 documents 0 as unlimited).

**Verdict: ineffective - worse than the default, because it also removes the
only body-size guard.**

---

## 11. Cross-cutting observations

* **Client-visible status is not a reliable OOM signal.** The baseline and U6
  return `200` with an empty chunked body; display_errors also embeds the fatal
  HTML in some cases. Only the FPM error log shows the OOM.
* **Pre-RINIT fatal = no FPM access line.** For U0/U6 the access log delta is 0,
  and the worker is recycled (`exit code 70`) - this is why "0 FPM access lines"
  alone does not prove "PHP never saw it"; you must also check the FPM error log
  and the session directory (as done for U3/U4: err=0, acc=0, no session file,
  `upst=-`).
* **Session artifacts track the parser, not the script.** U0/U6 create
  `sess_armsess1021` with upload-progress data even though the script never
  runs; U1/U2 create an empty 0-byte session file (session_start only); U3/U4
  (rejected) create none; U4 under-cap creates one with `upload_progress` and
  `name_len` equal to the supplied filename, proving the parser was reached.
* **`file_uploads=0` does not stop the body from being read** (nginx still
  buffered 4.98 MB to a temp file); it only prevents the upload data path.
* PHP-FPM was measured with `display_errors=On` and `cleanup=0` so that
  warnings/fatals and upload-progress payloads are visible; with
  `display_errors=Off` the U5 warning would go only to the log, but the
  session/header breakage would remain.

Measurement caveat (not a product finding): a long-lived opcache entry for
`index.php` was observed reporting `file_uploads`/`max_file_uploads` from the
pool that compiled it (PHP's optimizer can constant-fold literal
`ini_get()` calls for `ZEND_INI_SYSTEM` entries,
`Zend/Optimizer/zend_optimizer.c:164`). Verdicts therefore use per-lane
**freshly compiled** probe scripts (`results/ini/<lane>_fresh.txt`) plus the
observed behaviour (fatal, `$_FILES`, session payload), not a reused script's
`ini_get()` output. The non-`_fresh` dumps under `results/ini/` are kept as the
raw reused-worker transcripts and show the stale values.

---

## 12. Recommended recipe

### For a "no-upload" application (recommended)

```nginx
# 1) reject multipart bodies at the edge, before PHP
map $http_content_type $reject_multipart {
    default 0;
    "~*^multipart/form-data" 1;
}
# optional stricter variant (avoids 415 on a bodyless GET carrying the header):
# map "$request_method:$http_content_type" $reject_multipart {
#     default 0;
#     "~*^(POST|PUT|PATCH):multipart/form-data" 1;
# }

server {
    client_max_body_size 128k;      # 2) tiny cap for all other bodies too

    location ~ \.php$ {
        if ($reject_multipart) { return 415; }
        include /opt/nginx-1.30.1/conf/fastcgi_params;
        fastcgi_pass ...;
    }
}
```

PHP side (php.ini / FPM pool - defence in depth, not required once the edge
rule is in place):

```ini
file_uploads = Off
session.upload_progress.enabled = 0
; memory_limit >= 8 x client_max_body_size; 128k cap -> 8M is ample, 16M gives margin
```

Why this order:

* the 415 fires in the rewrite phase from a header, so **PHP never reads the
  body** (measured `req_len=222` for a 4.98 MB request), which also saves
  bandwidth, temp files and worker churn;
* the 128k cap bounds every other POST body and keeps the multipart parser far
  below the 8 MiB limit even if a multipart request somehow reaches PHP;
* `upload_progress=0` and `file_uploads=Off` remove the amplifier if the edge
  rule is ever bypassed/misconfigured (e.g. a new vhost);
* normal urlencoded POSTs and GETs are unaffected (measured 200).

The measured recommended combination is therefore: **edge `415` (method-scoped
map) + `client_max_body_size 128k` + `file_uploads=Off` +
`session.upload_progress.enabled=0`**; GET and urlencoded POST stay 200.

### For an application that *does* need uploads

Do **not** use the 415 rule, `file_uploads=0` or `max_file_uploads=0` - they
break uploads (silently in the first two cases). Use a cap plus headroom:

```
memory_limit >= 6.5 x client_max_body_size + ~1 MiB      (use 8x for margin)
```

Examples: 2 MiB cap -> >= 14 MiB, use 16 MiB (8 MiB with a 2 MiB cap was
measured fatal in the reference lab); 8 MiB cap -> >= 53 MiB, use 64 MiB.
`session.upload_progress.enabled=0` can stay off if upload progress is not
needed, but it is not a substitute for headroom.

---

## 13. Artifacts (this receipt block)

```
m5_no_upload/
  findings.md                this report (paths made receipt-relative)
  conf/nginx.conf            one server block per lane (29060-29068)
  conf/php-fpm.conf          one pool per lane, own socket/log/session dir
  lanes/php.ini              shared stock upload INI
  docroot/                   index.php, probe.php, post.php, upload.php, peak.php,
                             rawpost.php, dynprobe.php, per-lane probe_*.php
  bin/narm.py                arm/shape/legit driver (copied from the reference lab)
  bin/measure.py             battery: log/pid/session deltas per case
  bin/make_table.py          results/table.md renderer
  results/lanes.jsonl        46 measured rows (full evidence)
  results/table.md           rendered table (raw; see curation notes)
  results/arm_summary.json   canonical arm rows (all fields)
  results/ini/*.txt          effective INI per lane (fresh + reused-worker dumps)
  results/ini/*_fresh.txt    per-lane freshly compiled probes used for the table
  logs/                      nginx + FPM access/error + master log per lane
  sessions/<lane>/           small cited session records; large ones pinned in
                             inventory.sha256.txt
```

Key raw evidence: `results/arm_summary.json` (fatal lines, statuses, worker
PIDs, session files), `logs/fpm_u*/error.log`, `logs/fpm_u*/access.log`,
`logs/php-fpm-master.log`, `logs/u*.access.log`.

The configs keep the absolute scratch paths (`/tmp/opencode/no_upload_mitigation_1021/`)
that were measured. To re-run from the receipt, copy the block to a scratch dir
and rewrite that prefix in `conf/nginx.conf` and `conf/php-fpm.conf` (sockets,
logs, session dirs, docroot), or keep the original path.

---

## 14. Curation notes and inconsistencies

The source rows were **not altered**; the two labelling defects below are
documented here instead so the measured values stay byte-identical.

* `results/table.md` row `U4_body_130000_413` has a stale tag/note: it measured
  **HTTP 200 at 130,000 B** (the 128k cap is 131,072 B). The row's values are
  correct; only the label says 413. The boundary rows that matter are
  128,328 / 131,072 B -> 200 and 140,000 B -> 413.
* `results/table.md` row `U3_get_no_body` carries the note "legit GET
  unaffected" but measured **415**; that case is a GET *with* a multipart
  `Content-Type` header (the coarse-rule false positive). The plain GET case is
  the next row, `U3_get_no_body_plain` -> 200.
* `U4_body_131072_at_cap`'s captured response body reports
  `max_file_uploads=0`, while `results/ini/U4_fresh.txt` reports 20. This is the
  documented opcache literal-fold staleness (section 11), not a lane config
  difference; the fresh probe is authoritative.
* The source summary said "45 rows"; the JSONL actually contains **46** rows
  (U4 has 8, including the 128,328 B near-cap case). `results/table.md` is
  rendered from that file and contains all 46.

Every file in the scratch source is either copied and hashed in
`inventory.sha256.txt` or pinned there as `OMITTED <sha256> <bytes> <path>`
(pycache, the two 1.07 MB stored uploads, the 118,965/128,352 B U4 session
records, and the remaining zero-byte session files). The inventory also pins
the source `findings.md` hash next to the adapted copy's hash.

---

## 15. Reproduce

```bash
cd /tmp/opencode/no_upload_mitigation_1021     # or the retargeted receipt copy
/home/davide/ailocal/php/zerodays_1020/install_plain/sbin/php-fpm \
    -y conf/php-fpm.conf -c lanes/php.ini -D
/opt/nginx-1.30.1/sbin/nginx -p $PWD -c conf/nginx.conf
env PHP_FCGI_CHILDREN=1 PHP_FCGI_MAX_REQUESTS=1000 \
    /home/davide/ailocal/php/zerodays_1020/install_plain/bin/php-cgi \
    -b 127.0.0.1:29074 -c $PWD/lanes/php.ini -d file_uploads=0 -d memory_limit=8M \
    -d session.save_path=$PWD/sessions/u1cgi \
    -d error_log=$PWD/logs/cgi_u1cgi.error.log &
python3 bin/measure.py baseline u1 u1cgi u2 u3 u3b u4 u5 u6
python3 bin/make_table.py
```

Services used and stopped at the end of the run (PIDs recorded before shutdown):

| service | PID(s) | shutdown |
|---|---|---|
| php-fpm master (this lab) | 1068056 | `SIGQUIT`, reaped |
| php-fpm pool workers | 1068057-1068090, 1068130 (u0 respawn), 1068858 (u6 respawn) | exited with master |
| nginx master + worker | 1068091, 1068092 | `nginx -s quit` (lab prefix), reaped |
| php-cgi (this lab) | 1068094 (parent), 1068096 (child) | `SIGTERM`, reaped |

Shutdown was verified after the final measurement battery: `ps` shows no process
referencing `/tmp/opencode/no_upload_mitigation_1021`, and `ss -ltnp` shows no
listener on any port in 29060-29079 (all lanes are loopback-only).

Unrelated FPM masters on the host (e.g. `realapps` 4052217, pools `lab`/`wp`/`wiki`)
were never signalled; `realapps` (4052217) was confirmed still alive after shutdown.
