# CVE-2026-109618 / CVE-2026-109619 — upload-progress mechanism on PHP 8.5.12 (CGI lane)

Date: 2026-10-21. Scratch dir: `/tmp/opencode/vulntest8512_2127/` (self-contained; no other dir modified).
Status: **complete** (plain + ASAN 8.5.12 builds, 8.5.10 ASAN control, mitigation lane, stored-record lane, marker-integrity lane).

---

## 1. Builds and verification

Source tarball (unchanged, hash matches the brief):

```
/tmp/opencode/build8512/php-8.5.12.tar.xz  14,554,312 B
sha256 08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209
```

Fresh extraction to `/tmp/opencode/vulntest8512_2127/src/`; two out-of-tree builds in this scratch dir.

Plain build (`build/`):

```
$ src/configure --disable-all --enable-cli --enable-cgi --enable-session --without-pcre-jit \
      CFLAGS="-g -O1"
$ make -j$(nproc) sapi/cgi/php-cgi            # MAKE_RC=0
```

ASAN build (`build_asan/`):

```
$ src/configure --disable-all --enable-cli --enable-cgi --enable-session --without-pcre-jit \
      CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address"
$ make -j$(nproc) sapi/cgi/php-cgi            # MAKE_ASAN_RC=0
```

Verification:

```
$ build/sapi/cgi/php-cgi -v
PHP 8.5.12 (cgi-fcgi) (built: Oct 21 2026 21:28:01) (NTS)
$ build/sapi/cgi/php-cgi -n -m | grep session
session
$ nm build/sapi/cgi/php-cgi | grep php_session_rfc1867_update
000000000040f247 t php_session_rfc1867_update      # plain
000000000098f3bb t php_session_rfc1867_update      # ASAN build

$ build_asan/sapi/cgi/php-cgi -v
PHP 8.5.12 (cgi-fcgi) (built: Oct 21 2026 21:29:38) (NTS)
```

Control (8.5.10 ASAN, pre-existing, untouched):

```
/home/davide/ailocal/php/zerodays_1020/build_asan/sapi/cgi/php-cgi
PHP 8.5.10 (cgi-fcgi) (built: Oct 21 2026 12:05:36) (NTS)
```

Module lists are identical between 8.5.10 and 8.5.12 (`session` present in both).
**Important harness caveat:** `memory_limit` is only enforced when Zend's allocator is on
(`USE_ZEND_ALLOC=1`). With `USE_ZEND_ALLOC=0` (the usual ASAN setting) the 4.98 MB arm
completes with rc 0 and writes a 4,986,076-byte session record. All OOM lanes below therefore
use `USE_ZEND_ALLOC=1`; ASAN is only a secondary lane.

---

## 2. Arm shape (identical to the mod_php control)

`arm.py` builds the exact body used by the control driver
(`/tmp/opencode/research/asanmodphp_20261021T192547Z/arm_driver.py`):

- field `PHPSESSID=<sid>`; field `PHP_SESSION_UPLOAD_PROGRESS=MMM`;
- 20 file parts, filenames `F`×9 then `F`×262144 (max_file_uploads = 20);
- body **4,983,500 B**, sha256
  `7c155121cd01eb7df0c9c2bf91172c012c17c986fbfbbb9053dc0121d9da31e3` (byte-identical to control).
- CGI env: `REQUEST_METHOD=POST`, multipart boundary `NATIVEOUTPUTEXACT`,
  `HTTP_COOKIE: PHPSESSID=labprobe123`, `SCRIPT_FILENAME=work/index.php`,
  `REDIRECT_STATUS=1`, no network, no ports.
- INI: `-n -d memory_limit=8M -d session.upload_progress.enabled=<1|0>
  -d session.upload_progress.cleanup=0 -d session.use_strict_mode=0
  -d session.use_cookies=1 -d session.use_only_cookies=1 -d session.gc_probability=0
  -d display_errors=stdout|stderr -d log_errors=0 -d error_reporting=-1`.
- Producers use `display_errors=1` (fatal in response body, for sha comparison);
  consumers use `display_errors=stderr` (clean `S:n` body).
- Consumer = same PHPSESSID, multipart with `PHP_SESSION_UPLOAD_PROGRESS` + one small file part.
- Scripts: `work/index.php` = `<?php session_start(); echo "S:", count($_SESSION);`
  `work/probe.php` = `<?php session_start(); echo "M:", $_SESSION["marker"] ?? "NONE", "|N:", count($_SESSION);`

Every run is a separate local `php-cgi` spawn; stdout/stderr/request bytes and all session-file
bytes are saved under `runs/<lane>/<step>/` and `sessions/<lane>/`.

Exact fatal (body, HTML) — 8.5.10:

```
<br />
<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in <b>Unknown</b> on line <b>0</b><br />
```

8.5.12:

```
<br />
<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 2097152 bytes) in <b>Unknown</b> on line <b>0</b><br />
```

Both bodies contain no `S:` output: the fatal is still pre-RINIT / pre-script on 8.5.12.
Plain-text form from `log_errors=1` (`errlog_8510/php_err.log`, `errlog_8512/php_err.log`,
2 occurrences each):

```
[21-Oct-2026 19:36:49 UTC] PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in Unknown on line 0
Stack trace:
#0 {main}
```

```
[21-Oct-2026 19:36:49 UTC] PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 2097152 bytes) in Unknown on line 0
Stack trace:
#0 {main}
```

Reproduction note: `session.save_path` must be **absolute**. php-cgi chdirs to the script
directory before RINIT, so a relative save path makes late `session_start()` calls fail with
ENOENT (a harness artifact; all battery lanes use absolute paths).

---

## 3. Producer lanes (×5 each, same session dir, cleanup=0)

| binary | upload_progress | rc | tried | "Unknown on line 0" | body len | body sha256 (prefix) | session file after producer |
|---|---|---|---|---|---|---|---|
| 8.5.10 ASAN | enabled=1 | 255 | 266240 | **yes** | 149 | `561043a1e978c656…` | `sess_labprobe123` 330 B (`991e7c86e47e…`, p3–p5 `e0e360ba134f…`) |
| 8.5.10 ASAN | **enabled=0** | 255 | 266240 | **yes** | 149 | `561043a1e978c656…` | none |
| 8.5.12 plain | enabled=1 | 255 | **2097152** | **yes** | 150 | `49910aca3542b961…` | none |
| 8.5.12 plain | **enabled=0** | 255 | 2097152 | **yes** | 150 | `49910aca3542b961…` | none |
| 8.5.12 ASAN | enabled=1 | 255 | 2097152 | **yes** | 150 | `49910aca3542b961…` | none, **0 ASAN reports** |
| 8.5.12 ASAN | enabled=1, `USE_ZEND_ALLOC=0` | **0** | – | no | 3 (`S:1`) | `de34ad408f98…` | 4,986,076 B record, **0 ASAN reports** |

Determinism: the fatal body is byte-identical across all 5 producers in every lane
(stdout sha256 also identical; e.g. 8.5.10 `59118bebab5b…`, 8.5.12 `c991c92909c8…`).
No signals, no timeouts, no ASAN reports; rc 255 is PHP's normal fatal-exit code.
The 8.5.10 OOM allocation (266240) is the multipart filename copy
(262144+1 rounded to a 266240 chunk); the 8.5.12 fatal fires later, at a 2 MiB allocation,
consistent with the fix's soft-limit/delayed-OOM behaviour. Both are still
`Unknown on line 0`, i.e. request-startup, before RINIT/script execution.

### 3.1 Disabling upload_progress does NOT stop the OOM

Contrary to the expectation in the brief, `session.upload_progress.enabled=0` leaves the
8.5.10 fatal **byte-identical** (`561043a1e978…`, tried 266240, ×5). The OOM is in multipart
filename handling, independent of the session-progress callback; disabling the feature only
removes the session-file/progress-record side effect. Same on 8.5.12 (tried 2097152, ×5).

### 3.2 Session file produced by the 8.5.10 producer (330 B)

```
upload_progress_MMM|a:5:{s:10:"start_time";i:1792611066;s:14:"content_length";i:4983500;
s:15:"bytes_processed";i:5300;s:4:"done";b:0;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";
s:7:"upload0";s:4:"name";s:9:"FFFFFFFFF";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;
s:10:"start_time";i:1792611066;s:15:"bytes_processed";i:5300;}}}
```

This is a **valid partial progress record** (plain serialized PHP, first file only, `done:0`),
not zval/decoder payload. Consumers decode it normally.

---

## 4. Consumer lane — immediate request with the same PHPSESSID (twice)

`index.php`, 3-byte bodies: `S:1` = `de34ad408f98…`, `S:0` = `41208e228a3f…`.

| binary | lane | c1 body | c2 body | c1/c2 identical? | stdout sha12 (c1=c2) | vs no-OOM baseline | divergence |
|---|---|---|---|---|---|---|---|
| 8.5.10 ASAN | enabled=1, 5 producers | `S:1` (3 B) | `S:1` (3 B) | yes | `8ab7ae892d87` | baseline `8ab7ae892d87` | **none** |
| 8.5.10 ASAN | enabled=0, 5 producers | `S:0` (3 B) | `S:0` (3 B) | yes | `a710e0343bfa` | (no-progress baseline) | none |
| 8.5.12 plain | enabled=1, 5 producers | `S:1` (3 B) | `S:1` (3 B) | yes | `091fdde306e1` | baseline `091fdde306e1` | **none** |
| 8.5.12 plain | enabled=0, 5 producers | `S:0` (3 B) | `S:0` (3 B) | yes | `591111982d2e` | – | none |
| 8.5.12 ASAN | enabled=1, 5 producers | `S:1` (3 B) | `S:1` (3 B) | yes | `091fdde306e1` | baseline `091fdde306e1` | **none** |

Session files after each consumer are valid progress records (393–397 B); their sha changes
between consumers only because `start_time`/`tmp_name` change — response bytes do not diverge.

**Control caveat:** in the empty-start 8.5.10 shape the consumer does **not** diverge
(contrary to the prior-receipt expectation). The divergence appears only in the
stored-large-record lane below, and it is caused by the session file being deleted.

### 4.1 Stored-record lane (pre-existing 4.98 MB progress record, 8 M limit)

The record is a legitimate 4,986,076-byte session produced by 8.5.12 itself with
`USE_ZEND_ALLOC=0` (`records/8512asan_nomm_seed.sess`, sha256 `ca3be92f12e7…`), i.e. it
contains 20 `files` entries with 262144-char names.

| binary | producer | fatal / warning | session file after producer | consumer c1/c2 | vs baseline | divergence |
|---|---|---|---|---|---|---|
| 8.5.10 ASAN | rc 255, tried **266240** | fatal + `PHP Request Startup: Failed to decode session object. Session has been destroyed` | **none** (unlinked) | **warnings** (`session_start(): open(...) failed: No such file`, `Failed to read session data`) + `S:0`, stdout sha12 `c8b7bea925e2` | baseline `S:1` / `8ab7ae892d87` | **yes (destruction → warnings, state loss)** |
| 8.5.12 plain | rc 255, tried **2097152** | fatal only, **no decode warning** | original file unlinked; `Set-Cookie: PHPSESSID=<new 32-hex>` + **330 B valid progress record under the new id** | clean `S:1`, stdout sha12 `091fdde306e1` | baseline `091fdde306e1` | **none** |

8.5.10 transcript (295 B body):

```
<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in <b>Unknown</b> on line <b>0</b><br />
<b>Warning</b>:  PHP Request Startup: Failed to decode session object. Session has been destroyed in <b>Unknown</b> on line <b>0</b><br />
```

8.5.12 transcript (282 B stdout incl. headers; 150 B body):

```
X-Powered-By: PHP/8.5.12
Set-Cookie: PHPSESSID=130cec80463f9f8e2b01365f1293f3ed; path=/
Content-type: text/html; charset=UTF-8

<br />
<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 2097152 bytes) in <b>Unknown</b> on line <b>0</b><br />
```

The 330 B record written under the new id was copied into a clean dir and consumed by two
fresh requests: `S:1`, **no warnings**, byte-identical (`de34ad408f98…`), i.e. the post-OOM
record is structurally valid.

---

## 5. Marker-integrity lane (does pre-existing session data survive the OOM?)

Planted `marker|s:4:"GOOD";`, then the 20-part OOM producer, then `probe.php` consumers ×2.

| binary | planted | producer | session after producer | consumer c1/c2 | warnings |
|---|---|---|---|---|---|
| 8.5.10 ASAN | marker only | rc 255, 266240 | 348 B = `marker|s:4:"GOOD";` **+** progress record | `M:GOOD|N:2`, ×2 identical | none |
| 8.5.10 ASAN | marker + 4.98 MB record | rc 255, 266240 | **none** (unlink) | `M:NONE|N:1`, ×2 identical | none to client, but decode-failure warning in producer |
| 8.5.12 plain | marker only | rc 255, 2097152 | **none** (unlink) | `M:NONE|N:1`, ×2 identical | none |
| 8.5.12 plain | marker + 4.98 MB record | rc 255, 2097152 | original unlinked; new-id 330 B record | `M:NONE|N:1`, ×2 identical | **none** |
| 8.5.12 plain | marker + 4.98 MB record, **64 M** | rc 0, no OOM | 4,986,034 B, marker preserved | `M:GOOD|N:2` ×2, no warnings | none |

`strace -f -e trace=openat,unlink,…` confirms the mechanism on 8.5.12:

```
openat(..., "sess_labprobe123", O_RDWR|O_CREAT|O_NOFOLLOW, 0600) = 4
...
unlink(".../sess_labprobe123") = 0        # only in the 8 M OOM run
write(1, "<br />\n<b>Fatal error</b>: ...", 150)
```

8.5.10 does **not** unlink in the marker-only 266240 lane (it does unlink when decoding the
4.98 MB record fails, §4.1), and 8.5.12 does **not** unlink at 64 M.
So on 8.5.12 the OOM path destroys the supplied session (clean removal), it does not leave a
partial/corrupt record. Reading it as a security property: the following request is clean, but
pre-existing session data is lost (availability/integrity side effect, not memory corruption).

---

## 6. ASAN results

- 8.5.12 ASAN + Zend MM ON (`build_asan`, `USE_ZEND_ALLOC=1`): same deterministic
  `tried 2097152` fatal ×5; **zero AddressSanitizer reports** in stdout/stderr.
- 8.5.12 ASAN + Zend MM OFF (`USE_ZEND_ALLOC=0`): the 4.98 MB arm completes ×5 (rc 0, `S:1`),
  writes/re-consumes 4,986,076-byte records; **zero AddressSanitizer reports**.
- 8.5.10 ASAN control: zero reports in all lanes.

Limitation: with Zend MM ON, ASAN does not instrument the Zend heap, so the OOM path itself is
not sanitizer-instrumented; with Zend MM OFF the memory limit is not enforced, so ASAN cannot
reach the OOM path. The plain-build behavioural result therefore stands as the primary evidence,
and no sanitizer evidence of use-after-free/heap corruption was obtained either way.

---

## 7. Verdict

1. **Is the pre-RINIT `Unknown on line 0` OOM signature present on 8.5.12?**
   **YES.** `Allowed memory size of 8388608 bytes exhausted (tried to allocate 2097152 bytes)
   in <b>Unknown</b> on line <b>0</b>`, rc 255, byte-identical ×5, with and without
   upload_progress, plain and ASAN. The script never runs, so it is still a request-startup fatal.
   The allocation that trips it moved from 266240 B (8.5.10 multipart filename copy) to
   2097152 B (8.5.12 soft-limit/delayed-OOM path), and the fatal is emitted at a safe point
   (no `zend_bailout` mid-decode warning, no ASAN report), rather than as the 8.5.10
   longjmp-out-of-the-allocator failure. No `_exit(137)` hard-limit exit was reached in this
   arm shape: every OOM lane exits 255 (the soft/delayed path). No signal/segfault: the CGI
   process exits normally with 255 just as the 8.5.10 control does.

2. **Is there evidence of stale/corrupted machinery state consumed by the following request on 8.5.12?**
   **NO.** After the OOM producer, with the same `PHPSESSID`:
   - consumers return byte-identical bodies/sizes (`S:1`, 3 B, sha `de34ad408f98…`,
     stdout sha `091fdde306e1…`) and are identical to the no-OOM baseline, with no warnings;
   - no partial/zval/decoder blobs are left in session files; remaining files are valid plain
     serialized `upload_progress_MMM|a:5:{…}` records (330/390/393 B);
   - the one state effect is **clean destruction**: 8.5.12 unlinks the supplied session file on
     the OOM path (strace-confirmed) and, in the stored-large-record case, writes a valid record
     under a new PHP-generated id announced by `Set-Cookie`. That is loss of the old session,
     not stale/corrupt state consumed later; no `Failed to decode session object` /
     `Failed to read session data` warnings appear on 8.5.12 (they do on 8.5.10).
   - 8.5.10 control caveat: the empty-start arm shows **no** divergence; divergence
     (warnings + `S:0`) appears only when a 4.98 MB stored record is decoded and the session is
     destroyed.

3. **Does disabling upload_progress stop the arm on 8.5.10?**
   **NO** (expected yes was not confirmed). `session.upload_progress.enabled=0` leaves the
   fatal and body sha **byte-identical** (`561043a1e978…`, tried 266240, ×5); it only removes
   the session progress record. The OOM is in multipart filename parsing, so this INI is not a
   mitigation for the OOM itself (it does remove the session-machinery dimension).

4. **Confidence / limitations.**
   High confidence for the CGI lane: 8.5.10 ASAN control reproduces the exact known fingerprint
   (`561043a1e978…`, tried 266240, ×5) and the 8.5.12 session build is verified
   (`session` module + `php_session_rfc1867_update` symbol). Limitations: (a) CGI only — every
   request is a fresh process, so the FPM “same worker survives and serves the next request”
   angle (global/worker state, `_exit(137)` hard-limit path) is not exercised here; (b) ASAN
   could not cover the OOM path (Zend MM on hides it from ASAN; Zend MM off disables the limit);
   (c) the consumer script only reports `count($_SESSION)` / a `marker`, so silent in-process
   corruption without observable output cannot be excluded; (d) no RCE/exploit attempt was made.
   The 8.5.12 data-destruction behaviour (§5) is an observable availability/state-loss property
   worth a separate FPM-lane follow-up, not evidence of the CVE's corruption primitive.

---

## 8. Artifact paths (all under `/tmp/opencode/vulntest8512_2127/`)

| path | contents |
|---|---|
| `arm.py`, `battery.py`, `work/index.php`, `work/probe.php` | harness |
| `battery_run.log`, `battery_results.json` | all lane results |
| `runs/<lane>/<step>/{stdout.bin,stderr.bin,request.bin,meta.json,sessfile_*.bin}` | raw per-request receipts |
| `sessions/<lane>/` | live session dirs |
| `records/8510asan_encode_seed.sess` | 330 B control record (sha `991e7c86e47e…`) |
| `records/8512asan_nomm_seed.sess` | 4,986,076 B record (sha `ca3be92f12e7…`) |
| `marker/`, `stored/`, `stderr_*/`, `errlog_*/`, `baseline_*/`, `ctest/` | focused lanes |
| `trace_8512/`, `trace_8510/`, `trace_8512_64m/` | strace of session-file open/unlink |
| `build/`, `build_asan/`, `src/` | this task's builds |
