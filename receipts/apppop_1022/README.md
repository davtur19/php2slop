# apppop — MediaWiki session-upload-progress object injection: measured verdict

Receipt: `/tmp/opencode/research/apppop_20261022T015427Z`  
Run: 2026-10-22 01:57–02:20 UTC (03:57–04:20 local, UTC+2)  
Lab: MediaWiki 1.46.2, PHP 8.5.10 FPM, nginx `127.0.0.1:28866`  
Status: **primary write primitive disproven; downstream decode + stock POP chains proven**

---

## 1. Verdict

**The `|`-key injection through `PHP_SESSION_UPLOAD_PROGRESS` is not possible on the tested
PHP versions, including the deployed PHP 8.5.10.** The stock `php` session serializer rejects
any session key containing `|` (and usually `!`) in `php_session_encode()`. The caller then
writes a **zero-length string** to the session store. The upload-progress key is
`session.upload_progress.prefix . value`; a value such as
`x|O:9:"TestClass":0:{}` makes the key contain `|`, so the request produces warnings and a
**0-byte session file**, not an injected object.

This is not a missing step or a lab mistake:

* Live HTTP uploads with `PHP_SESSION_UPLOAD_PROGRESS=x|O:9:"TestClass":0:{}` produced 104
  warnings in one slow-abort run and truncated the session file to 0 bytes.
* The deployed lab's upload-progress prefix/cleanup values were varied (empty and stock
  `upload_progress_` prefix; cleanup 0 and 1); the guard runs before either setting matters.
* The same result was reproduced with standalone CLI runs on PHP 5.6.40, 7.0.33, 7.4.33 and
  8.5.10 (0-byte file; benign control key writes 22 bytes).
* Source inspection shows the guard and the empty-write failure path from PHP 5.0.5 through
  8.5.12 (table in §4.3).

**The downstream half is real.** When a session file *does* contain a `|`-delimited object,
MediaWiki's `includes/Setup.php:536 session_start()` decodes it, autoloads the class, and runs
`__wakeup`/`__destruct`. Stock gadget chains available in this MediaWiki installation then work:
Guzzle `FW1` (file write), MediaWiki `FD1` (file delete), Monolog `RCE9`/`RCE8` (`touch`), and
Monolog `FW1` (file write). These were triggered over HTTP with a MediaWiki-issued session id;
the crafted session file was written out-of-band and is explicitly labeled as a simulation of
the missing write primitive.

**Bottom line:** end-to-end default-config
`multipart upload -> | key -> session file -> session_start() -> POP chain`
is **disproven** on this stack. The object-injection sink and gadget availability are
**proven**, but they require a different primitive that can write arbitrary bytes into the
session file without going through `php_session_encode()`.

---

## 2. Scope and rules

* Lab only: MediaWiki 1.46.2 at `/tmp/opencode/research/wikitype_20261021T212610Z`, nginx on
  `127.0.0.1:28866`, PHP-FPM 8.5.10, `FundraisingEmailUnsubscribe` 2.1.0 installed.
* Session store: local files in `/tmp/opencode/research/wikitype_20261021T212610Z/sessions`,
  `session.save_handler=files`, `session.serialize_handler=php`.
* The lab baseline inherited from the `wikitype_20261021T212610Z` receipt has
  `session.upload_progress.cleanup=0` and `session.upload_progress.prefix=""`. Both cleanup
  modes and the stock prefix `upload_progress_` were exercised; the encoder guard is
  independent of all three settings (see §4).
* The WP labs on ports 28891/28893 were **not touched**. No repository commit was made. All
  artifacts are under this receipt.
* A lab-only `TestClass` with `__wakeup`/`__destruct` markers was registered through
  `$wgAutoloadClasses`, used for the decode proof, then removed. `LocalSettings.php` is
  byte-identical to the pre-run copy (`e259dacc…`, see §8).
* The only crafted session files used for the POP proofs were written directly to the
  session directory. They simulate "an attacker can write the session file"; they are **not**
  an in-band upload-progress write.

---

## 3. Lab trigger and session-id mechanics

MediaWiki renames the PHP session and starts it in `includes/Setup.php`:

```
489:  session_name( $wgSessionName ?: $wgCookiePrefix . '_session' );
536:  session_start();
```

`$wgCookiePrefix` is `wikidb`, so the app cookie is `wikidb_session`. The upload-progress
handler runs at PHP request startup, **before** MediaWiki calls `session_name()`; at that
point PHP still uses its default name `PHPSESSID`. Therefore:

* To make the progress handler write into a chosen session file, the multipart request must
  carry `Cookie: PHPSESSID=<SID>` (and, for the app trigger, also `wikidb_session=<SID>`).
* To make MediaWiki decode the same file, the request must carry
  `Cookie: wikidb_session=<SID>`.
* A request with only `PHPSESSID` does not decode the file; a request with only
  `wikidb_session` does not get the progress write. This was measured both ways
  (`phase/RUNJOURNAL.md`; `req/phpsessid_only_hdr.txt`).

MediaWiki also validates/normalizes the session id. Arbitrary ids that were not issued by
MediaWiki were discarded or renewed: a 26-character id produced
`Set-Cookie: wikidb_session=deleted` followed by a new id, and an arbitrary 32-character id
was replaced by a new id. The clean POP re-proofs therefore first obtain a MediaWiki-issued
id via `p=optin`, overwrite that session file, and then trigger with the same cookie. See
`phase/fd1_reproof_clean_20261022.txt` and `req/fd1_reproof_hdr.txt` /
`req/fd1_reproof2_hdr.txt`.

Trigger used throughout:

```
GET /index.php?title=Special:FundraiserSubscribe&p=optin&e=<addr>&v=<variant>
Cookie: wikidb_session=<SID>
```

`p=optin` reaches `Setup.php:536` without authentication. A normal trigger with an existing
session returns HTTP 200 and the `⧼fundraisersubscribe⧽` page.

---

## 4. Write primitive: upload progress cannot insert `|`

### 4.1 Live HTTP measurements

The probe is `upload_probe.py` (multipart body with a `PHP_SESSION_UPLOAD_PROGRESS` field
followed by a file part). The sink `lab_upload_sink.php` made no session calls, so the session
file state after the request is exactly what PHP's progress handler wrote. The lab sink and
class-probe PHP files were removed after the run.

| Run | Settings | Progress value | Observed session file / result |
|---|---|---|---|
| Complete upload, benign key | cleanup=0, prefix `""` | `x` | lab `sessions/sess_test123` (332 B) retains `x\|a:5:{…done:1…}` |
| Slow abort, benign key | cleanup=0 | `x` | `phase/sess_after_abort_control.bin` = 560 B, retains `x\|a:5:{…done:1…}` |
| Slow abort, benign key | cleanup=1 | `x` | in-flight `log/slowabort_cleanup_on.txt` shows 535 B with `x\|a:5:{…done:0…}`; after shutdown `sess_5ptn…` = 223 B, only `fr-unsub\|…` (progress key removed) |
| Complete upload, cleanup=1 | cleanup=1 | `x` | post-run state is `fr-unsub` only; the preserved `sess_5ptn` snapshot was later reused by the abort run (see note) |
| Complete/abort, inject | cleanup=0 and 1 | `x\|O:9:"TestClass":0:{}` | **0-byte file** + `Failed to write session data. Data contains invalid key` warnings (`sess_vd1u…`, `sess_l8cr…`, `sess_vuvq…`) |
| Default prefix, inject | prefix `upload_progress_` | `x\|O:…` | **0-byte file** + warning for key `upload_progress_x\|O:9:"TestClass":0:{}` (`sess_sra6…`) |

Notes:

* The cleanup=1 complete run and the cleanup=1 abort run shared one session id; the preserved
  post-run snapshot (`sess_5ptn…`, 223 B) is from the abort run. The complete run's key removal
  was observed during the run but a dedicated post-complete snapshot was not kept. This does
  not affect the verdict: the `|` payload produces a 0-byte file under **both** cleanup modes.
* With nginx's default FastCGI buffering, progress writes are not visible in the session file
  until the body is handed to FPM. For the slow-abort runs, `fastcgi_request_buffering off`
  was set temporarily to observe `bytes_processed` growing mid-upload
  (`log/slowabort_cleanup_on.txt`). Buffering was restored; `nginx.conf` hash matches the
  baseline (`065dbfde…`, §8).
* The upload-progress key is `prefix . value`. With `prefix=""`, the key is exactly
  `x|O:…`. With the stock prefix it is `upload_progress_x|O:…`. Both contain `|` and both are
  rejected.

Representative warning (8.5.10, first live attempt):

```
PHP Request Startup: Failed to write session data. Data contains invalid key
"x|O:9:"TestClass":0:{}" in Unknown on line 0
```

Warning counts in the lab log:

```
104  "k|O:9:"TestClass":0:{}"
103  "q|O:9:"TestClass":0:{}"
 26  "x|O:9:"TestClass":0:{}"
 25  "y|O:9:"TestClass":0:{}"
 13  "upload_progress_x|O:9:"TestClass":0:{}"
```

The repeated counts are the progress handler writing on every frequency tick during slow
uploads; each write hits the same key guard. Full excerpt: `phase/php_error_excerpts.txt`.

### 4.2 CLI matrix

To exclude an HTTP/FPM-specific artifact, the same key was written with standalone PHP CLIs:

```
php -d session.save_path=<dir> -d session.serialize_handler=php -d session.use_cookies=0 \
    -r 'session_id("<sid>"); session_start(); $_SESSION["<key>"]=1; var_dump(session_write_close());'
```

| PHP | inject `x\|O:9:"TestClass":0:{}` | control `upload_progress_x` |
|---|---|---|
| 5.6.40 | 0 B | 22 B `upload_progress_x\|i:1;` |
| 7.0.33 | 0 B | 22 B |
| 7.4.33 | 0 B | 22 B |
| 8.5.10 | 0 B + invalid-key warning | 22 B |

Raw outputs and files: `phase/ver_cli_20261022/`; summary: `phase/cli_matrix_20261022.txt`.
The earlier raw snapshots `phase/cli_sess/` (8.5.10) and `phase/ver_sess/` (5.6/7.0) show the
same 0-byte result.

### 4.3 Source proof

The guard is in `PS_SERIALIZER_ENCODE_FUNC(php)`. On failure the caller writes an empty
string. Line numbers from the available source trees:

| PHP | guard line (`memchr(key, PS_DELIMITER, …)`) | empty-write line |
|---|---|---|
| 5.0.5 | 470 | 839 |
| 5.1.6 | 471 | 845 |
| 5.2.17 | 816 (also `!`) | 553 |
| 5.3.29 | 922 (also `!`) | 611 |
| 5.4.45 | 889 (also `!`) | 495 |
| 5.6.40 | 990 (also `!`) | 547 |
| 7.0.33 | 1041 (also `!`) | 596 |
| 7.4.33 | 964 | 487 |
| 8.4.26 | 1086 | 543 |
| 8.4.27 | 1112 | 547 |
| 8.5.10 (deployed) | 1075 (warning at 1079) | 553 |
| 8.5.11 | 1075 (warning at 1079) | 553 |
| 8.5.12 | 1101 | 557 |

Exact deployed snippet and the failure branch: `phase/php_encoder_source_proof.txt`.

The deployed `php_session_save_current_state()` branch is:

```c
val = php_session_encode();
if (val) {
    ... s_write(..., val, ...);
} else {
    ret = PS(mod)->s_write(&PS(mod_data), PS(id), ZSTR_EMPTY_ALLOC(), PS(gc_maxlifetime));
}
```

PHP 8.5 adds the explicit warning; older versions fail silently from the caller's perspective
but write the same zero-length data (5.x use `s_write(..., "", 0)`; 7.0+ use
`ZSTR_EMPTY_ALLOC()`).

**Conclusion:** in-band upload progress cannot create a session file with a `|`-containing
key on any tested version. Cleanup=On/Off only changes whether the *benign* progress key is
removed; the invalid-key path has already truncated the file before cleanup matters.

---

## 5. Decode sink: MediaWiki `session_start()` does execute `__wakeup`/`__destruct`

A lab-only class was registered with `$wgAutoloadClasses`:

```php
class TestClass {
    public $p = 'x';
    public function __wakeup() { /* marker */ }
    public function __destruct() { /* marker */ }
}
```

Source: `phase/TestClass.php.txt`.

Out-of-band session file (explicitly a simulation of the missing write primitive):

```
x|O:9:"TestClass":0:{}|a:5:{s:10:"start_time";i:1;…s:4:"done";b:1;…}
```

Trigger with `Cookie: wikidb_session=bgal0l5ubji923v03lcge3f0bpilrva9`:

* HTTP 200 (`req/oob_trigger_hdr.txt`, no new `Set-Cookie`).
* Markers written:
  * `phase/markers/class_file_loaded.txt` — class file was autoloaded;
  * `phase/markers/testclass_wakeup.txt` — `__wakeup` at 01:59:54 UTC, pid 1666499;
  * `phase/markers/testclass_destruct.txt` — `__destruct` at 01:59:55 UTC, same pid.
* Session file after the request:
  `x|O:9:"TestClass":1:{s:1:"p";s:1:"x";}|a:5:{…}fr-unsub|…`
  (`sess_bgal…`, 371 B): the object was decoded, the property was restored, and trailing
  data was tolerated.

Negative controls:

* **No autoloader registration** (TestClass file removed, `$wgAutoloadClasses` entry removed):
  same payload produced no markers and the object remained `O:9:"TestClass":0:{}` in the
  session file (`phase/sess_testclass_after_registration_removed.bin`, 44 B). This shows the
  markers are not a side effect of file access; they require class resolution.
* **Only `PHPSESSID`** (no `wikidb_session`): HTTP 200, new `Set-Cookie: wikidb_session=…`,
  no marker; the crafted file was untouched (`sess_nbu…`; `req/phpsessid_only_hdr.txt`).
  MediaWiki did not call `session_start()` with that id.
* **Normal request**: no marker (class file not loaded unless unserialized).

This proves the sink is real at `includes/Setup.php:536`, and it proves the autoload timing:
the class is resolved during `session_start()`, before MediaWiki's normal page code.

---

## 6. Stock POP chains in this MediaWiki tree

PHPGGC checkout: `phpggc/` (commit `f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c`,
2025-09-29). Payloads were generated with `phpggc` and wrapped as a session variable
(`z|` + payload + `|a:1:{s:4:"done";b:1;}`) or copied from the generated payload into a
MediaWiki-issued session file.

### 6.1 Autoloadable classes

`phase/class_resolution.txt` (probe request at 02:05:46 UTC):

| Class | Resolved file |
|---|---|
| `GuzzleHttp\Cookie\FileCookieJar` | core `vendor/guzzlehttp/guzzle/src/Cookie/FileCookieJar.php` (Guzzle 7.15.2) |
| `GuzzleHttp\Cookie\SetCookie` | core `vendor/guzzlehttp/guzzle/src/Cookie/SetCookie.php` |
| `Monolog\Handler\GroupHandler` | extension `extensions/FundraisingEmailUnsubscribe/vendor/monolog/monolog/src/…` (Monolog 3.12.1) |
| `Monolog\Level` / `Monolog\LogRecord` | same extension vendor |
| `Wikimedia\FileBackend\FSFile\TempFSFile` | core `includes/libs/FileBackend/FSFile/TempFSFile.php` |
| `JakubOnderka\PhpParallelLint\FileWriter` | **not loadable** (not installed) |
| `TestClass` | lab autoloader (removed after the run) |

Autoloaders in order: two Composer loaders, a Closure (MediaWiki), another Composer loader.
The extension's `load_composer_autoloader: true` prepends its vendor autoloader, so Monolog
3.12.1 is what the Monolog chains see, even though core has Monolog 2.11.0. This is why
`Monolog/RCE2` fails (see §6.2) while the Monolog 3 chains work.

### 6.2 Results

| Chain | Vector | Marker / observable | Result |
|---|---|---|---|
| `Guzzle/FW1` | `FileCookieJar::__destruct()` → `save()` | `phase/markers/pop_guzzle_written.txt` (94 B JSON) | **works**; HTTP 200; re-proved 02:18:28 UTC |
| `MediaWiki/FD1` | `TempFSFile::__destruct()` → unlink | victim file existed (38 B, sha256 `271dad…`) then absent | **works**; HTTP 200; clean re-proof 02:15:31 UTC |
| `Monolog/RCE9` | `FingersCrossedHandler` + processors → `touch` | `phase/markers/pop_Monolog_RCE9.txt` (0 B, sha256 `e3b0…`) | **works**; HTTP 200; re-proved 02:18:30 UTC |
| `Monolog/RCE8` | `GroupHandler` + `BufferHandler` + processors → `touch` | `phase/markers/pop_Monolog_RCE8.txt` (0 B) | **works**; HTTP 200 (earlier run 02:04:40 UTC) |
| `Monolog/FW1` | `GroupHandler` → `DeduplicationHandler` → write | `phase/markers/pop_monolog_fw1.txt` (52 B) | **works**; HTTP 200 (earlier run 02:05:54 UTC) |
| `Monolog/RCE2` | `SyslogUdpHandler` + `BufferHandler` | HTTP 500 | **blocked**: `TypeError: Cannot assign null to property Monolog\Handler\AbstractHandler::$level of type Monolog\Level` (Monolog 3 typed property) |
| `MediaWiki/FW1` | `JakubOnderka\PhpParallelLint\FileWriter` | class not loadable | **blocked**: dependency not installed |

Evidence details:

* Guzzle marker content:
  `[{"Expires":1,"Discard":false,"Value":"POPPWNED-apppop guzzle file write\n","HostOnly":false}]`
* FD1 clean proof: `phase/fd1_reproof_clean_20261022.txt`; before 38 B, after absent; HTTP 200;
  session file after trigger 460 B (`phase/sess_fd1_after_clean_trigger.bin`).
* Monolog RCE9 clean proof: `phase/pop_clean_reproof_20261022.txt`; marker 0 B, HTTP 200.
* Monolog FW1 marker content:
  `1792634754:DEBUG:POPPWNED-apppop guzzle file write`
* The RCE2 failure body: `req/monolog_rce2_body.html` and
  `req/monolog_rce2_hdr.txt` (HTTP 500, TypeError).
* Payload binaries: `phase/pop_*.bin`; corresponding injected session snapshots:
  `phase/sess_*_injected.bin`.

### 6.3 Reproducing one chain (lab)

```bash
# 1. obtain a MediaWiki-issued session id
curl -sS -c cj.txt -o /dev/null \
  'http://127.0.0.1:28866/index.php?title=Special:FundraiserSubscribe&p=optin&e=a%40b.c&v=x'
SID=$(awk '$6=="wikidb_session"{print $7}' cj.txt)

# 2. write the crafted session file out-of-band (simulates the missing write primitive)
cp phase/sess_mediawiki_fd1_injected.bin \
   /tmp/opencode/research/wikitype_20261021T212610Z/sessions/sess_$SID
chmod 600 /tmp/opencode/research/wikitype_20261021T212610Z/sessions/sess_$SID

# 3. trigger
curl -sS -b cj.txt -D hdr.txt -o body.html \
  'http://127.0.0.1:28866/index.php?title=Special:FundraiserSubscribe&p=optin&e=a2%40b.c&v=y'
# expect HTTP 200 and the FD1 victim file deleted
```

---

## 7. What would be required for a real end-to-end chain

The following are necessary but **not sufficient** on this stack; the missing piece is a
write primitive that bypasses the encoder:

1. **Arbitrary session-file write.** The server must write attacker-controlled bytes into
   `sess_<SID>` without passing through `php_session_encode()` (e.g., a file-write bug, a
   custom save handler, a shared session directory writable by another component, or a
   different session backend). The upload-progress handler is not such a primitive.
2. **Same id in both phases.** The multipart request needs `PHPSESSID=<SID>` for the progress
   handler, and the app request needs `wikidb_session=<SID>`. The id must be one MediaWiki
   accepts (it renews/deletes unknown ids).
3. **A gadget class autoloadable at `session_start()`.** In this tree: core Guzzle,
   core `TempFSFile`, and extension Monolog 3.12.1. The class must be loadable before
   MediaWiki's normal autoloader setup completes; all three are.
4. **A sink in `__wakeup`/`__destruct`.** The chains above use destructors; `__wakeup` alone
   is enough to instantiate and can be used for property-oriented gadgets.
5. **A serializer that treats `|` as a delimiter.** Only `session.serialize_handler=php`
   has this behavior. `php_serialize` encodes the whole array and `php_binary` uses
   length-prefixed keys; neither interprets `|` as a key/value separator, so the injection
   does not apply there.
6. **Cleanup does not help the attacker.** With `cleanup=1` the benign progress key is
   removed at request end; with `cleanup=0` it persists. In both cases the invalid-key path
   has already written a 0-byte file, so there is nothing to clean up.

---

## 8. Residual lab state

At 2026-10-22T02:20Z:

| Item | State |
|---|---|
| MediaWiki health | HTTP 200 (`/index.php?title=Main_Page`) |
| PHP | 8.5.10 (`X-Powered-By`) |
| FPM master | pid 1696968 (restarted during the run; current) |
| `conf/fpm.conf` | sha256 `201e55f99cff03e7d3e92487e3e56d701b0457ec31a05c6ffd71dff790814536` (matches pre-run baseline) |
| `conf/nginx.conf` | sha256 `065dbfde76073d5a4a1498656639f6048330df42819a36383ea147852192d99d` (matches baseline; buffering restored) |
| `LocalSettings.php` | sha256 `e259daccba568167efd9fae2dc529aac9c89faf1c6d15c50fff7965399f344e4`; byte-identical to pre-run; `TestClass` count 0 |
| `labclasses/`, `lab_upload_sink.php`, `lab_class_probe.php` | absent |
| Session settings | `files`, local `sessions/`, `php`, upload_progress enabled, cleanup=0, prefix `""`, freq=1, min_freq=0 |
| Session snapshots | original run files 03:58–04:07 local remain; 13 representative files copied to `phase/` (map: `phase/lab_session_snapshots.txt`); re-proof session files were removed after copying `sess_fd1_after_clean_trigger.bin` |
| WP labs 28891/28893 | untouched |
| Repository | no commits; no changes to project files |

The baseline is the `wikitype_20261021T212610Z` receipt's configuration, which deliberately
had `cleanup=0`/`prefix=""` for the earlier session tests. The stock prefix
`upload_progress_` and cleanup=1 were each exercised separately; the default-prefix warning
is in `phase/php_error_excerpts.txt`.

---

## 9. Evidence index

All paths are relative to this receipt.

| Path | What it shows |
|---|---|
| `phase/php_encoder_source_proof.txt` | source-level guard + empty-write branch, 5.0.5–8.5.12 |
| `phase/cli_matrix_20261022.txt` | CLI 0-byte vs 22-byte control for 5.6.40/7.0.33/7.4.33/8.5.10 |
| `phase/ver_cli_20261022/` | raw CLI outputs and session files for the matrix |
| `phase/php_error_excerpts.txt` | warning counts, exact invalid-key messages, decode errors |
| `phase/RUNJOURNAL.md` | contemporaneous run notes (baseline, first HTTP attempt, OOB decode) |
| `phase/class_resolution.txt` | class→file mapping and autoloader order |
| `phase/TestClass.php.txt` | lab-only `__wakeup`/`__destruct` class |
| `phase/lab_upload_sink.php.txt` | no-session upload sink used for file-state isolation |
| `phase/lab_class_probe.php.txt` | autoload/class-resolution probe |
| `phase/markers/` | TestClass, Guzzle, Monolog markers |
| `phase/sess_oob_injected.bin` | crafted TestClass session file (decode proof input) |
| `phase/sess_testclass_after_registration_removed.bin` | negative control (no autoloader) |
| `phase/sess_guzzle_fw1_injected_valid.bin` | Guzzle payload as a session file |
| `phase/sess_mediawiki_fd1_injected.bin` | FD1 payload as a session file |
| `phase/sess_Monolog_RCE9_injected.bin` | RCE9 payload as a session file |
| `phase/sess_Monolog_RCE8_injected.bin` | RCE8 payload as a session file |
| `phase/sess_Monolog_FW1_injected.bin` | Monolog FW1 payload as a session file |
| `phase/sess_monolog_rce2_injected.bin` | RCE2 payload (fails on Monolog 3) |
| `phase/sess_fd1_after_clean_trigger.bin` | FD1 session file after the clean trigger |
| `phase/pop_clean_reproof_20261022.txt` | Guzzle/RCE9 clean re-proof log |
| `phase/fd1_reproof_clean_20261022.txt` | FD1 clean re-proof log (victim before/after) |
| `phase/sess_after_abort_control.bin` | cleanup=0 abort control (560 B, done:1) |
| `phase/lab_session_snapshots.txt` | map of 13 lab `sessions/sess_*` originals → `phase/` copies, with bytes and sha256 |
| `phase/sess_inject_*_0b.bin` | four 0-byte injection outcomes (cleanup off, cleanup on, slow abort cleanup on, default prefix) |
| `phase/sess_cleanup_off_complete.bin`, `sess_cleanup_off_abort.bin`, `sess_cleanup_on_after.bin` | preserved cleanup-mode session files (332 B / 560 B / 223 B) |
| `phase/sess_testclass_after_decode.bin`, `sess_testclass_negative_control.bin` | TestClass decode result (371 B) vs no-autoloader control (259 B) |
| `phase/sess_phpsessid_only_untouched.bin` | crafted file untouched when only `PHPSESSID` is sent |
| `phase/sess_fd1_after_trigger.bin`, `sess_guzzle_after_trigger.bin`, `sess_monolog_after_trigger_12b.bin` | post-trigger session files for the FD1 / Guzzle / Monolog runs |
| `phase/sess_before_inject_http.bin` | pre-injection session file (HTTP attempt) |
| `log/slowabort_cleanup_on.txt` | in-flight progress key with cleanup=1; removed after shutdown |
| `log/slowabort_control_cleanup_off.txt` | in-flight progress key with cleanup=0 |
| `log/upload_default_prefix_inject.txt` | HTTP 200 + invalid-key warning for `upload_progress_x|O…` |
| `log/upload_*_inject.txt` | injection-run probe logs (0-byte/no-response artifacts) |
| `req/oob_trigger_hdr.txt` | 200 on TestClass decode trigger |
| `req/phpsessid_only_hdr.txt` | 200 + new `Set-Cookie` when only PHPSESSID is sent |
| `req/monolog_rce2_hdr.txt` / `_body.html` | 500 TypeError for RCE2 |
| `req/fd1_reproof_hdr.txt`, `fd1_reproof2_hdr.txt` | unknown-id rejection evidence |
| `req/*_clean_hdr.txt` | clean Guzzle/RCE9/FD1 trigger headers |
| `upload_probe.py` | multipart probe (complete/slow-abort/slow-finish) |
| `phase/phpggc_checkout.txt` | PHPGGC commit and chain metadata |
| `phpggc/` | PHPGGC checkout, commit `f8aebde…` |
| `SHA256SUMS` | sha256 of every receipt file except `phpggc/.git/` and itself (522 entries; `sha256sum -c` → 522/522 OK) |

---

## 10. Limitations and open questions

* **No in-band bypass found.** The guard is present in every sampled source version from
  5.0.5 through 8.5.12; live HTTP was tested on 8.5.10 and CLI on 5.6.40, 7.0.33, 7.4.33 and
  8.5.10. Earlier/later SAPIs were not executed, but the source path is the same.
* **The OOB file is not an exploit primitive.** It proves the sink and gadget availability
  only. A real end-to-end chain still needs a way to write the session file.
* **Cleanup=1 complete-run snapshot is shared** with the abort run; see §4.1. The `|` payload
  result is unambiguous under both cleanup modes (0-byte file).
* **RCE8 and Monolog FW1 were not re-proved in the final clean pass**; their markers are from
  the earlier 02:04–02:05 UTC run and are preserved in `phase/markers/`. Guzzle, FD1 and
  RCE9 were re-proved cleanly at 02:15–02:18 UTC.
* **Monolog version depends on extension load order.** The lab loads Monolog 3.12.1 from
  `FundraisingEmailUnsubscribe`; a MediaWiki without that extension (or with core Monolog 2
  first) may have a different chain set.
* **Session id validation is MediaWiki-specific.** Arbitrary ids are renewed; the proof used
  a MediaWiki-issued 32-character id. This is an operational constraint, not a security
  control against a local file-write primitive.

---

## 11. One-line answer

**`|` key injection via `PHP_SESSION_UPLOAD_PROGRESS` is blocked by PHP's `php` session
encoder (0-byte session file, guard present 5.0.5–8.5.12); MediaWiki's `session_start()`
does decode a crafted session file and stock Guzzle/MediaWiki/Monolog POP chains do execute,
so the downstream object-injection half is real but requires a separate session-file write
primitive.**

## Repository curation note (this copy)

* **Credential redaction.** `phase/LocalSettings.php.before` and `.after` are sanitized:
  `$wgDBpassword`, `$wgSecretKey` and `$wgUpgradeKey` are replaced with `REDACTED` in both
  files. Their **original** sha256 values (`e259dacc…` before, `3189d2a4…` after, as quoted
  in §8 above) are preserved in `SHA256SUMS.sanitized`; that file is a pointer to the local
  archive, not a manifest for the in-repo copies.
* **PHPGGC checkout excluded.** The source receipt vendored the PHPGGC tree used for payload
  generation (380 files). It is a pinned upstream checkout, not run evidence; the chain
  inventory is kept separately in `pop_inventory_1022/`. Payload/control captures
  (`phase/cj_*`, `class_resolution.txt`) remain here.
* `SHA256SUMS` was regenerated for the curated set (every file except itself), so
  `sha256sum -c SHA256SUMS` passes. The source manifest covers 139 of these files exactly;
  the only intended deltas are this README and the two sanitized `LocalSettings` copies.
