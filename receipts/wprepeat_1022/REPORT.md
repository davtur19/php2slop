# Technical report: two repeats of the plugin-written session realchain with fresh ASLR

## 1. Objective

Repeat the complete chain twice on the private WordPress realchain lab, with a
fresh FPM master (fresh ASLR) for each repeat, and send the final exploit POST
without gdb:

- write a native PHP session file through the free MultiStep Forms for Contact
  Form 7 plugin (no authentication),
- leave a stale `BG(unserialize)` pointer through the real HexCoupon
  `LoyaltyProgramHelpers::start_session()` OOM,
- use the stale pointer to turn the session decoder into a static memory leak of
  1052954 bytes,
- use the same primitive to overwrite `ps_serializers[1].decode` with
  `zif_passthru` and execute a command through `popen`,
- keep the worker alive and preserve the receipt.

Both repeats succeeded. This report records the mechanics and the measured
geometry, including where it differs from the prior reference receipt.

## 2. Target and primitive

Target binary `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`
(md5 `4ee099823b75e16ea36f93c71d57bfd8`, non-PIE, debug symbols). Private pool:
one static worker (`pm.max_children=1`), `session.save_path` in the web-served
`wp-content/uploads/sessions`, PHP `session.serialize_handler=php`,
`session.use_strict_mode=0`, `session.upload_progress.enabled=1`,
`session.upload_progress.cleanup=0`.

Static symbols:

```
ps_serializers[1].decode   0x22c54c8   normal 0x9e6fae (ps_srlzr_decode_php)
zif_passthru               0xa3c074
```

`php_var_unserialize_init()` reuses `BG(unserialize).data` when
`BG(unserialize).level != 0`. The plant leaves exactly that state with `data=P`,
where P is a freed allocation that is later reused by the 1 MB session read
buffer of the next request. The record therefore controls the fake
`php_unserialize_data` structure at the absolute address P.

## 3. Plugin write

`plugin_submit_many` equivalent `scripts_plugin_submit.py <sid> 1000 20 <out>`
posts 1000 checkbox groups x 20 values (20000 values, 380270-byte body) to the
unauthenticated `/plugin-step1/` form (CF7 form 26). The mu plugin
`cf7msm-force-session.php` forces the free plugin's native PHP session path.
Every run observed:

```
HTTP 302 Location /plugin-step2/
request body 380270 bytes
session file 388350 bytes (greater than the 266240-byte plant threshold)
```

The plant endpoint `/wp-content/uploads/plant/hexplant.php` includes the real
plugin trait and `LoyaltyProgramHelpers.php`, creates the class without its
constructor, lowers `memory_limit` to `2M`, and calls the real `start_session()`.
It returns HTTP 500 with an empty body, deletes the session file, keeps
`basic_globals.unserialize={data=P, level=1}`, and leaves the static decoder at
`0x9e6fae`. The worker survives the plant.

## 4. Leak mechanics

The leak record is built by `scripts_mkprobe_big.py`:

- `S|s:32:"SSSS...";J|i:4096;K|s:L:"<filler>"` with total 1048576,
- a copy of the fake `php_unserialize_data` at every page boundary of the file,
  with absolute pointers to P,
- fake `last_dtor` at `P+0x80`, `used_slots=used`, `next=0`, data at `P+0x90`,
  fake entries at `P+0x38`, `first_dtor=0`, `max_depth=0x7fffffff`.

During decode, `tmp_var()` returns `&last_dtor->data[used]` and writes one
`ZVAL_UNDEF` there. The first session value (`S`) is parsed into that slot.
The subsequent value `J|i:4096` uses the next slot and overwrites the low
zend_string length word with 4096; `K` uses the following slot. Because the
slot for S is chosen by `used = (S-(P+0x90))/16`, the S zval itself lands on the
zend_string chunk, and the J zval at `S+0x10` corrupts `len=4096`. At session
encode the S value is serialized as `s:4096:"` and dumps 4096 bytes from
`S+0x18`. At offset 8 of the dump sits the K/session-buffer pointer.

Measured slots:

```
run1: P=0x7fa8a96e6000  S=0x7fa8a9656080  used=-0x9001  K=0x7fa8a9001000
run2: P=0x7f791b0f1000  S=0x7f791b056080  used=-0x9b01  K=0x7f791aa01000
```

Both leak files are 1052954 bytes, start with `S|s:4096:"`, and carry the second
decode buffer address at dump+8 (file offset 0x12). The second decode length is
1052954 in both runs. The trigger worker crashes with SIGSEGV after the second
decode; the master respawns it.

The first run-1 attempt used the reference constant `used=-36865` with
`P=0x7fa8a96f1000` (initial-worker layout). The correct slot for that P was
`-0x9b01`; the J zval therefore landed 0xb000 above S and the resulting session
was a normal 1048888-byte `S|s:32` record (`run1/leak.http`). This is why the
`used` value must be derived from the measured S, not copied.

## 5. Final record mechanics

The final record (512 KB) is:

- first var: a 0x60-byte key that doubles as a fake `zend_execute_data`
  (arg zval at `+0x50` = {value.ptr=F, type=6}, `+0x18`/`+0x2c` set), value
  `i:10731636` (`0xa3c074`),
- second var: a long `B` key and an `s:512` value whose bytes at `+0x10`/`+0x18`
  form the fake zend_string at F (`len(cmd)`, command),
- `K` filler with the fake `php_unserialize_data` at an absolute P offset.

First decode: the temp slot for the first value is computed as
`used_target_static=(0x22c54c8-(P+0x88+0x10))/16`, so the parsed integer
`0xa3c074` is written into `ps_serializers[1].decode`. The fake `first_dtor` at
`P+0x88` has a negative used count, so `var_destroy` does nothing.

Second decode: `php_session_decode()` calls `PS(serializer)->decode(val,len)`,
now `zif_passthru`, with the session buffer as a fake `zend_execute_data`.
`Z_PARAM_STR` reads the arg zval at `+0x50`, which points to the fake zend_string
at F; `Z_PARAM_STR` gets `cmd` at `F+0x18`, and `popen(cmd,"r")` runs.

Measured calibration (gdb) in both runs:

```
DECODE n=1 data=X            len=524288                      decodefield=0x9e6fae
DECODE n=2 data=K_dest       len=524600                      decodefield=0xa3c074
ZIF_PASSTHRU rdi=K_dest+0x18 rsi=524600
POPEN cmd=touch .../MARK_TEST;
REQUEST_SHUTDOWN static=0xa3c074
```

The final POST (no gdb) produced HTTP 500 with an empty body, created `MARK_REAL`
size 0, kept the same worker PID, and left
`ps_serializers[1].decode=0xa3c074` and
`basic_globals.unserialize={data=0x0, level=0}`.

## 6. Geometry differences from the prior reference receipt

The prior receipt measured `K_dest=X+0x81000` for the 512 KB final record. In
this stack the second decode buffer is `K_dest=X+0x88000` in both runs. The
builder `scripts_mkfinal_large.py` hardcodes `X=K_dest-total-0x1000`, which
makes the file offset of the fake struct wrong when the heap relation differs;
that produced a decode-1 SIGSEGV at `0xa947b6` in calibration cal2. The corrected
builder `scripts_mkfinal2.py` takes X explicitly and K_dest independently; with
it the calibration and the final worked on the first try in run 2.

Worker-type rule observed in both runs:

- initial worker (started with the master): `P-X = 0x87000`;
- respawned worker (after a crash): `P-X = 0x7c000`.

X itself was stable across worker types (`0x...66a000` in run 1,
`0x...06a000` in run 2 after ASLR), and S tracked X (`X-S=0x13f80`). Only P
moved by 0xb000 between the two worker types.

For the 1 MB leak record the K string is an mmap at `X-0x669000`
(`0x7fa8a9001000` and `0x7f791aa01000`), which is also the address of the second
decode buffer.

## 7. Evidence

Run 1:

```
run1/plug_submit_*.html          plugin write responses
run1/plugin_submit*.txt          submit output (302, 388350)
run1/plant*.hdr/.body            plant HTTP 500, empty
run1/state_*.gdb                 P and static decode measurements
run1/probe1.gdb                  temp-slot probe (S, J, K slots)
run1/leak1.gdb, leak1.resp       rejected first leak (S|s:32, 1048888)
run1/leak1c.gdb, leak1c.resp     successful leak decode log
run1/leak1c.sess, leak1c.http    leak file and HTTP twin (1052954)
run1/leak1c_after.http           post-final static fetch (identical)
run1/cal*.gdb/.resp/.geo         calibrations; cal3 created MARK_TEST
run1/fin1.geo, fin1.resp         final geometry and no-gdb response
run1/fin1.start/.end             UTC timestamps
run1/final1.rec                  exact final record (rebuilt)
run1/MARK_REAL, run1/MARK_TEST   marker files (size 0)
run1/state_after_fin1.gdb        static poison and cleared unserialize
```

Run 2 mirrors the same layout under `run2/` with `leak2.sess`, `leak2.http`,
`leak2_after.http`, `cal2a.*`, `fin2.*`, `final2.rec`, `MARK_REAL`,
`MARK_TEST`, and `state_after_fin2.gdb`.

Hashes:

```
run1 leak 1052954  SHA1 b447af3fa39ccfa019b7617745ae7fc7202bae30
                   SHA256 627c64fa3a41bda2ac390bb4fa162b549ac049ef2831f8810c5f8dbb7bae88d4
run2 leak 1052954  SHA1 62a41f815418ceb9ef56cfe416f1290701231bc2
                   SHA256 cbf771de97416af5758321735f33b3272d66dc79ac424ccc13b4d65b3ffd5591
```

Final markers:

```
run1/MARK_REAL 2026-10-22 02:59:50.215650741 +0200  size 0
run1/MARK_TEST 2026-10-22 02:59:15.459976617 +0200  size 0
run2/MARK_REAL 2026-10-22 03:01:00.122997903 +0200  size 0
run2/MARK_TEST 2026-10-22 03:00:45.075138150 +0200  size 0
```

## 8. Survival and reset

- Run 1 final worker: 957712, alive before and after the final POST; still the
  pool worker at verification. Static decode `0xa3c074`.
- Run 2 final worker: 959141, alive before and after the final POST; static
  decode `0xa3c074`.
- The poisoned workers are not reset: a later session request would call
  `zif_passthru` with normal arguments. Health checks used static file fetches
  only (`sess_lk1c`, `sess_lk2`), both HTTP 200 and identical after the final.
- Run 2 required a master restart between runs:
  master 591059 was stopped, master 958304 started at 03:00:07 with a new ASLR
  layout. During each run the calibration worker was killed after the
  calibration to clear the static poison; the master respawned a fresh worker.
  These are lab reset actions, not part of the exploit.
- No shared service was touched: 28891 and 28870/28871 were never addressed and
  PIDs 4052217/4052937/4053032/4054145 were never signalled.

## 9. Limits

- The plant requires a writable session directory served by the web server and
  an attacker-controlled `PHPSESSID`.
- The plugin session file is deleted by the OOM plant; it must be regenerated for
  every attempt.
- The final record hardcodes X (hence K_dest and F) and P. The geometry is
  stable for a fixed request sequence but shifts by 0xb000 in P between the
  initial worker and respawned workers, so P must be re-measured after every
  plant. X and the 512 KB K relation were stable across both runs and both worker
  types; the 1 MB leak is robust to X because the fake struct is placed at every
  page boundary, but its `used` value still depends on S.
