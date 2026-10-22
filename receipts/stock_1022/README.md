# Receipt: stock OpenMage session write in a served directory + native PHP 8.5.10 decode → `zif_passthru`

Receipt root: `/tmp/opencode/research/stock_20261022T013022Z`
Date: 2026-10-22 (UTC), local `+0200`.
Status: both objectives reproduced. Nothing below is simulated.
Full detail: [`REPORT.md`](REPORT.md). Integrity: [`SHA256SUMS`](SHA256SUMS).

## Result

**A. Stock app condition (qualifying).** Unmodified OpenMage 20.10.0, with stock
PHP settings (no `session.*` / `upload_progress.*` overrides), writes the raw
POST of a failed, **unauthenticated** registration into `$_SESSION` and stores
it in `www/var/session/` — a directory below the nginx document root:

```
GET /var/session/sess_7738e1bcf77727f74bc0a5a58680a888
200 OK, Content-Length 1777
sha256 7ba9f06c1919f034b0deb77300d995fad61477c4e3164f89da67eb5ee415afc2
```

On-disk file, HTTP body, and the captured copy
(`phase/stock/sess_stock_marker*`) are byte-identical; the marker
`STOCKMARK1792632782` is in `customer_form_data.firstname`.

**B. Native decode chain (ASLR on, no gdb on the trigger).** On the same PHP
8.5.10 `php-fpm` binary, the worker's
`ps_serializers[1].decode` (`0x22c54c8`) was overwritten with `zif_passthru`
(`0xa3c074`); the command `touch .../MARK_CHAIN;` executed. Marker exists
(mtime `2026-10-22 03:57:05.467 +0200`), response was `200`, and the same
worker (`PID 1682840`) was still serving afterward. Post-run static read:
`ser1_decode=0xa3c074`, `ser2_decode=(nil)`, `BG level=0`.

## Verify

```bash
cd /tmp/opencode/research/stock_20261022T013022Z

sha256sum -c SHA256SUMS                 # every curated evidence file
stat -c '%n %s %y' MARK_CHAIN           # 0 2026-10-22 03:57:05.467 +0200
grep -E 'ser1_decode|WORKER' phase/post_final.txt
sha256sum www/var/session/sess_7738e1bcf77727f74bc0a5a58680a888 \
          phase/stock/sess_stock_marker.http_body    # both 7ba9f06c...
grep 1682840 log/fpm-access.log         # 03:56:59 POST 200, 03:57:05 POST 200
```

The final trigger client output is `req/finB_final.drive`:
`status 200 len 5 body b'NOOP\n'`.

## Layout

| path | content |
|---|---|
| `REPORT.md` | full report: stock citations, static facts, geometry, dry run, final run, caveats |
| `SHA256SUMS` | hashes of the curated receipt (this file, report, conf, phase, req, cycles, logs, markers) |
| `conf/fpm.conf.pre_chain` | **stock** pool config used for Part A — no session overrides |
| `conf/fpm.conf` | live chain config; the only deltas vs stock are listed in `REPORT.md` §3.3 |
| `conf/nginx.conf` | docroot `www/`, plain `location /`, port `28895` |
| `phase/stock/` | stock session file, HTTP body + headers, create/regpost captures |
| `phase/mkfinal_b.py` | delimiter-safe final record builder (frame in a string value) |
| `phase/finB_final.rec`, `.geo` | official 1 MiB record, sha256 `065315c2...`, and geometry |
| `phase/finB_dry.*`, `gdb_fin_dry.gdb` | instrumented dry run (decode, frame, `ZIF_PASSTHRU`) |
| `phase/post_final.txt` | post-trigger static slot and worker PID |
| `phase/state_plantP.txt` | pre-trigger stale `php_unserialize_data` (`P=0x7f747ce8b000`) |
| `req/finB_final.drive` | final trigger HTTP result |
| `log/` | nginx/FPM access, error and PHP logs with the timing/PID trail |
| `cycles/` | dry-run and final record + log + geo copies |
| `MARK_CHAIN`, `MARK_DRY` | exploit/dry-run markers (empty files) |
| `www/` | installed OpenMage tree (vendor code not hashed; see scope) |

## Stock vs lab (read this before quoting Part B)

* Part A is genuine stock application behaviour: native `session_start()`,
  controller write of unauthenticated POST data, session directory chosen by
  the app (`Mage_Core_Model_Config_Options` → `var/session`), nginx serves it.
  `var/.htaccess` exists in the release but nginx ignores it.
* Part B shares the app's session directory and the native decoder, but its
  1 MiB input is a lab-crafted session record (`phase/finB_final.rec`), not a
  payload the stock controller produces. It proves the PHP primitive
  (`ps_serializers[1].decode` → `zif_passthru`) reached through the app's
  session file, not an end-to-end app exploit.
* The trigger must use the multipart upload-progress `session_start()` because
  it runs **before** `PHP_RINIT(basic)`, which would otherwise memset the stale
  `BG(unserialize)` state planted by the OOM request.
* Lab deltas on the live pool are exactly the seven `php_value[...]` lines in
  `conf/fpm.conf` shown by `diff -u conf/fpm.conf.pre_chain conf/fpm.conf`
  (`session.serialize_handler`, `use_strict_mode`, four `upload_progress.*`,
  and `session.save_path` pointing at the same `www/var/session`).
* ASLR is on (`randomize_va_space=2`, personality `0`). Workers of one master
  share a layout; the record is built for the measured master layout
  (`P=0x7f747ce8b000`, `X2=0x7f747c801000`, `F=0x7f747c801418`). The fake
  `php_unserialize_data` is replicated at all 255 page-aligned offsets, so the
  first decode buffer address `X1` is not needed at build time.
* Worker recycling was a lab reset only (SIGKILL of the poisoned worker); the
  master stayed up and the final worker survived the exploit. After a successful
  run `GET /` returns `503` because the poisoned serializer persists per worker;
  liveness is checked by worker PID and static-file fetch, not by `/`.
* Ports `28891`/`28893` and PIDs `4052217`/`4052937`/`4053032`/`4054145` were
  never contacted or signalled.

## Hash scope

`SHA256SUMS` covers the curated receipt only: this README, `REPORT.md`,
`conf/`, `phase/`, `req/`, `cycles/`, `log/`, `run/cj.txt`, `run/marker.txt`,
the two markers, and the two session files under `www/var/session/`
(`sess_7738e1...` stock evidence, `sess_chainQ` post-trigger file). The rest of
`www/` (vendored app code), `db/`, `run/nginxprefix/`, and `openmage.zip` are
environment, not evidence, and are intentionally not hashed. No git commit was
made.

## Repository curation note (this copy)

The public copy keeps `conf/`, `phase/`, `req/`, `cycles/`, `log/`, `run/cj.txt`,
`run/marker.txt`, the two markers and the two session files under `www/var/session/` that
the report cites. The **193 MB** `www/` tree (vendored OpenMage code), the **199 MB** `db/`
dump, `openmage.zip` (**41 MB**) and `run/nginxprefix/` are environment and are omitted, as
is the live MariaDB log discussed below.

Six manifest entries are not copied:

| path | why |
|---|---|
| `cycles/finB_dry.rec`, `cycles/finB_final.rec` | **byte-identical duplicates** of `phase/finB_dry.rec` and `phase/finB_final.rec`, both retained (sha256 `0d30fedc…`, `065315c2…`) |
| `phase/cal1.rec`, `phase/cal2.rec`, `phase/cal3.rec` | 1 MiB calibration records, kept in the local archive; the calibration results they produced are in `cycles/` and `log/` |
| `log/mariadb.err` | **live-log drift**: the manifest hash `0541a4f3…` was taken before MariaDB appended to the file; the current archive copy is `729dec91…`. It is an environment log, not run evidence, and is deliberately not committed rather than silently re-hashed |

Every other manifest entry (94 files) verifies against the source hashes. The only delta is
this README. `SHA256SUMS` was regenerated for this curated set and covers every file here
except itself, so `sha256sum -c SHA256SUMS` passes.
