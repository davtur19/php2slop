# receipt — mitigation_matrix_1021 (config mitigations M1–M4 + nginx edge, PHP 8.5.10)

Curated 2026-10-21 from four private loopback runs (volatile scratch dirs; every copied
file is hashed in `inventory.sha256.txt`, large sources deliberately not copied are
pinned as `OMITTED`):

| block | dir | scratch source | ports |
|---|---|---|---|
| M1–M3 INI lanes on FPM + mod_php | this dir (`findings.md`, `configs/`, `results/`, `logs/`) | `/tmp/opencode/mitigation_1021/` | 28980–28995 |
| nginx edge lanes N0–N4 | `nginx_edge/` | `/tmp/opencode/nginx_mitigation_1021/` | 29000–29011 |
| M4 callback pin lanes l0–l6 | `m4_unserialize_callback/` | `/tmp/opencode/m4_test_1021/` | 29030–29036 |
| PHP 8.5.12 patch reports (source runs) | `patch_8512/` | `/tmp/opencode/vulntest8512_2127/`, `/tmp/opencode/fpmtest8512_2140/` | CGI + 28961–28968 |

The M1–M3 block replays the known multipart / upload-progress OOM arm against real
running PHP 8.5.10 stacks and changes only admin-scope INI knobs:

- **M1** `session.upload_progress.enabled=0`
- **M2** `memory_limit` headroom (measured; see the two boundary rules)
- **M3** `display_errors=0` + `fatal_error_backtraces=0`

The unified decision document is `docs/mitigation_matrix_1021.md`; each block has its own
detailed `findings.md` and this README is the map.

## M1–M3 stacks / lanes

| lane | listener (front) | stack | key settings | purpose |
|---|---|---|---|---|
| A | 28990 (FPM 28980) | FPM 8.5.10 ASAN | 8M, up=1, disp=1, bt=1 | unmitigated control |
| B | 28991 (FPM 28981) | FPM 8.5.10 | 128M, post 8M, up=0, disp=0, bt=0 | M1+M2+M3 |
| C | 28992 (FPM 28983) | FPM 8.5.10 | 8M, up=0, disp=1, bt=1 | M1 only |
| B2 | 28993 (FPM 28984) | FPM 8.5.10 | 12M, post 16M, up=1 | M2 too small |
| B3 | 28994 (FPM 28985) | FPM 8.5.10 | 128M, post 16M, up=1 | M2 enough |
| B4 | 28995 (FPM 28987) | FPM 8.5.10 | `memory_limit=-1`, post 8M, up=0 | stopgap probe |
| D | 28982 direct | httpd 2.4.66 + mod_php 8.5.10 | 128M, up=0, disp=0, bt=0 | mitigated mod_php |
| D0 | 28986 direct | httpd 2.4.66 + mod_php 8.5.10 | 8M, up=1, disp=1, bt=1 | mod_php control |

FPM lanes were driven through a private nginx 1.30.1 front-end
(`configs/nginx/nginx.conf`) because a hand-written FastCGI client was rejected by PHP's
param parser. `pm=static, max_children=1, max_requests=0` and `%p` in the access log make
worker identity unambiguous; mod_php logs `%P`.

## M1–M3 headline numbers

- **A**: baseline consumer on the planted 4,986,076 B record → 322 B fatal (`tried 266240`);
  producer arm → worker **1051783 exit 70**, empty HTTP response, fatal only in php_err.log;
  the planted record is replaced by a 330 B progress record; post-attack consumer `S:1`.
- **B**: 5/5 arms + 2 consumers + marker test + 19,925,707 B oversize on **one worker
  (1051025, 14 requests)**, zero exits; stored record sha unchanged
  `ca3be92f12e7b58edb097a4fc4002cfadb34c97baa6e1d7db312eeafd275b543`; marker state
  `S:1|M:'GOOD'|K:marker` unchanged.
- **C**: 3/3 arms → 3 worker exits (1051058/1051059/1051060) with `tried 266240`, no session
  files. M1 alone does not stop the OOM.
- **B2 vs B3**: same 14,944,972 B body, post_max 16M; 12M limit → exit 70 (`tried 790528`);
  128M limit → 200 `S:1`, record 14,947,510 B. M2 must be sized.
- **D**: 3/3 arms, same prefork child 1052092, `S:1`, record untouched, no php_err.log.
- **D0**: arm → 149 B fatal body sha `561043a1e978c656…`, child 1052102 survives, record
  replaced by a 330 B progress record.
- **php-cgi boundary** (byte-exact bisection, upload_progress=0): for parsed bodies
  1.2–14.9 MB, min memory_limit is 2.52–3.36× body; at 8M `post_max_size` recommend
  **≥28 MiB**, rule `memory_limit ≥ 3 × post_max_size + 4 MiB`; 128M is ~4.5× margin.

## M4 — callback pin lanes (`m4_unserialize_callback/`)

Question: does `php_admin_value[unserialize_callback_func] =` (empty) stop an attacker from
making PHP autoload a class during `unserialize()` / session decode, and where does it stop?
One private FPM master, 7 pools (`l0`–`l6`), one worker each, direct FastCGI, `-n` only.

| lane | docroot / pin | script `unserialize()` marker | pre-script marker | predefined-class gadget marker |
|---|---|---|---|---|
| l0 | defaults, no `.user.ini` | no | upload-progress: no | **yes** |
| l1 | `.user.ini` callback `spl_autoload`, no pin | **yes** | upload-progress: **yes** | **yes** |
| l2 | pool pin `""` | no | upload-progress: no | **yes** |
| l3 | pin `""` + `include_path="."` | no | upload-progress: no | **yes** |
| l4 | `.user.ini` + `session.auto_start=1`, no pin | **yes** | auto_start: **yes** | n/a |
| l5 | pin `""` + `session.auto_start=1` | no | auto_start: no | n/a |

Measured pin semantics: `ini_get() === ''`, `access=4` (PHP_INI_SYSTEM), `ini_set(...) ===
false`; unpinned lanes report `access=7` and accept both `.user.ini` and `ini_set()`. The
default is already `''`; the control is the **admin lock**, not the empty value. M4 does
**not** block gadgets whose class the application has already defined (marker yes in
l2/l3), and does **not** touch the multipart OOM: the 4,983,495 B stock arm on pinned
`l6`/8M still fatals (`tried 1052672`, worker 1066102 exit 70 → replacement 1066166).
l3's extra `include_path` pin is defense in depth for the autoloader+search-path lever,
not required when the callback is empty.

## nginx edge — N0–N4 (`nginx_edge/`)

| lane | config | 4,983,500 B arm | filename-dense body under the cap | verdict |
|---|---|---|---|---|
| N0 | cap 8m, PHP 8M | 200 + empty, fatal 266240 | 1.84 MB → fatal | baseline broken |
| N1 | `client_max_body_size 2m`, PHP 128M | **413, PHP never reached** | 1.96 MB → 200 + output | **works** |
| N2 | cap 2m, PHP 8M | 413 | 1.84 / 2.09 MB → fatal | blocks only >2 MiB |
| N3 | reference token-rule shim (not nginx) | 403 on the literal | bypass: no-token, renamed field, 8 KiB window | **not a mitigation** |
| N4 | cap 2m + `limit_req`/`limit_conn` | 413 | same as N2 under the cap | cost lever only |

Measured edge rule: `memory_limit ≥ 6.5 × client_max_body_size + 1 MiB` (recommend 8×;
a 2 MiB cap → 16 MiB recommended, 12 MiB measured minimum; an 8 MiB cap → 64 MiB,
extrapolated). With 8M memory the cap must be ≤1m. A pre-RINIT fatal is HTTP 200 + empty
body, so status codes are not a detection signal.

## PHP 8.5.12 patch reports (`patch_8512/`)

`cgi_8512_findings.md` and `fpm_8512_findings.md` are the measured 8.5.12 runs copied from
their scratch dirs (the binaries were built there, not rebuilt for this receipt). Both
show the pre-RINIT OOM fatal **still exists** at 8M, but the 8.5.10 corruption/stale-state
consumption signal does not: the fatal is emitted at a safe point, FPM workers exit 70 as
before, every consumer after a producer runs on a fresh worker with baseline bytes, and no
CVE-surviving signal was observed. The patch is the only complete fix of the CVE; it is
not a fix for the availability OOM at an undersized `memory_limit`.

## What the mitigations do NOT do

- **M1** removes the 109619 progress-record writer and the RFC1867 startup update path but
  **not** the RFC1867 multipart filename allocation that OOMs (lane C). It also does not
  remove records already on disk: a planted 4.98 MB record still fatals a consumer where it
  exists (lane A).
- **M2** is headroom, not a fix — a parsed body above the limit still kills the worker (B2).
  `memory_limit=-1` (B4) removes the crash by removing the bound, not the bug.
- **M3** hides output only; FPM startup OOM already produces no body, and on mod_php it
  hides the 149 B fatal while the OOM and record replacement remain.
- **M4** only blocks the attacker autoload/callback lever; it leaves already-defined class
  gadgets and the multipart OOM untouched.
- **Edge** prevents reaching PHP when the cap is correctly sized against `memory_limit`
  (N1) or raises cost (N4); cap-without-headroom (N2) and token rules (N3) do not work.
- Direct FastCGI exposure without nginx normalization, concurrency and non-ASAN/other SAPI
  shapes are unverified — see the per-block `findings.md` gaps sections.

## Artifact map

- `findings.md` — M1–M3 report (matrix, per-lane evidence, effective INI, boundary rule,
  non-coverage, gaps, final PIDs).
- `configs/fpm/*.conf`, `configs/modphp/*.conf`, `configs/nginx/nginx.conf` — exact configs.
- `htdocs/` — `index.php`, `probe.php` (effective-INI/access proof), `probe_session.php`,
  `plant.php`.
- `scripts/` — drivers: `run_lanes.py` (lanes A/B/C/B2/B3/B4/D/D0), `http_arm.py`,
  `cgi_boundary.py` (bisection), `cgi_arm.py` (CGI fingerprint), `make_configs.py`,
  `make_summary.py`.
- `results/<lane>/results.jsonl` — one row per request: HTTP status, response length/sha256,
  OOM limit/tried, fatal/warning lines, request body length/sha256.
- `results/<lane>/effective_ini.txt` — raw `probe.php` transcript (values + `access=` +
  `ini_set(...)=false` + `PHP_VERSION`/SAPI).
- `results/<lane>/worker_receipt.json` — access-log pids, FPM exit lines, final records.
- `results/<lane>/session_state_*.json` — planted/after record size and sha256.
- `results/results_table.md`, `results/boundary_table.md`, `results/matrix_summary.json` —
  rendered + machine-readable consolidation.
- `results/cgi/*.json`, `results/cgi/cgi_fingerprint/*_meta.json` — bisection + CGI data.
- `logs/<lane>/` — access log (pid-prefixed / `%P`), fpm/err log, php_err.log, stdout.
- `logs/nginx/` — front-end access/error log.
- `nginx_edge/` — curated nginx edge run (N0 control, N1 cap+headroom, N2 cap only,
  N3 token rule, N4 rate/conn): `conf/` (nginx + FPM + php.ini), `docroot/` (incl. the
  `.user.ini` rename bypass), `bin/` (arm, battery, headroom, shim, capture, table drivers),
  `results/` (`table.md`, `lanes.jsonl`, `headroom*.json`, 413/429/403/200 transcripts),
  selected `logs/` and small session records, and the run's own `findings.md`. The
  5.4 MB FPM master log and the 1.8–4.98 MB session records are not copied; path+sha256
  pins are in `inventory.sha256.txt` (`OMITTED` lines).
- `m4_unserialize_callback/` — `conf/fpm.conf` (7 pools), `www/{base,plain,auto}/` (probe,
  `d.php`, `dpre.php`, `index.php`, `.user.ini`), `autoload_plain|auto/d2.php`,
  `bin/{fcgi.py,run_m4.py,make_summary.py,run_oom_arm.py}`, `results/m4_results.jsonl`
  (22 rows), `m4_summary.md`, `effective_ini.txt`, `binary_env.txt`, `m4_oom_arm.json`,
  raw `transcripts/`, `logs/`, and `findings.md`. `sessions/sess_m4oom6` (1,049,838 B) is
  not copied; its sha256 is pinned in the inventory.
- `patch_8512/` — the two measured 8.5.12 reports (CGI and FPM same-worker lanes).

Not copied: the multi-MB request/response bodies under the M1–M3 scratch `steps/`
(~5–20 MB each); their sizes and sha256 are in `results.jsonl`, and the HTTP-level facts
are reproducible with the scripts + configs. The 4,986,076 B seed record lives at
`/tmp/opencode/vulntest8512_2127/records/8512asan_nomm_seed.sess` (sha
`ca3be92f…`, same value as the planted records in lanes A/B/D).

## Provenance / reproduction

```
# M1–M3
cd /tmp/opencode/mitigation_1021
python3 scripts/make_configs.py
/opt/nginx-1.30.1/sbin/nginx -p $PWD/nginx -c $PWD/nginx/nginx.conf
python3 scripts/run_lanes.py all          # starts/stops each FPM/httpd lane
python3 scripts/cgi_boundary.py --lengths 1024,65536,262144 --lo 2097152 \
        --out results/cgi_boundary_small.json
python3 scripts/cgi_boundary.py --lengths 524288 --out results/cgi_boundary_524.json
python3 scripts/cgi_boundary.py --lengths 786432 --out results/cgi_boundary_786.json
python3 scripts/make_summary.py

# nginx edge
cd /tmp/opencode/nginx_mitigation_1021
/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm -y conf/php-fpm.conf -c lanes/php.ini -D
/opt/nginx-1.30.1/sbin/nginx -p $PWD -c conf/nginx.conf
python3 bin/battery.py p1 p2 p3 p4 p5 p6 p7
python3 bin/headroom.py 5
python3 bin/headroom2.py
python3 bin/capture.py
python3 bin/make_table.py

# M4
cd /tmp/opencode/m4_test_1021
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 USE_ZEND_ALLOC=1 \
  /home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm -n -y conf/fpm.conf -D
python3 bin/run_m4.py
python3 bin/make_summary.py
python3 bin/run_oom_arm.py
kill $(cat run/fpm.pid)
```

All services were stopped after each run: M1–M3 FPM masters A 1051782, B 1051024, C
1051057, B2 1051136, B3 1051170, B4 1052960; httpd masters D 1052091, D0 1052101; nginx
master 1049956 (worker 1052954); edge master/PIDs in `nginx_edge/results/pids.txt`; M4
master 1066095, workers l0–l5 1066096–1066101, l6 1066102 (exit 70) → replacement 1066166
(all stopped). No listeners remained on 28980–28995, 29000–29011 or 29030–29036.
Unrelated concurrent processes under `/tmp/opencode/realapps`, `/tmp/opencode/research`,
the `:28850` mod_php lab and other tasks' dirs were not touched.
