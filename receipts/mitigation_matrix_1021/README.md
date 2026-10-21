# receipt — mitigation_matrix_1021 (config mitigations M1–M3, PHP 8.5.10 FPM + mod_php)

Curated 2026-10-21 from `/tmp/opencode/mitigation_1021/` (volatile scratch; full sha256
inventory in `inventory.sha256.txt`). Measured by playing the known multipart /
upload-progress OOM arm against **real running PHP 8.5.10 stacks** and changing only
admin-scope INI knobs:

- **M1** `session.upload_progress.enabled=0`
- **M2** `memory_limit` headroom (measured; see boundary rule)
- **M3** `display_errors=0` + `fatal_error_backtraces=0`

Loopback only (127.0.0.1), ports 28980–28995, all files under `/tmp/opencode/mitigation_1021/`.
No change was made to `/tmp/opencode/realapps`, the `:28850` mod_php lab conf, or any
php2slop checkout. Details and evidence chains are in `findings.md`; this README is the map.

## Stacks / lanes

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

## Headline numbers

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
- **Boundary** (php-cgi, byte-exact): for parsed bodies 1.2–14.9 MB, min memory_limit is
  2.52–3.36× body; at 8M `post_max_size` recommend **≥28 MiB**, rule
  `memory_limit ≥ 3 × post_max_size + 4 MiB`; 128M is ~4.5× margin.

## What the mitigation does NOT do

M1 removes the progress-record writer/consumer surface but **not** the RFC1867 multipart
filename allocation that OOMs (lane C). M2 is headroom, not a fix — a parsed body above the
limit still kills the worker (B2). M3 hides output only; FPM startup OOM already produces no
body, and on mod_php it hides the 149 B fatal while the OOM and record replacement remain.
The PHP patch (8.5.12) is the only complete fix and was **not** measured here (no built
binary). Direct FastCGI exposure without nginx normalization, concurrency and other build
shapes are unverified — see `findings.md` §7.

## Artifact map

- `findings.md` — full report (matrix, per-lane evidence, effective INI, boundary rule,
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

Not copied: the multi-MB request/response bodies under scratch `steps/` (~5–20 MB each);
their sizes and sha256 are in `results.jsonl`, and the HTTP-level facts are reproducible with
the scripts + configs. The 4,986,076 B seed record lives at
`/tmp/opencode/vulntest8512_2127/records/8512asan_nomm_seed.sess` (sha
`ca3be92f…`, same value as the planted records in lanes A/B/D).

## Provenance / reproduction

```
cd /tmp/opencode/mitigation_1021
python3 scripts/make_configs.py
/opt/nginx-1.30.1/sbin/nginx -p $PWD/nginx -c $PWD/nginx/nginx.conf
python3 scripts/run_lanes.py all          # starts/stops each FPM/httpd lane
python3 scripts/cgi_boundary.py --lengths 1024,65536,262144 --lo 2097152 \
        --out results/cgi_boundary_small.json
python3 scripts/cgi_boundary.py --lengths 524288 --out results/cgi_boundary_524.json
python3 scripts/cgi_boundary.py --lengths 786432 --out results/cgi_boundary_786.json
python3 scripts/make_summary.py
```

All services were stopped after the run: FPM masters A 1051782, B 1051024, C 1051057,
B2 1051136, B3 1051170, B4 1052960; httpd masters D 1052091, D0 1052101; nginx master
1049956 (worker 1052954). No listeners remained on 28980–28995. Unrelated concurrent
processes under `/tmp/opencode/nginx_mitigation_1021` (ports 29000–29007, php-fpm master
1054948 / nginx master 1054998) belong to another task and were not touched.
