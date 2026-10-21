# Mitigation matrix 1021 — M1/M2/M3 vs PHP 8.5.10 upload OOM

Receipt: [`receipts/mitigation_matrix_1021/`](../receipts/mitigation_matrix_1021/README.md) ·
full findings: [`receipts/mitigation_matrix_1021/findings.md`](../receipts/mitigation_matrix_1021/findings.md)

Measured 2026-10-21 on private loopback stacks (FPM 8.5.10 ASAN + nginx front-end, and
httpd 2.4.66 + mod_php 8.5.10). Eight lanes, admin-scope INI only:

- **A** FPM control (8M, upload_progress=1)
- **B** FPM + M1+M2+M3 (128M, post 8M, upload_progress=0, display_errors=0, backtraces=0)
- **C** FPM + M1 only (8M, upload_progress=0)
- **B2/B3** FPM, post 16M, same 15 MB body, memory_limit 12M vs 128M
- **B4** FPM + M1, `memory_limit=-1` stopgap
- **D/D0** mod_php mitigated (128M) / control (8M)

## Results

| lane | arm result | worker | stored record |
|---|---|---|---|
| A | empty HTTP 200; fatal `tried 266240` in php_err.log; baseline consumer on 4.98 MB record → 322 B fatal | **exit 70** (1051783 → 1051784) | replaced 4,986,076 → 330 B |
| B | 5/5 arms + 2 consumers + marker + 19.9 MB oversize: 200 `S:1`, no OOM | **same 1051025** (14 req) | unchanged `ca3be92f12e7…` |
| C | 3/3 arms empty, fatal `tried 266240` | **3 exits 70** | no files created |
| B2 | 15 MB body, 12M limit: empty, fatal `tried 790528` | **exit 70** | 331 B partial |
| B3 | same body, 128M: 200 `S:1` | survives 1051171 | 14,947,510 B `d3c072df…` |
| B4 | `memory_limit=-1`: 200 `S:0`, no OOM | same 1052961 | none |
| D | 3/3 arms, 200 `S:1`, no errors | same child 1052092 | unchanged |
| D0 | 149 B fatal body `561043a1e978…` | child survives | replaced by 330 B |

## Boundary rule (measured, php-cgi bisection)

For a multipart body B that PHP actually parses, the smallest surviving `memory_limit` was
**2.52–3.36 × B** for B = 1.2–14.9 MB (L=1024 is at PHP's 2 MiB enforcement floor). At 8M
`post_max_size` the recommendation is:

> `memory_limit ≥ 3 × post_max_size + 4 MiB` → **≥ 28 MiB** at 8M post (52 MiB at 16M).

128M gives ~4.5× margin at 8M post. The 12M lane (B2) dies on a 15 MB body: M2 is headroom,
not a fix.

## What the knobs do not do

- **M1 alone does not stop the OOM**: the allocation is RFC1867 multipart filename handling
  before app code (lane C: 3/3 worker exits; CGI both progress settings).
- **M2 is not a fix**: any body inside `post_max_size` but above the memory envelope still
  OOMs. `-1` removes the crash by removing the bound (B4).
- **M3 is output-only**: FPM startup OOM already yields an empty response; on mod_php it hides
  the 149 B fatal body but not the OOM/log/record replacement.
- **The PHP patch (8.5.12, CVE-2026-109618/109619) remains the only complete fix.** It was
  not built in this run (`/tmp/opencode/fpmtest8512_*/build/sbin/php-fpm` absent), so the
  patched-version comparison is unverified here. Direct FastCGI exposure without nginx
  normalization, concurrency, and non-ASAN/other SAPI shapes are also unverified.

Exact effective INI per lane (`probe.php`, all `access=4` / `ini_set=false`):

| setting | A | B | C | B2 | B3 | B4 | D | D0 |
|---|---|---|---|---|---|---|---|---|
| session.upload_progress.enabled | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 1 |
| memory_limit | 8M | 128M | 8M | 12M | 128M | -1 | 128M | 8M |
| post_max_size | 8M | 8M | 8M | 16M | 16M | 8M | 8M | 8M |
| display_errors | 1 | 0 | 1 | 1 | 1 | 0 | 0 | 1 |
| fatal_error_backtraces | 1 | 0 | 1 | 1 | 1 | 0 | 0 | 1 |

All services were stopped after the run (FPM masters 1051782/1051024/1051057/1051136/1051170/
1052960, httpd masters 1052091/1052101, nginx master 1049956 + worker 1052954); no listeners
remained on 28980–28995.
