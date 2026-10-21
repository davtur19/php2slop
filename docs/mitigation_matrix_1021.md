# Mitigation matrix 1021 — PHP 8.5.10 upload machinery (CVE-2026-109618 / 109619)

Receipt: [`receipts/mitigation_matrix_1021/`](../receipts/mitigation_matrix_1021/README.md) ·
detailed reports: [M1–M3](../receipts/mitigation_matrix_1021/findings.md),
[nginx edge](../receipts/mitigation_matrix_1021/nginx_edge/findings.md),
[M4](../receipts/mitigation_matrix_1021/m4_unserialize_callback/findings.md),
[8.5.12 CGI](../receipts/mitigation_matrix_1021/patch_8512/cgi_8512_findings.md),
[8.5.12 FPM](../receipts/mitigation_matrix_1021/patch_8512/fpm_8512_findings.md).

Measured 2026-10-21 on private loopback stacks: PHP 8.5.10 FPM (ASAN) behind a private
nginx 1.30.1, httpd 2.4.66 + mod_php 8.5.10, a direct-FastCGI FPM matrix, and a plain
PHP 8.5.12 build. Every claim below is tied to a receipt artifact; unmeasured gaps are
listed at the end. The arm is the known multipart body (4,983,500 B, 20 parts,
`F`×262144 filenames) plus its variants; the OOM is in the RFC1867 filename handling
**during request startup, before application code**, so no application-level control can
prevent it.

## Decision matrix

| id | exact control | scope / lock | blocks (measured) | does not block (measured) | evidence | decision |
|---|---|---|---|---|---|---|
| **M1** | `session.upload_progress.enabled=0` | `php_admin_value` in every FPM pool / vhost. The setting is `ZEND_INI_PERDIR`; only admin scope (measured `access=4`, `ini_set=false`) is a lock. | The 109619 progress-record writer and the RFC1867 startup update path: no new progress record, no progress-update decode/write, no session-store write from the upload machinery (an existing record is still decoded as ordinary session data: lane B `S:1`). | The 109618 OOM. Lane C (M1 only, 8M): 3/3 arms killed the worker (`tried 266240`, exits 70), no session files. It also does not clean a progress record already in the store: lane A's consumer still hits the planted 4.98 MB record (322 B fatal at 8M); that record remains dangerous until consumed or purged. | `findings.md` §0, §3, lane C; `results/C_fpm_m1_only/` | **Apply** as a 109619-surface reduction (upload-progress portion only), never as an OOM fix. |
| **M2** | `memory_limit` sized to the **actual body ceiling**: with an edge cap, `≥ 6.5 × client_max_body_size + 1 MiB` (**8×** recommended); without an edge and with upload-progress machinery off (M1 pinned), php-cgi bisection gives `≥ 3 × post_max_size + 4 MiB`. | `php_admin_value[memory_limit]`; ceiling is `min(client_max_body_size, post_max_size)` in the deployed path. | The arm when the limit covers the filename amplification: lane B (128M) served 5/5 arms + 2 consumers + marker + 19,925,707 B oversize on **one worker, 14 requests, zero exits**; lane B3 (128M, 15 MB body) completed. | Any parsed body above the envelope: B2 (12M, 15 MB body) died (`tried 790528`, exit 70). `-1` (B4) removes the crash by removing the bound, not the bug. | `findings.md` §0, §5; `results/boundary_table.md`; edge `findings.md` §5, `results/headroom*.json` | **Apply**, sized. Not a fix. |
| **M3** | `display_errors=0` + `fatal_error_backtraces=0` | `php_admin_value`; output/verbosity only. | The client-visible fatal body on mod_php: D0 showed the 149 B fatal, D (M1+M2+M3, 128M) did not. | The OOM itself, the error-log entry, the stored-record replacement. On FPM the pre-RINIT OOM already returns an empty body (A/C), so M3 changes no observable OOM behavior. | `findings.md` §0, lanes A/C/D/D0 | **Optional hygiene**, not a mitigation. |
| **M4** | `php_admin_value[unserialize_callback_func] =` (empty) + optional `php_admin_value[include_path] = .` | `php_admin_value` only. Unpinned it is `PHP_INI_ALL` (measured `access=7`): `.user.ini` and `ini_set()` both restore `spl_autoload`. Pinned: `''`, `access=4`, `ini_set=false`. | Attacker autoload via the callback in three measured paths: script-level `unserialize()` (l2/l3 no marker vs l1 yes), request-startup upload-progress decode (l2 no vs l1 yes, class present at script entry), and `session.auto_start` RINIT decode (l5 no vs l4 yes). | Already-defined class gadgets: `dpre.php` (class D3 defined in-script) wrote the marker in **every** lane incl. l2/l3. App-level `unserialize()` of internal/known classes, and the multipart OOM (l6/8M still fatal `tried 1052672`, worker exit 70). | `m4_unserialize_callback/findings.md` §2–§6; `results/m4_summary.md`, `results/m4_results.jsonl` | **Apply** as a narrow 109619 hardening; do not sell it as RCE-proof. |
| **E1** | `client_max_body_size` at the edge, sized against `memory_limit` with the same 8× rule; e.g. `2m` + PHP `16M`, `8m` + PHP `64M`. | nginx (or any reverse proxy) in front of FPM. Enforced on `Content-Length` **and** chunked bodies. | The arm before PHP: N1 answered 4,983,500 B with **413**, 0 bytes in both FPM logs, no session file; a 1.96 MB filename-dense body under the cap completed normally. | Anything under the cap that still exceeds the PHP envelope: N2 (cap `2m`, PHP 8M) fatals on 1.84 MB and on the 2,090,030 B at-cap body. | `nginx_edge/findings.md` §4B–§4C, §5; `results/table.md`, `results/n1_413_php_never_saw.json` | **Apply**, but only as cap **plus** headroom. Cap alone is unsafe. |
| **E2** | `limit_req` (e.g. 10 r/m, burst 5) + `limit_conn` (5), status 429. | nginx; per-IP cost lever independent of body signature. | Mass attempts: 6 back-to-back requests admitted, 7th 429; 10 concurrent → 5×200/5×429 (wall 2.0 s). | A single request every ~6 s; it does not slow the arm itself. `client_max_body_size` is enforced **before** `limit_req`, so an oversize body gets 413, not 429. | `nginx_edge/findings.md` §4E; `results/n4_limit_conn.json` | **Optional** cost lever, not a mitigation. |
| **E3** | Body-token rule matching `PHP_SESSION_UPLOAD_PROGRESS` | Not implementable in core nginx: no modsec/njs/lua; `if ($request_body ~ ...)` measured **200** (body not read at rewrite time). A reference shim was measured instead. | The literal token only: full arm 403; tiny token body 403. | **Complete bypass**: the OOM fires with **no token at all** (4,983,404 B → 8 MiB fatal 266240). Also bypassed by renaming the field via `.user.ini` (`UPGX`), by placing it after an 8 KiB inspection window, and it false-positives on a legitimate filename containing the token. | `nginx_edge/findings.md` §6; `results/shim_full.log`, `results/table.md` | **Rejected.** Do not deploy as a control; it is security theatre for this arm. |
| **P** | PHP 8.5.12 (CVE fix) | The only complete fix of the CVE. | The 109618/109619 corruption/stale-state consumption: 8.5.12 emits the pre-RINIT fatal at a safe point, FPM workers exit 70 as before, every consumer after a producer runs on a fresh worker with baseline bytes; no CVE-surviving signal was observed. | The availability OOM itself at an undersized `memory_limit`: 8.5.12 at 8M still fatals (`tried 2097152`) and the worker still exits 70. It also destroys the session record (data loss) in these lanes. | `patch_8512/cgi_8512_findings.md` (verdict §7), `patch_8512/fpm_8512_findings.md` (verdict §10) | **Required fix.** Keep M2/E1 sizing after patching. |

## Deployment rules (in order)

1. **Patch to 8.5.12 or later.** This is the only control that removes the CVE effect; it
   does not remove the availability OOM.
2. **Put a body ceiling in front of PHP and size `memory_limit` to it.** With an edge:
   `memory_limit ≥ 8 × client_max_body_size` (measured minimum 6.5× + 1 MiB). Recommended
   inversion: `1m → 8M`, `2m → 16M`, `4m → 32M`, `8m → 64M` (1m–4m measured, 8m extrapolated).
   With 8M memory the cap must be `≤ 1m`.
   Without an edge, php-cgi bisection with M1 pinned off gives
   `memory_limit ≥ 3 × post_max_size + 4 MiB` (`8M → 28M`, `16M → 52M`, `32M → 100M`);
   FPM without an edge was not bisected, so use the larger edge-style rule if in doubt.
   If upload-progress may be enabled, use the larger, edge-style rule.
3. **Lock M1 in admin scope:** `php_admin_value[session.upload_progress.enabled] = 0` in
   every pool/VirtualHost. `php_value`/`.user.ini` is not a lock: the setting is PERDIR
   (source-verified) and a docroot `.user.ini` was measured renaming the upload-progress field.
4. **Pin M4 in admin scope:** `php_admin_value[unserialize_callback_func] =` (empty) in
   every pool; optionally `php_admin_value[include_path] = .`. Empty is already the default,
   so the value buys nothing — the non-overridable scope is the control. With M1 applied the
   upload-progress decode path is off anyway; the pin still covers `auto_start` and
   script-level `unserialize()`.
5. **Treat M3 as output hygiene only.** Do not count it as risk reduction.
6. **Do not build token rules.** If rate limiting is wanted, add E2 as a cost lever, knowing
   one request every few seconds still reaches the parser.

## Measured basis

### M1–M3 (FPM 8.5.10 + mod_php 8.5.10)

| lane | settings | arm result | worker | stored record |
|---|---|---|---|---|
| A control | 8M, up=1, disp=1, bt=1 | empty 200; fatal `tried 266240`; consumer on 4.98 MB record → 322 B fatal | **exit 70** (1051783 → 1051784) | replaced 4,986,076 → 330 B |
| B M1+M2+M3 | 128M, post 8M, up=0 | 5/5 arms + 2 consumers + marker + 19.9 MB oversize: 200 `S:1`, no OOM | same 1051025 (14 req) | unchanged `ca3be92f12e7…` |
| C M1 only | 8M, up=0 | 3/3 empty, fatal `tried 266240` | **3 exits 70** | no files created |
| B2 | 12M, post 16M | 15 MB body: empty, fatal `tried 790528` | **exit 70** | 331 B partial |
| B3 | 128M, post 16M | same body: 200 `S:1` | survives | 14,947,510 B |
| B4 | `memory_limit=-1`, up=0 | 200 `S:0`, no OOM | same worker | none |
| D mod_php mitigated | 128M, up=0, disp=0 | 3/3 arms 200 `S:1`, no errors | same child | unchanged |
| D0 mod_php control | 8M, up=1, disp=1 | 149 B fatal `561043a1e978…` | child survives | replaced by 330 B |

Effective INI was verified by `probe.php` in every lane: the five admin keys report
`access=4` and `ini_set(...) === false`.

**Two M2 boundaries** (why the rule depends on the path):

- php-cgi bisection with `session.upload_progress.enabled=0`: for parsed bodies 1.2–14.9 MB,
  min `memory_limit` was **2.52–3.36× body**; at 8M `post_max_size` → **≥28 MiB**.
- FPM/nginx with the upload-progress token present: the token is a measured **amplifier**
  (8- and 12-part bodies are 4/4 fatal with the token vs 0/4 without at 8 MiB; the 12-part
  body stays 0/4 without the token through 12 MiB) and at 128 MiB the arm writes a
  4,984,996 B progress record that serialises every 262144-byte filename. The
  filename-driven parser cost then needs **5.9–6.9× filename bytes**; hence
  `6.5× cap + 1 MiB`, 8× recommended. A 2 MiB cap at 8M PHP is outside the rule and fails
  in practice (N2, 3/3).

### nginx edge (N0–N4)

| lane | edge config | 4,983,500 B arm | under-cap filename-dense body | verdict |
|---|---|---|---|---|
| N0 | cap 8m, PHP 8M | 200 + empty, fatal 266240 | 1.84 MB → fatal | broken baseline |
| N1 | cap 2m, PHP 128M | **413, PHP never reached** | 1.96 MB → 200 + output | **works** |
| N2 | cap 2m, PHP 8M | 413 | 1.84 / 2.09 MB → fatal | unsafe |
| N3 | token rule (reference shim) | 403 literal | no-token / renamed / 8 KiB window → fatal | rejected |
| N4 | cap 2m + 10 r/m + conn 5 | 413 | same as N2 under the cap | cost only |

Operational note: a pre-RINIT fatal is **HTTP 200 with an empty body**; some requests print
full output and still log an OOM at shutdown. Status codes are not a detection signal — use
the FPM error log and worker-exit lines.

### M4 (direct FastCGI, 7 pools)

| lane | pin | script `unserialize()` | upload-progress startup decode | `auto_start` RINIT decode | predefined class |
|---|---|---|---|---|---|
| l0 | none, no `.user.ini` | no | no | — | **yes** |
| l1 | none, `.user.ini` callback | **yes** | **yes** | — | **yes** |
| l2 | `""` | no | no | — | **yes** |
| l3 | `""` + include_path `.` | no | no | — | **yes** |
| l4 | none, `.user.ini` + auto_start | **yes** | — | **yes** | n/a |
| l5 | `""` + auto_start | no | — | no | n/a |
| l6 | `""`, 8M (orthogonality pool) | — | — | — | n/a (OOM arm) |

`l1/l4` prove the pre-script path is real (class present before the script runs); `l2/l3/l5`
prove the admin pin stops it. The predefined-class column is the measured limit: M4 cannot
stop gadgets for classes the application has already defined. l6 is the orthogonality pool:
the 4,983,495 B arm still fatals at 8M (`tried 1052672`, worker exit 70).

### Patch (8.5.12)

- CGI: the same arm still fatals pre-RINIT, but with `tried to allocate 2097152` (the 8.5.10
  arm tripped at `266240`) and at a safe point; no `zend_bailout`/ASAN report, rc 255.
- FPM: 5/5 producers still kill the child (`exit 70`), but every post-producer consumer runs
  on a fresh worker and returns baseline bytes; no corrupted/stale state is consumed.
- Residual: session-record destruction (data loss) and, in the hard-limit lane,
  `_exit(137)` + connection reset. The patch is a CVE fix, not an OOM fix.

## What no control does

No PHP-level setting in this matrix prevents the RFC1867 multipart allocation from running.
M1 only removes the progress-record writer/update path; M4 only removes the autoload lever;
M3 only hides output; a cap only refuses bodies above the chosen ceiling; rate limits only
tax volume.
The parser still over-allocates on any filename-dense body that reaches it. The patch
removes the corruption consequence, not the allocation itself.

## Unverified / gaps

- Direct FastCGI exposure without nginx normalization, HTTP/2 and other SAPI/build shapes
  were not measured; the M4 matrix used a hand-written FastCGI client, the M1–M3 FPM lanes
  used nginx normalization.
- ASAN could not cover the OOM path itself (`USE_ZEND_ALLOC=1` is required for
  `memory_limit` enforcement; ASAN is secondary). Silent in-process corruption without
  observable output cannot be excluded by these runs.
- No RCE/exploit attempt was made; CVE-2026-109619 stale-state RCE remains unproven.
- The M2 constants depend on part count, filename lengths and build (ASAN vs plain);
  re-measure if the upload shape changes. The 8.5.12 runs used a separately built binary,
  not the receipt's binaries.
- PHP 8.5.11 was not tested; the source-level `in_rfc1867_update` guard is a 8.5.12
  observation, not a runtime result here.

## Services / artifacts

All services were stopped after the runs; no listeners remained on 28980–28995,
29000–29011 or 29030–29036. Exact PIDs and per-run shutdown notes are in each block's
`findings.md`; the M1–M3, edge, M4 and patch artifact maps are in the
[receipt README](../receipts/mitigation_matrix_1021/README.md).
