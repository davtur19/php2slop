# findings — mitigation_matrix_1021 (config-level mitigations vs PHP 8.5.10 upload arm)

Measured 2026-10-21 21:48–21:56 CEST on private loopback stacks. Scope: apply config-level
mitigations M1 (session.upload_progress.enabled=0), M2 (memory_limit headroom) and M3
(display_errors=0 + fatal_error_backtraces=0) to real PHP 8.5.10 FPM and mod_php stacks,
then replay the known multipart/upload-progress OOM arm and record what changes.
Loopback only (127.0.0.1), ports 28980–28995, private dirs under
`/tmp/opencode/mitigation_1021/`. The realapps lab (`/tmp/opencode/realapps`), the :28850
mod_php lab conf and the php2slop checkouts were not modified.

## 0. Verdict (short)

- **M1 alone does not stop the OOM.** Lane C (upload_progress=0, 8M): 3/3 arms killed the
  FPM worker with exit code 70 and the same `tried to allocate 266240` fatal; no session
  file was created. The allocation is the RFC1867 multipart filename handling, not the
  progress-record writer.
- **M1+M2+M3 on FPM (lane B, 128M) absorbs the arm completely.** 5/5 arms and a 19.9 MB
  oversize request returned HTTP 200 `S:1` on one unchanged worker (pid 1051025 for all 14
  requests), no OOM, no worker exit, and the planted 4,986,076 B record stayed byte-identical
  (`ca3be92f12e7…`). A normal marker session also survived unchanged.
- **M1+M2+M3 on mod_php (lane D, 128M) behaves the same at HTTP level**: 3/3 arms and both
  consumers returned `S:1` on prefork child 1052092; the 4,986,076 B record was untouched;
  no PHP error log entry was produced.
- **M2 is headroom, not a fix, and must be sized.** 12M limit with a 15 MB parsed body
  (lane B2, post_max 16M) still OOMs (`tried 790528`) and kills the worker; 128M (lane B3)
  completes and writes the 14,947,510 B record.
- **M3 is output-only.** In FPM the startup OOM produces an empty upstream response anyway;
  `display_errors` changes nothing (lane A/C bodies are empty, fatal only in php_err.log).
  On mod_php it hides the 149 B fatal body (lane D0 vs D) but not the OOM, the log entry or
  the stored-record replacement.
- **Measured M2 rule:** for a multipart body B that PHP actually parses, the smallest
  surviving `memory_limit` is ≈ **2.5–3.4 × B** in the measured 1.2–14.9 MB range
  (L=1024 is at the 2 MiB enforcement floor). Recommend **`memory_limit ≥ 3 × post_max_size
  + 4 MiB`** ⇒ ≥28 MiB at 8M post, ≥52 MiB at 16M post. 128M is comfortably above both.
- **The PHP patch remains the only complete fix.** 8.5.12 was not built here, so the patch
  itself is unmeasured in this matrix.

## 1. Stacks and method

Binaries:
- FPM: `/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm` (PHP 8.5.10, ASAN build),
  started with `-n -y <lane>/fpm.conf`, `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1`,
  `USE_ZEND_ALLOC=1` (needed for memory_limit enforcement).
- mod_php: `/tmp/opencode/apache/bin/httpd` + `/tmp/opencode/apache/modules/libphp.so`
  (PHP 8.5.10), one private conf per lane, `ServerLimit 1 StartServers 1 MaxRequestWorkers 1
  MaxConnectionsPerChild 0`.
- Front-end for FPM lanes: private nginx 1.30.1
  (`/opt/nginx-1.30.1/sbin/nginx`, prefix `/tmp/opencode/mitigation_1021/nginx`,
  listeners 28990–28995, `client_max_body_size 64m`), because a hand-written FastCGI client
  was rejected by PHP's FastCGI param parser (every non-empty PARAMS record → connection
  reset). nginx also normalizes chunked bodies to CONTENT_LENGTH, which is the realistic
  deployment shape.
- Each FPM pool: `pm=static`, `pm.max_children=1`, `pm.max_requests=0`, so worker identity is
  unambiguous; access log format `%p|%d|%t|%m|%s|%l` (leading pid) and the mod_php log adds
  `%P` (serving child pid).

Mitigations were set as **admin scope** (`php_admin_value` in the pool / VirtualHost):
`session.upload_progress.enabled`, `memory_limit`, `post_max_size`, `display_errors`,
`fatal_error_backtraces`; `session.upload_progress.cleanup=0` in every lane so records stay
on disk for inspection. The `probe.php` response confirms every lane reports `access=4`
(PHP_INI_SYSTEM lock) for those keys, and `ini_set(...)` returns `false`.

Arm shape (identical across lanes): multipart POST to `/index.php` =
field `PHPSESSID=<sid>` + field `PHP_SESSION_UPLOAD_PROGRESS=MMM` + 20 file parts
(`max_file_uploads=20`): filename `F`×9 then 19 × `F`×262144, one byte of content each;
body 4,983,496–4,983,500 B, below the 8M `post_max_size`. `index.php` is only
`<?php session_start(); echo "S:", count($_SESSION);` — the OOM fires before app code.
`sid` travels as the form field (session.use_only_cookies=1 is set, but PHP's request
startup consumes the POST field for the session id; consumers use the Cookie header).

## 2. Results matrix

| lane | stack / settings | request | HTTP | resp body | fatal | worker |
|---|---|---|---|---|---|---|
| A | FPM 8.5.10 control: 8M, up=1, disp=1, bt=1 | consumer on planted 4,986,076 B record | 200 | 322 B, sha `f02f5c8e53ce`, `tried 266240` | yes (in body) | 1051783 then 1051784 |
| A | " | producer arm, 4,983,500 B | 200 | 0 B (empty upstream) | yes (php_err.log only) | **1051783 exit 70**, respawn 1051784 |
| A | " | consumer after | 200 | 3 B `S:1` sha `de34ad408f98` | no | 1051784 |
| A | " | stored record after | — | 4,986,076 B → **330 B** progress record | — | — |
| B | FPM + M1+M2+M3: 128M, up=0, disp=0, bt=0 | consumer on planted record | 200 | 3 B `S:1` | no | 1051025 |
| B | " | arm ×5 | 200 ×5 | 3 B `S:1` each | no | **same 1051025**, no exits |
| B | " | consumer ×2 after | 200 ×2 | 3 B `S:1` | no | 1051025 |
| B | " | marker session before/after arm | 200 | `S:1|M:'GOOD'|K:marker` both, sha `c37a5a1f9350` | no | 1051025 |
| B | " | 19,925,707 B body (> 8M post_max) | 200 | 3 B `S:1` | no, only post_max warning | 1051025 |
| B | " | stored record after 5 arms + 2 consumers | — | 4,986,076 B, sha **unchanged** `ca3be92f12e7` | — | — |
| C | FPM + M1 only: 8M, up=0, disp=1, bt=1 | arm ×3 | 200 ×3 | 0 B each | yes ×3 (`tried 266240`) | **3 workers exit 70**: 1051058, 1051059, 1051060 |
| B2 | FPM: 12M, post 16M, up=1 | 15 MB body (14,944,972 B) | 200 | 0 B | yes (`tried 790528`) | **1051137 exit 70** |
| B3 | FPM: 128M, post 16M, up=1 | same 15 MB body | 200 | 3 B `S:1` | no | **1051171 survives** |
| B4 | FPM + M1, `memory_limit=-1`, post 8M | arm ×2 | 200 ×2 | 3 B `S:0` each | no | **same 1052961** |
| B4 | " | 19,925,702 B body | 200 | 3 B `S:0` | no, only post_max warning | 1052961 |
| D | mod_php + M1+M2+M3: 128M, up=0, disp=0, bt=0 | consumer + arm ×3 + consumer ×2 | 200 ×6 | `S:1` sha `de34ad408f98` | no, no php_err.log | **same child 1052092** |
| D | " | stored record after | — | 4,986,076 B, sha unchanged `ca3be92f12e7` | — | — |
| D0 | mod_php control: 8M, up=1, disp=1, bt=1 | arm, 4,983,498 B | 200 | **149 B** fatal, sha `561043a1e978` | yes (`tried 266240`) | **same child 1052102 survives** |
| D0 | " | consumer after / record after | 200 | 3 B `S:1`; record replaced by 330 B progress record | no | 1052102 |

Note on lane A: the 322 B fatal came from the **consumer** reading the planted record
(`session_start()` at index.php line 2); the producer arm response is empty because the FPM
worker dies during request startup (exit 70) before a body can be produced. The producer
fatal is visible only in `lanes/A_fpm_control/logs/php_err.log`:
`PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240
bytes) in Unknown on line 0` — the same message that mod_php returns in the body (D0, 149 B).
This is the FPM startup-failure path: `php_request_startup() == FAILURE` → worker exits 70;
the HTTP client sees a reset/empty response, not a fatal page.

Lane A stored-record divergence: planted 4,986,076 B record (sha `ca3be92f12e7…`, from
`/tmp/opencode/vulntest8512_2127/records/8512asan_nomm_seed.sess`) is **replaced** by a
330 B partial progress record (sha `713fb73e6b37…`, `bytes_processed: 5300, done: 0`) after
the producer OOM. Post-attack consumers then return `S:1`; the large record is gone.
Lane B never enters this path: upload_progress=0 means no machinery write, and the planted
record stays intact for all consumers. Lane D0 shows the same replacement on mod_php
(330 B, sha `15d82752d8d2…`).

## 3. Lane details

### A — FPM 8.5.10 control (port 28990 → FPM 28980)
Effective: `memory_limit=8M`, `post_max_size=8M`, `upload_progress.enabled=1`, `cleanup=0`,
`display_errors=1`, `fatal_error_backtraces=1`, `max_file_uploads=20`.
Access log pids: 1051783 ×2 (effective-ini probe + baseline consumer), then 1051784 ×2
(consumer after the arm). The arm itself never reaches the access log — the worker dies at
request startup. FPM log: `child 1051783 exited with code 70 after 0.111707 seconds`.
Session files: planted 4,986,076 B; after producer 330 B; consumers both 3 B `S:1`.
PHP error log: the consumer's `session_start()` OOM (322 B body) and the producer's
`Unknown on line 0` OOM, plus `Warning: Unknown: Failed to decode session object. Session has
been destroyed`.

### B — FPM + M1+M2+M3 (port 28991 → FPM 28981)
Effective: `memory_limit=128M`, `post_max_size=8M`, `upload_progress.enabled=0`, `cleanup=0`,
`display_errors=0`, `fatal_error_backtraces=0`, `max_file_uploads=20`.
One static worker **1051025 served all 14 requests** (probe, baseline consumer, 5 arms,
2 consumers, plant/probe/arm/probe marker set, oversize). Zero `exited with code` lines.
Stored record sha `ca3be92f12e7b58edb097a4fc4002cfadb34c97baa6e1d7db312eeafd275b543`
(4,986,076 B) before and after. Marker record `sess_bstate` 18 B sha
`a21a2edf710b…`, body `S:1|M:'GOOD'|K:marker` before and after the arm. 19,925,707 B body:
`PHP Request Startup: POST Content-Length of 19925707 bytes exceeds the limit of 8388608
bytes in Unknown on line 0`, no parse, no OOM.

### C — FPM + M1 only (port 28992 → FPM 28983)
Effective: `memory_limit=8M`, `post_max_size=8M`, `upload_progress.enabled=0`,
`display_errors=1`, `fatal_error_backtraces=1`.
3 arms → 3 × HTTP 200 with empty body; php_err.log has 3 × `Allowed memory size of 8388608
bytes exhausted (tried to allocate 266240 bytes) in Unknown on line 0`; FPM exits
1051058/1051059/1051060 all code 70; sessions dir **empty** (no progress record created).
This isolates M1: disabling the progress writer removes the stored-record surface but not
the multipart allocation.

### B2/B3 — M2 sizing probes (ports 28993/28994 → FPM 28984/28985)
Both: `post_max_size=16M`, `upload_progress.enabled=1`, `cleanup=0`, same 14,944,972 B body
(20 parts, 786432-byte filenames). B2 `memory_limit=12M` → worker 1051137 exit 70, fatal
`12,582,912 bytes exhausted (tried to allocate 790528)`, 331 B partial record. B3
`memory_limit=128M` → worker 1051171 survives, HTTP 200 `S:1`, record 14,947,510 B sha
`d3c072df44a3…`, `done:1`, `bytes_processed:14,944,972`, 20 files. Same body, same post_max,
only memory_limit differs: this is the M2 boundary in one pair.

### B4 — `memory_limit=-1` stopgap (port 28995 → FPM 28987)
M1+M3 with `memory_limit=-1`, `post_max_size=8M`. Arm ×2 and a 19,925,702 B oversize request:
HTTP 200, `S:0`, same worker 1052961, no OOM; only the post_max warning for the oversize
body. This removes the crash by removing the bound (Tenable-style stopgap); it does not
restore a resource limit and was not tested under memory pressure.

### D — mod_php 8.5.10 + M1+M2+M3 (port 28982, direct HTTP)
Effective: `memory_limit=128M`, `post_max_size=8M`, `upload_progress.enabled=0`, `cleanup=0`,
`display_errors=0`, `fatal_error_backtraces=0`. Probe + stored-record consumer + 3 arms +
2 consumers all served by **prefork child 1052092**; all `S:1` (3 B, sha `de34ad408f98`);
record unchanged `ca3be92f12e7…`; `php_err.log` does not exist (no PHP errors at all).
On mod_php the worker never exits — the 8M OOM is a bailout in the request, the child
survives; with 128M it is not reached.

### D0 — mod_php 8.5.10 control (port 28986)
Effective: `memory_limit=8M`, `upload_progress.enabled=1`, `display_errors=1`,
`fatal_error_backtraces=1`. Arm → HTTP 200, **149 B** body
`<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate
266240 bytes) in <b>Unknown</b> on line <b>0</b>` sha
`561043a1e978c6563cea92ea0aa5d4ef9cf90c6c9fe0ae7f428afea29d6bef6a`; child 1052102 survives;
record replaced by a 330 B progress record; consumer `S:1`; php_err.log contains the same
fatal. This is the byte-parity control for the 149 B fatal used in earlier receipts.

### CGI fingerprint (8.5.10 php-cgi, no network)
`scripts/cgi_arm.py` ran the same 4,983,495 B body on the ASAN php-cgi (8M, post 64M,
`USE_ZEND_ALLOC=1`). Both `upload_progress.enabled=1` and `=0` produce the identical 217 B
CGI stdout → 149 B body sha `561043a1e978…`, `tried 266240`, rc 255. en1 (enabled=1) ran
first at 21:52:06.309 and created the 330 B progress record; en0 (enabled=0) ran 96 ms later
against the same shared sid dir, so its record is **stale** — do not cite en0 as evidence
that M1 creates a record. The authoritative M1 session result is lane C (empty sessions dir).

## 4. Effective INI per lane (admin-scope values, verified by probe.php)

All values reported `access=4` (PHP_INI_SYSTEM) except `max_file_uploads` (`access=6`,
PHP_INI_PERDIR); `ini_set()` on the four tested keys returned `false` in every lane.

| setting | A | B | C | B2 | B3 | B4 | D | D0 |
|---|---|---|---|---|---|---|---|---|
| session.upload_progress.enabled | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 1 |
| session.upload_progress.cleanup | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| memory_limit | 8M | 128M | 8M | 12M | 128M | -1 | 128M | 8M |
| post_max_size | 8M | 8M | 8M | 16M | 16M | 8M | 8M | 8M |
| display_errors | 1 | 0 | 1 | 1 | 1 | 0 | 0 | 1 |
| fatal_error_backtraces | 1 | 0 | 1 | 1 | 1 | 0 | 0 | 1 |
| log_errors | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| max_file_uploads | 20 | 20 | 20 | 20 | 20 | 20 | 20 | 20 |

Raw probe transcripts: `results/<lane>/effective_ini.txt`. The probe body also reports
`PHP_VERSION=8.5.10` and SAPI (`fpm-fcgi` or `apache2handler`).

## 5. Measured M2 boundary (php-cgi, byte-exact bisection)

Method: `scripts/cgi_boundary.py` spawns the 8.5.10 ASAN php-cgi with `-n`,
`post_max_size=64M`, `session.upload_progress.enabled=0`, `USE_ZEND_ALLOC=1`, and feeds the
same 20-part body with 19 filenames of length L. Binary search over `memory_limit` with byte
granularity; the lower neighbour is re-run to prove it OOMs (unless the enforcement floor is
hit). Data (`results/cgi_boundary_small.json`, `cgi_boundary_524.json`,
`cgi_boundary_786.json`; rendered in `results/boundary_table.md`):

| filename len | 20-part body bytes | min memory_limit that survives | body+overhead | ratio |
|---|---|---|---|---|
| 1024 | 22,219 | ≤ 2,097,152 B (2 MiB, floor) | +2,074,933 B | 94.39x |
| 65536 | 1,247,947 | 4,194,304 B (4 MiB) | +2,946,357 B | 3.36x |
| 262144 | 4,983,499 | 12,582,912 B (12 MiB) | +7,599,413 B | 2.52x |
| 524288 | 9,964,235 | 29,360,128 B (28 MiB) | +19,395,893 B | 2.95x |
| 786432 | 14,944,971 | 41,943,040 B (40 MiB) | +26,998,069 B | 2.81x |

For L=1024 the true minimum is below the observable floor: PHP refuses to lower
`memory_limit` below its startup usage (2 MiB) — the `-d memory_limit=2097151` run prints
`Failed to set memory limit` and keeps the higher limit (detected by
`set_limit_failed` in the JSON). So 2 MiB is an upper bound, not an exact boundary.

**Rule (measured):** for bodies PHP parses, `min_limit ≈ 2.5–3.4 × body` in the 1.2–14.9 MB
range. For deployment, size the limit against the **ceiling** the parser can see, i.e.
`post_max_size`:

> `memory_limit ≥ 3 × post_max_size + 4 MiB`
> → 28 MiB at an 8M post_max_size, 52 MiB at 16M, 100 MiB at 32M.

128M gives ~4.5× margin at 8M post and 2.5× at 16M post. 12M is *below* the measured need
for a 15 MB body (needs ≥40 MiB) and dies (B2). The rule is a headroom rule, not a fix: any
body the parser accepts and the limit cannot cover will still OOM.

Caveats: measured with 20 parts / one 9-byte plus 19 equal large filenames and
`max_file_uploads=20` on an ASAN 8.5.10 build. Different part counts, filename lengths,
multipart field counts, or a non-ASAN build shift the constant; re-measure if the upload
shape changes. The ratio is not a safety proof, only the observed envelope.

## 6. What these mitigations do NOT do

- **M1 alone is not a fix.** upload_progress=0 removes the progress-record writer/consumer
  surface only. The OOM is in RFC1867 multipart filename allocation *before* app code and
  fires with M1 on (lane C: 3/3 worker deaths; CGI both settings). It also does not stop an
  attacker from filling the session store by other means.
- **M2 is headroom, not a fix.** A body within `post_max_size` but above the memory envelope
  still OOMs (B2: 12M vs 15 MB body → worker exit 70). If `post_max_size` is raised without
  scaling `memory_limit`, the window reopens. `memory_limit=-1` (B4) removes the crash by
  removing the bound, not by fixing the bug.
- **M3 only hides output.** In FPM the startup OOM already yields an empty response (A/C),
  so display_errors=0 changes nothing observable; on mod_php it hides the 149 B fatal body
  (D0 vs D) but the OOM, the php_err.log entry and the stored-record replacement still
  happen.
- **Stored-record divergence is not removed by M1 when the record already exists.** A
  4,986,076 B record planted in the session store makes an unmitigated consumer OOM at 8M
  (A baseline, 322 B body). M2 (128M) makes that consumer succeed (B). M1 prevents *new*
  progress records but does not clean existing ones.
- **The only complete fix is the PHP patch** (8.5.12; CVE-2026-109618/109619). These
  settings are compensations: they raise cost/limit the blast radius, but the vulnerable
  parser still runs.

## 7. Unverified / gaps (explicit)

1. **8.5.12 not measured.** No built FPM at `/tmp/opencode/fpmtest8512_*/build/sbin/php-fpm`
   exists; the patched-version comparison in this matrix is absent. The advisory attribution
   is referenced, not re-tested here.
2. **Direct FastCGI exposure.** All FPM lanes are behind nginx, which normalizes chunked
   bodies and sets CONTENT_LENGTH. An attacker speaking FastCGI directly to port 28980/28981
   (or a misconfigured proxy that forwards chunked bodies) may control/omit CONTENT_LENGTH;
   whether the post_max_size check can be bypassed that way is **not measured**.
3. **Concurrency / process-manager modes.** `pm=static, max_children=1` was used to pin
   worker identity. Behavior under `pm=dynamic`/`ondemand`, multiple workers, request
   queueing, or sustained repeats (worker respawn cost, DoS rate) is not measured.
4. **Other SAPI/build shapes.** Only ASAN 8.5.10 FPM + mod_php + local php-cgi were tested.
   Non-ASAN release builds, other SAPIs, opcache/preload, other session handlers/serializers,
   and other multipart shapes (part counts, filename encodings, nested fields) are not
   measured.
5. **No post-attack memory-pressure check** for B4 (`memory_limit=-1`): removing the bound
   may allow arbitrarily large allocations; only the immediate arm was observed.
6. **`post_max_size` refusal at 8M was tested only with 128M memory** (lane B, 19.9 MB body).
   The expected safe behavior at 8M memory (refuse before parse) was not re-run; B2/B3 show
   the parsed 15 MB body at 16M post.
7. **Session-record creation under M1 with a clean store** is proven by lane C (no files);
   the CGI en0 artifact is stale (en1 ran first, shared sid dir) and must not be cited as
   creation evidence.

## 8. Reproduction (private, loopback)

```
cd /tmp/opencode/mitigation_1021
python3 scripts/make_configs.py                 # regenerate lane configs
/opt/nginx-1.30.1/sbin/nginx -p $PWD/nginx -c $PWD/nginx/nginx.conf
python3 scripts/run_lanes.py A                  # or B, C, B2, B3, B4, D, D0, all
python3 scripts/cgi_boundary.py --lengths 1024,65536,262144 --lo 2097152 \
        --out results/cgi_boundary_small.json
python3 scripts/cgi_boundary.py --lengths 524288 --out results/cgi_boundary_524.json
python3 scripts/cgi_boundary.py --lengths 786432 --out results/cgi_boundary_786.json
python3 scripts/make_summary.py                 # results_table.md + boundary_table.md
```

`run_lanes.py` starts/stops each FPM/httpd master itself; nginx is a separate front-end and
was stopped last (`nginx -s quit`, master 1049956). All lane configs, access logs, php error
logs and per-request bodies are under `lanes/` and `results/`.

## 9. Service PIDs / final state

- nginx front-end: master **1049956**, initial worker 1049957, replacement worker **1052954**
  (the worker was replaced at 21:53:51; both master and worker are stopped at the end).
- FPM masters (all stopped by `run_lanes.py`): A 1051782, B 1051024, C 1051057, B2 1051136,
  B3 1051170, B4 1052960.
- FPM workers: A 1051783 (exit 70) → 1051784; B 1051025; C 1051058/1051059/1051060 (all
  exit 70) → 1051061; B2 1051137 (exit 70) → 1051138; B3 1051171; B4 1052961.
- mod_php masters: D 1052091, D0 1052101 (stopped); serving children D 1052092, D0 1052102.
- Final check: no listeners on 127.0.0.1:28980–28995; no `mitigation_1021` processes remain.
  (Concurrent, unrelated processes under `/tmp/opencode/nginx_mitigation_1021` on ports
  29000–29007 belong to another task and were not touched: php-fpm master 1054948, nginx
  master 1054998.)

## 10. Artifacts

- `results/results_table.md` — the matrix rendered from `results/<lane>/results.jsonl`.
- `results/boundary_table.md` + `results/cgi_boundary_*.json` — boundary data.
- `results/<lane>/effective_ini.txt` — raw probe transcript per lane.
- `results/<lane>/worker_receipt.json` — access-log pids, FPM exits, final session state.
- `results/<lane>/session_state_*.json` — planted/after record sizes and shas.
- `results/matrix_summary.json` — machine-readable consolidation of all lanes.
- `lanes/<lane>/fpm.conf` / `mitmD.conf` — exact configs; `logs/` — access/fpm/php error.
- `scripts/` — drivers (`run_lanes.py`, `http_arm.py`, `cgi_boundary.py`, `cgi_arm.py`,
  `make_summary.py`, `make_configs.py`).
