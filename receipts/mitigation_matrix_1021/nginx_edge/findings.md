# nginx-edge mitigation lanes vs. the PHP 8.5.10 upload-progress OOM arm

Date: 2026-10-21.  Work dir: `/tmp/opencode/nginx_mitigation_1021/`.
Loopback only, ports 29000-29011.  No git repo was touched.  The INI-lane worker
directory `/tmp/opencode/mitigation_1021/` was read only (arm shape reference),
never written.

---

## Lane verdicts (quick look)

| lane | edge config | 4,983,500 B arm | filename-dense body under the cap | PHP fatal | verdict |
|---|---|---|---|---|---|
| **N0** control | `client_max_body_size 8m`, PHP 8M | 200 + empty body | 1.84 MB → fatal | **yes** | baseline, broken |
| **N1** cap + headroom | `client_max_body_size 2m`, buffer 1m, PHP 128M | **413**, PHP never reached | 1.96 MB → 200 + output | **no** | **works** |
| **N2** cap only | `client_max_body_size 2m`, PHP 8M | **413** | 1.84 MB and 2.09 MB → fatal | **yes** | blocks only >2 MiB; unsafe |
| **N3** token block | not implementable in this nginx (no modsec/njs/lua); reference shim measured | 403 when the literal is present | shim bypassed (no-token / `.user.ini` / prefix window) → fatal | **yes** after every bypass | **not a mitigation for this arm** |
| **N4** rate/conn | cap 2m + `limit_req 10r/m burst=5` + `limit_conn 5` | 413 | same as N2 | **yes** under the cap | **cost lever only** |

---

## 0. TL;DR

* **N1 (edge size cap + PHP headroom) is the only lane that fully works**: the
  4,983,500 B arm is answered by nginx with **413** before PHP opens the body
  (0 bytes in the FPM error log and access log, no session file).  A
  filename-dense body just under the 2 MiB cap then completes normally.
* **N2 (cap alone) does not work**: `client_max_body_size 2m` with
  `memory_limit=8M` still OOMs on a **2,090,030 B** body (3/3 fatal) and on a
  1,836,238 B body (5/5 fatal).  The edge cap must be sized against
  `memory_limit`, not chosen alone.
* **Measured headroom rule**: the multipart parser needs
  **≈ 6.5 × (filename bytes in the body) + ~1 MiB**, and a body can be ~100 %
  filename bytes, so
  **memory_limit ≥ 6.5 × client_max_body_size + 1 MiB** (use **8×** for margin).
  With a 2 MiB cap that means **≥ 14 MiB, use 16 MiB**; 8 MiB is unsafe.
  Equivalently: at 8 MiB you may only allow `client_max_body_size ≤ 1m`.
* **N3 (protocol-token block) cannot be implemented with this nginx**: the
  binary has no modsecurity, no njs, no lua (only `--with-http_ssl_module`), and
  the core `if ($request_body ~ ...)` idiom provably never fires (measured 200
  on a body containing the token).  Worse, a perfect token rule would not stop
  this arm: **the identical OOM fires with no upload-progress field at all**
  (no-token 4,983,404 B body → 8 MiB fatal, tried to allocate 266240 B).
* **N4 (rate/conn limits) works as a cost lever, not as a fix**: a fresh zone
  admits 6 back-to-back requests (rate token + burst=5), the 7th is 429;
  `limit_conn 5` rejected 5 of 10 concurrent requests with 429.  One request
  every 6 s is still enough to trigger the bug.
* Client-visible status is **not** a reliable OOM signal: a pre-RINIT fatal is
  returned as **HTTP 200 with an empty chunked body**, and some bodies OOM
  during `session_start()`/shutdown *after* the script has already printed
  output (still 200).

---

## 1. Environment

| component | value |
|---|---|
| nginx | `/opt/nginx-1.30.1/sbin/nginx`, `nginx/1.30.1`, `configure arguments: --prefix=/opt/nginx-1.30.1 --with-http_ssl_module` |
| nginx modules | **none dynamic**: no `/opt/nginx-1.30.1/modules`; `ngx_http_*_module.so` files exist only inside a Docker overlay layer for a *different* nginx build and cannot be loaded into this binary. No modsecurity, no njs, no lua. |
| PHP | `/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm` → `PHP 8.5.10 (fpm-fcgi)` |
| PHP config | shared `lanes/php.ini`, defaults: `session.upload_progress.enabled=1`, `name=PHP_SESSION_UPLOAD_PROGRESS`, `cleanup=0`, `prefix=upload_progress_`, `max_file_uploads=20`, `post_max_size=8M`; `memory_limit`/`save_path` set per pool |
| OS | Linux, user `davide` (pools run as `davide`, "user/group ignored when FPM is not root") |

No packages were installed.  nginx was used exactly as shipped.

## 2. Lab layout

```
/tmp/opencode/nginx_mitigation_1021/
  conf/nginx.conf          one master, one server block per lane
  conf/php-fpm.conf        one master, one pool per lane (own unix socket, own logs, own sessions dir)
  docroot/                 index.php (session_start + probe), upload.php, probe.php, sleep.php
  docroot/tokrename/       index.php + .user.ini (session.upload_progress.name=UPGX)  [bypass test]
  lanes/php.ini            shared php.ini
  bin/narm.py              arm/shape/legit driver (raw socket, chunked support, log-delta aware)
  bin/battery.py           lane scenarios A-F
  bin/headroom.py          5-trial fresh-vs-warm OOM boundary
  bin/headroom2.py         amplification model + token contribution + at-cap
  bin/shim.py              REFERENCE body-inspection rule (not nginx) for the token-rule study
  bin/capture.py           exact wire transcripts
  bin/make_table.py        renders results/table.md
  logs/                    nginx access/error per lane, FPM error/access per pool
  sessions/{n0,n1,n2,n3,n4,shape,fresh,warm}/   session dirs outside every docroot
  results/                 lanes.jsonl, headroom*.json, shim logs, transcripts/, table.md
```

Lanes / ports:

| port | lane | nginx edge | PHP pool |
|---:|---|---|---|
| 29000 | N0 control | `client_max_body_size 8m` (to admit the arm), buffer 128k | `memory_limit=8M` |
| 29001 | N1 | `client_max_body_size 2m`, buffer 1m | `memory_limit=128M`, `post_max_size=8M` |
| 29002 | N2 | `client_max_body_size 2m`, buffer 1m | `memory_limit=8M` |
| 29003 | N3 | reference token-rule shim (python) → 29006 | `memory_limit=8M` (29006) |
| 29004 | N4 | cap 2m + `limit_req 10r/m burst=5 nodelay`, `limit_conn 5`, status 429 | `memory_limit=8M` |
| 29005 | sweep | no cap, per-request `PHP_VALUE` (memory_limit via `X-PHP-Mem`) | 256M default |
| 29006 | n3 upstream | no cap | `memory_limit=8M` |
| 29007 | N3-core-approx | no cap + `if ($request_body ~ "PHP_SESSION_UPLOAD_PROGRESS") { return 403; }` | `memory_limit=8M` |
| 29008 | N3-8k | reference shim with an 8 KiB inspection window | `memory_limit=8M` |
| 29009 | shape | no cap, for small-body grammar / `.user.ini` tests | `memory_limit=8M` |
| 29010 | fresh | per-request fresh worker (`pm.max_requests=1`) | per-request memory_limit |
| 29011 | warm | single persistent worker | per-request memory_limit |

Reproduce:

```bash
cd /tmp/opencode/nginx_mitigation_1021
/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm -y conf/php-fpm.conf -c lanes/php.ini -D
/opt/nginx-1.30.1/sbin/nginx -p $PWD -c conf/nginx.conf
python3 bin/battery.py p1 p2 p3 p4 p5 p6 p7     # lanes
python3 bin/headroom.py 5                        # boundary, 5 trials/point
python3 bin/headroom2.py                         # amplification + token contribution
python3 bin/capture.py                           # wire transcripts
python3 bin/make_table.py                        # results/table.md
```

## 3. The arm

Generator: `bin/narm.py:arm_body()` — byte-shape identical to the stock receipts
(`/tmp/opencode/mitigation_1021/scripts/http_arm.py`,
`/home/davide/ailocal/php2slop/tool/modules/arm.py`):

```
--NATIVEOUTPUTEXACT  field PHPSESSID=armsess1021
--NATIVEOUTPUTEXACT  field PHP_SESSION_UPLOAD_PROGRESS=MMM
--NATIVEOUTPUTEXACT  20 file parts: filename "F"*9, then "F"*262144 ×19, content "X"
--NATIVEOUTPUTEXACT--
```

`len(body) == 4_983_500` is asserted by the driver.  Attacker-chosen session id
travels in `Cookie: PHPSESSID=...` (`session.use_only_cookies=1`).

Control reproduction (N0, 8 MiB) — FPM error log:

```
PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted
(tried to allocate 266240 bytes) in Unknown on line 0
```

Client sees:

```http
HTTP/1.1 200 OK
X-Powered-By: PHP/8.5.10
Transfer-Encoding: chunked

0
```

i.e. **200 + empty body**.  The 266240 B request is exactly one
`262144 + 4096` filename buffer, i.e. the multipart header parser.

## 4. Lane results

Full per-scenario rows: `results/table.md` and `results/lanes.jsonl`.
"PHP reached" = an FPM access line exists **or** a fatal was logged (FPM does
not write an access line for a request that dies pre-RINIT, so the error log is
the authoritative signal).

### A. N0 control — nginx → FPM, 8 MiB, no cap

| scenario | body B | HTTP | PHP fatal | OOM limit / tried |
|---|---:|---:|---|---|
| stock arm (token present) | 4,983,500 | 200 + empty | **yes** | 8,388,608 / 266,240 |
| arm with **no** upload-progress field | 4,983,404 | 200 + empty | **yes** | 8,388,608 / 266,240 |
| 4.98 MB body, 20 parts, **short filenames**, 249 KB content each | 4,980,659 | 200 + script output | no | — |
| 8 giant-filename parts | 1,836,238 | 200 + empty | **yes** | 8,388,608 / 1,314,816 |
| 8 giant-filename parts ×280 KB | 1,961,230 | 200 + empty | **yes** | 8,388,608 / 1,122,304 |

Two things fall out immediately:

1. **The OOM does not need the upload-progress field.**  The no-token body
   produces the same fatal — so a rule that blocks the token cannot stop this
   arm (section 6).
2. **The OOM is driven by filename bytes, not body bytes.**  A 4.98 MB body
   whose filenames are short completes normally at 8 MiB; a 1.84 MB body made
   of giant filenames dies.

### B. N1 — `client_max_body_size 2m` + `memory_limit=128M`

| scenario | body B | HTTP | PHP reached | PHP fatal |
|---|---:|---:|---|---|
| stock arm | 4,983,500 | **413** | **NO** | no |
| stock arm, `Transfer-Encoding: chunked` | 4,983,500 | **413** | **NO** | no |
| 8 giant-filename parts | 1,836,238 | 200 | yes | no |
| 8 × 280 KB filenames | 1,961,230 | 200 | yes | no |
| legit 1280 B upload (`upload.php`) | 1,435 | 200, `ok:true`, stored byte-identical | yes | no |

Proof PHP never parsed the 413 request (unique sid, `results/n1_413_php_never_saw.json`):

```json
{"status": 413, "body_len": 4983508, "new_session_files": [],
 "fpm_error_log_bytes_delta": 0, "fpm_access_log_bytes_delta": 0}
```

nginx logged `[error] ... client intended to send too large body: 4983500 bytes`
(and, for the chunked attempt, `client intended to send too large chunked body:
2097152+65536 bytes`, i.e. chunked bodies are counted against the same cap).
The under-cap variant completes and lists its 8 files in the script output, and
the session file gets `upload_progress` data (cleanup=0).

### C. N2 — cap alone (`2m`), no headroom (`8M`)

| scenario | body B | HTTP | PHP fatal | OOM limit / tried |
|---|---:|---:|---|---|
| stock arm | 4,983,500 | **413** | no | — |
| 6 giant-filename parts | 1,311,696 | 200 + script output | **yes (shutdown-phase)** | 8,388,608 / 1,052,672 |
| 8 giant-filename parts | 1,836,238 | 200 + empty | **yes** | 8,388,608 / 266,240 |
| 8 × 280 KB filenames | 1,961,230 | 200 + empty | **yes** | 8,388,608 / 1,122,304 |
| **at cap** (8 parts × 298 KB filenames, under 2 MiB) | **2,090,030** | 200 + empty | **yes 3/3** | 8,388,608 / 1,196,032 |

So the 2 MiB edge cap **does not** protect an 8 MiB PHP: every filename-dense
body above ~1.3 MB either dies in the parser or OOMs during
`session_start()`/shutdown (the 6-part row returned output **and** logged an
OOM).  This is the boundary data behind the headroom rule.

### D. N3 — protocol-token block

**Core nginx cannot inspect request bodies.**  This build has no
modsecurity/njs/lua, and `$request_body` is not populated at rewrite time, so

```nginx
location ~ \.php$ {
    if ($request_body ~ "PHP_SESSION_UPLOAD_PROGRESS") { return 403; }
    ...
}
```

was measured to **never fire**: a small multipart body containing the token got
`200` and PHP parsed it (`results/transcripts/200_n3core_if_request_body.http`,
`sessions/shape` shows upload-progress data written).

To still measure what a token rule would buy, `bin/shim.py` implements the rule
"reject any body containing the literal `PHP_SESSION_UPLOAD_PROGRESS`" as a
transparent forwarder in front of the same FPM lane (403 → PHP never reached;
pass → forwarded byte-identically to 29006/`memory_limit=8M`).  **It is a
reference rule, not nginx.**

| case | HTTP | PHP reached | result |
|---|---:|---|---|
| stock arm through the rule | **403** | no (0 FPM log bytes) | rule works on the literal |
| tiny JSON-ish multipart with the field | **403** | no | rule is content-only, ignores size |
| legit upload, ordinary filename | 200 | yes | passes |
| legit upload whose *filename* contains `PHP_SESSION_UPLOAD_PROGRESS` | **403** | no | **false positive** |
| arm **without** the field | 200 | yes | **OOM 8M/266240 — the rule is irrelevant to this arm** |
| arm with field renamed `UPGX` (docroot `.user.ini`) | 200 | yes | **OOM 8M/266240 + upload-progress session written** |
| arm with the field **after** the file parts, rule scans first 8 KiB | 200 | yes | **OOM 8M/266240** |
| arm with default field in the renamed dir | 403 | no | false positive (PHP would have ignored it there) |
| arm with `%50HP_SESSION_UPLOAD_PROGRESS` | 200 | yes | **OOM 8M/266240** (rule misses; PHP also ignores it) |

Detail: the token enum is not what makes the arm reach the OOM; it is an
**amplifier**.  At 8 MiB, 8 giant-filename parts fatal **4/4 with** the token
and **0/4 without**; 12 parts fatal 4/4 with and 0/4 without (up to 12 MiB).
At 20 parts both variants fatal at 8/10/12 MiB.  The amplifier is visible in the
session payload: at 128 MiB the arm writes a **4,984,996 B**
`sess_armsess1021` — the upload-progress array serialises every 262144-byte
filename.

### E. N4 — rate / connection limits

`limit_req_zone $binary_remote_addr zone=n4post:1m rate=10r/m;`
`limit_req zone=n4post burst=5 nodelay; limit_req_status 429;`
`limit_conn_zone $binary_remote_addr zone=n4conn:1m; limit_conn n4conn 5; limit_conn_status 429;`

| test | result |
|---|---|
| fresh zone, back-to-back small POSTs | requests 1-6 → 200, request 7 → **429** (`excess: 5.824`, `excess: 6.000` in `logs/n4.error.log`) |
| 10-POST burst after 2 earlier requests (lane battery) | 5 × 200, then **5 × 429** |
| 10 concurrent 2 s requests (`limit_conn` only, `/sleep.php`) | **5 × 200, 5 × 429**, wall 2.0 s (`results/n4_limit_conn.json`) |
| 4,983,500 B arm sent while the zone was exhausted | **413**, not 429 |
| small POST immediately afterwards | 429 |

So `client_max_body_size` is enforced **before** `limit_req` (measured), and
the rate limiter does not slow a single arm request at all — it only taxes mass
attempts.

### F. Sanity

* `/probe.php` on N1: `memory_limit=128M`, `post_max_size=8M`,
  `session.upload_progress.enabled=1`, `name=PHP_SESSION_UPLOAD_PROGRESS`.
  On N0: `memory_limit=8M`.
* legit 1280 B upload through the edge: 200, `ok:true`, stored file sha256
  `067c1e7f0588be06…`, identical to the sent payload (`LEGIT`*256).
* nginx error log: 413 (`client intended to send too large body: 4983500`),
  429 (`limiting requests … zone "n4post"`), 429
  (`limiting connections … zone "n4conn"`).  403 comes from the reference shim
  (`results/shim_full.log`), not from nginx.

## 5. Headroom rule (derived from B and C)

Method: `bin/headroom.py` and `bin/headroom2.py` send the same arm shapes to a
pool with `pm.max_requests=1` (a **fresh worker per request**) and set
`memory_limit` per request through `fastcgi_param PHP_VALUE` /
`X-PHP-Mem`; a fatal is attributed via the FPM error-log delta, not via HTTP
status.  Each point is 3-5 trials.

| body (filename bytes) | max limit **with** fatal | min limit with 0 fatal | ratio |
|---:|---:|---:|---:|
| 459,982 | 3,145,728 (3M) | 4,194,304 (4M) | 9.1 |
| 918,734 | 5,242,880 (5M) | 6,291,456 (6M) | 6.9 |
| 1,836,238 | 11,534,336 (11M) | 12,582,912 (12M) | 6.9 |
| 2,090,030 (2 MiB cap) | 8,388,608 (8M) | 12,582,912 (12M) | 6.0 |
| 3,671,246 | 24,117,248 (23M) | 25,165,824 (24M) | 6.9 |
| 4,983,500 (stock arm) | 28,311,552 (27M) | 29,360,128 (28M) | 5.9 |

Linear fit over the 0.9-3.7 MB points: `peak ≈ 6.85 × filename_bytes + 0`; the
smallest point shows a ~1 MiB floor and the 4.98 MB point comes out at 5.9×.
Conservative engineering form:

```
memory_limit  ≥  6.5 × client_max_body_size + 1 MiB          (measured k = 5.9-6.9)
recommended   ≥  8   × client_max_body_size                  (round up, add margin)
```

Why the cap is the right variable: a multipart part header can be ~100 %
filename bytes (`filename="F"*N`), so for a given `client_max_body_size C` the
attacker can put ~C bytes of filename into the body, and the parser needs ~6.5×
that.  Content bytes are cheap: the 4.98 MB short-filename body completed at
8 MiB.

Inversion table (measured unless marked):

| `client_max_body_size` | minimum `memory_limit` | recommended |
|---:|---:|---:|
| 1m | ~7.2M (0.92 MB needed 6M) | **8M** |
| 2m | **12M** (2.09 MB body: 8M fatal 3/3, 12M clean) | **16M** |
| 4m | **24M** (3.67 MB body) | **32M** |
| 8m | ~52M (extrapolated from k=6.5) | **64M** |

Consequences for N2: `cap=2m, memory_limit=8M` is **outside** the rule
(8 < 13.5) and fails in practice.  If `memory_limit` must stay at 8M, the cap
has to come down to **1m** — not because 2m is large, but because 2 MiB of
filename bytes needs ~13 MiB of parser memory.

### Non-obvious boundary behaviour (important for monitoring)

* A pre-RINIT fatal returns **HTTP 200 with an empty body** (N0 stock arm).
  Do not use response codes to detect this.
* At the boundary the failure moves: 7 parts at 8 MiB produced
  `Fatal error: Allowed memory size … in …/index.php on line 4`
  (`session_start()`), i.e. after the parser had already succeeded.
* Some requests print full script output **and** log an OOM at shutdown
  (6 parts at 8 MiB: 0/5 on an already-warm worker, but 1/4 in a sequence whose
  first request followed a worker start, and 1/1 in the N2 lane, which had just
  been through two fatals).  A 200 with a body is therefore not proof that the
  worker stayed healthy.
* `tried to allocate` tracks the current filename aggregation: 266,240
  (1 × 262144 + 4096), 1,052,672 (4 × 262144 + 4096), 1,314,816
  (5 × 262144 + 4096), 1,196,032, 1,122,304 …

## 6. Token rule: what it blocks, and how it is bypassed

### 6.1 It cannot be built in this nginx

* `nginx -V` → only `--with-http_ssl_module`; no modules directory; the only
  `ngx_http_js_module.so` on disk belongs to a different (Docker-layer) nginx
  build and is not loadable here.
* Core nginx has no body-inspection directive.  `$request_body` is empty in the
  rewrite phase (body not read yet), so
  `if ($request_body ~ "PHP_SESSION_UPLOAD_PROGRESS")` **measured 200** on a
  body that contains the token.
* Closest core-only approximation: size cap + rate/connection limits (lanes
  N1/N4).  `auth_request` cannot help either (subrequests carry no body).

### 6.2 What a real token rule does (reference shim, measured)

It blocks the literal token and only the literal token: full arm → 403, tiny
token body → 403, legit upload → 200, legit file *named* with the token → 403
(false positive).

### 6.3 Bypass / evasion conditions

| # | condition | measured? | effect |
|---|---|---|---|
| 1 | **Omit the field entirely** — the OOM does not need it | **yes**: 4,983,404 B no-token body → 8 MiB fatal 266,240 | complete bypass, rule never involved |
| 2 | **Rename the field** via a writable docroot `.user.ini` (`session.upload_progress.name=UPGX`; the setting is PERDIR) | **yes**: field `UPGX` → forwarded → 8 MiB fatal + upload-progress session written | complete bypass of a literal rule |
| 3 | **Put the field after the bulk** and rely on a body-prefix inspection window | **yes**: 8 KiB window → forwarded → fatal (field at offset 4,983,440) | bypass of prefix-limited WAF inspection |
| 4 | **Quoting variants**: PHP accepts `name="TOKEN"`, `name=TOKEN` (unquoted) and `name='TOKEN'` (single quotes) | **yes**: all three produce upload-progress session data | a regex that requires double quotes is bypassed; a substring rule is not |
| 5 | **Case change** (`php_session_upload_progress`) | **yes**: PHP ignores it (no upload-progress data) | breaks the *trigger*, but **not the OOM** (token not required) |
| 6 | **Percent-encoding** (`%50HP_…`) | **yes**: PHP does not URL-decode multipart field names (no upload-progress data); arm still OOMs | not a bypass for the session-poisoning goal; irrelevant to the OOM |
| 7 | Chunked transfer / rules that assume `Content-Length` | partially: nginx applies `client_max_body_size` to chunked (**413** measured); my shim de-chunks (token still matched) | deployment caveat: a body-inspecting rule that does not de-chunk can be evaded; not measured against a real WAF here |
| 8 | Duplicate/extra fields, multipart boundary tricks | not measured | unproven; do not rely on either direction |

Note on #1: the token is an **amplifier**, not a gate.  With it, 8- and 12-part
bodies fatal at 8-10 MiB; without it they survive up to 12 MiB.  Removing the
token lowers the memory need but does not eliminate the filename-driven parser
cost (20 parts fatal either way at 8-12 MiB, and the 2.09 MB at-cap body is
filename-dense regardless).

## 7. What the edge can and cannot do

* **Prevents reaching PHP**: `client_max_body_size` at the reverse proxy,
  correctly sized against `memory_limit`, answers the arm with 413 before a
  single byte reaches FPM (0 bytes in both FPM logs, no session file).  This is
  the only lane that actually keeps the buggy parser away from the payload.
* **Raises cost**: `limit_req` (10r/m, burst 5) and `limit_conn` (5) turn mass
  attempts into 429s (measured 5/10 and 5/10) but leave a single request every
  6 s untouched.  They are signature-independent and cheap.
* **Does not fix anything**: the parser still over-allocates and still corrupts
  the worker when a filename-dense body arrives under the cap and above the
  headroom.  A token rule is security theatre for this arm (bypass #1), and
  cannot even be expressed in this nginx build.
* **Explicit statement**: edge mitigation prevents reaching PHP or raises the
  cost of exploitation; it is **not** a substitute for the patch.  The fix has
  to be in the multipart parser (bounded filename/header handling, no
  pre-RINIT allocation proportional to attacker-controlled header length); the
  edge only buys time and reduces exposure.

## 8. Artifacts

| path | contents |
|---|---|
| `conf/nginx.conf`, `conf/php-fpm.conf`, `lanes/php.ini` | all lane configs |
| `docroot/` | index.php, upload.php, probe.php, sleep.php, `tokrename/` + `.user.ini` |
| `results/table.md` | every scenario, rendered from `lanes.jsonl` |
| `results/lanes.jsonl` | 48 structured rows (status, FPM log deltas, sessions, OOM limit/tried) |
| `results/headroom.json`, `results/headroom2.json` | fresh/warm trials, token contribution, min-safe-limit grid |
| `results/n1_413_php_never_saw.json` | 413 with zero FPM log/session footprint |
| `results/n4_limit_conn.json` | 10 concurrent → 5×200 / 5×429, wall 2.0 s |
| `results/shim_full.log`, `results/shim_8k.log` | token-rule decisions incl. match offsets |
| `results/transcripts/*.http` (+ `.meta.json`) | exact wire responses: 413, 403, 429, 200-empty, 200-ok, 200-not-blocked |
| `results/lanes_run1_preliminary.jsonl` | first pass (before log-flush fix); superseded, kept for provenance |
| `logs/` | nginx and FPM access/error logs per lane |

## 9. Services / shutdown

Started for this work (loopback only):

* `/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm` master
  (pid file `run/php-fpm.pid`) — pools n0,n1,n2,n3,n4,shape,sweep,fresh,warm
* `/opt/nginx-1.30.1/sbin/nginx` master (pid file `run/nginx.pid`) — servers
  29000-29011
* two `bin/shim.py` processes (ports 29003, 29008)

Stop:

```bash
/opt/nginx-1.30.1/sbin/nginx -p /tmp/opencode/nginx_mitigation_1021 -c conf/nginx.conf -s quit
kill $(cat /tmp/opencode/nginx_mitigation_1021/run/php-fpm.pid)
pkill -f 'bin/shim.py --listen 2900[38]'
```

PIDs at end of run are recorded in `results/pids.txt`.
