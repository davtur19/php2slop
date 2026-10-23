# PHP-FPM 200-parallel saturation / "fast slowloris" — local lab report

- Date: 2026-10-23 (UTC), lab run `fpm_saturation_20261023T081008Z`
- Target: stock `php:8.4.26-fpm` (`pm=dynamic`, `pm.max_children=5`) behind stock `nginx:alpine` (1.31.8)
- Scope: isolated Docker lab only. Shared/active FPM labs (`b2fpm8426`, `b2fpm8511`, `b1mw8426`, `b1ctl8426`) were **not** touched and were **not** restarted. No push/commit/PR. No existing report was edited.
- Question: *For FPM, does spamming 200 parallel requests / a fast slowloris occupy all workers and improve the 9bie producer→consumer timing (worker affinity), or does it only queue/DoS?*
- Answer in one line: **Stock = NO.** 200 complete parallel requests only fill `pm.max_children` transiently and queue the rest; slow headers/bodies never reach FPM with stock `fastcgi_request_buffering on`. With the **non-stock** `fastcgi_request_buffering off` diagnostic, slow bodies **do** hold workers (up to `max_children`) and can queue/DoS the pool, but they still give **no exploit improvement**: the producer always dies (`exit 70`) and the consumer runs in a freshly respawned worker.

---

## 1. Verdict details

| Claim | Stock config (defaults) | Non-stock diagnostic (`fastcgi_request_buffering off`, 64m body limit) |
|---|---|---|
| 200 complete parallel requests occupy **all** workers | Transiently, up to `pm.max_children` (5); all excess sits in the FPM listen queue (high-water: 48 on stock5 mixed, 123 on diag5 mixed; 191 in the pool-50 slow-body test) | Same (completion-based occupancy only) |
| Slow headers (incomplete request line/headers) hold FPM workers | **No.** nginx holds the connections; FPM sees 0 of 200 | **No.** Same; nginx must parse complete headers before opening FastCGI |
| Slow bodies (< body limit) hold FPM workers | **No.** nginx buffers the body to temp files before contacting FPM; 200 fds / ~114 MB buffered, FPM active = status probe only | **Yes.** Workers block reading the body: max active = 5, listen queue 209, fast probes timeout at 5 s |
| Improves producer→consumer timing / affinity | **No.** Prime can pin the next request to the single free worker (pid-proven), but the A-body producer `exit 70`s that worker; the consumer is served by a new pid (fresh address space) | Same: pinning is possible via slow bodies, producer still dies, consumer is a fresh worker |
| Same `PHPSESSID` helps | File-session **serialization** only. 5×`session_start+sleep 2s` = 10.01 s wall vs 2.79 s with distinct SIDs. A same-SID wave can occupy the pool (a stock DoS if such an endpoint exists), but it spreads requests over different workers, i.e. it is the opposite of affinity. Session *file* state persists (upload progress), the in-process `PS(id)` does not | Same |
| Crash/UAF/RCE | **0** signals, **0** SIGSEGV/heap corruption, **0** RCE. 961 nginx 502 = 961 FPM `exit 70` (all code 70), 0 504 | Same |
| Pool 50 vs 5 | 50 raises the occupancy ceiling/queue absorption but 200 parallel A-bodies still produce 200 failures / 200 exits. No success-rate change; latency effect is flat/mixed | Same |

**Config-dependent statements** are marked **[NON-STOCK]**: `fastcgi_request_buffering off`, `client_max_body_size 64m`, `fastcgi_read_timeout 300s`, and the `pm.max_children=50` control. Everything not marked is stock defaults.

---

## 2. Lab topology and exact configuration

Network `fsat20261023T081008Z`, subnet `10.99.77.0/24`.

| Container | Image | Role / published port |
|---|---|---|
| `fsat-fpm5` | `php:8.4.26-fpm` (`sha256:9f0837de65e3c405aca0d0c00a1a54d0fce759d2d08f2742387c1ed4a711283b`) | stock pool, `pm.max_children=5`, FastCGI 9000, status 9001 |
| `fsat-fpm50` | same image | control pool, `pm.max_children=50` |
| `fsat-web-stock5` | `nginx:alpine` 1.31.8 (`sha256:3d6cab9c2941df2441024a2f02a65ebe1b8916c3cbe7b9527f62627accea8004`) | `127.0.0.1:18810`, stock: 1m body limit, buffering on (default) |
| `fsat-web-diag5` | nginx | `18811`, **[NON-STOCK]** `client_max_body_size 64m`, buffering on |
| `fsat-web-nobuf5` | nginx | `18812`, **[NON-STOCK]** 64m, `fastcgi_request_buffering off` |
| `fsat-web-stock50` | nginx | `18814`, pool 50, stock 1m, buffering on |
| `fsat-web-diag50` | nginx | `18813`, pool 50, 64m, buffering on |
| `fsat-web-nobuf50` | nginx | `18815`, pool 50, 64m, buffering off |
| status | `fsat-fpm5`: `http://127.0.0.1:18822/status?json`; `fsat-fpm50`: `18825/status?json` | mapped via nginx 8082 → FPM 9000 |

### 2.1 FPM pools (exact)

`conf/fpm/www5.conf` (stock, these are the PHP image defaults):

```ini
[www]
user = www-data
group = www-data
listen = 0.0.0.0:9000
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 0
pm.status_path = /status
ping.path = /ping
access.log = /var/log/fpm/access.log
access.format = "%R %t "%m %r" %s pid=%p dur=%d"
slowlog = /var/log/fpm/slow.log
request_slowlog_timeout = 10s
request_terminate_timeout = 0
catch_workers_output = yes
decorate_workers_output = no
```

`conf/fpm/www50.conf` differs only in:

```ini
pm.max_children = 50
pm.start_servers = 10
pm.min_spare_servers = 5
pm.max_spare_servers = 25
```

PHP config: stock `php.ini-production`, `display_errors=Off`, `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`, `max_execution_time=30`, `session.save_handler=files`, `session.save_path=` (→ `/tmp`), `session.upload_progress.enabled=1`. Verified at runtime via `/probe.php`.

### 2.2 nginx

Stock fronts use the stock default `client_max_body_size 1m` and the stock default `fastcgi_request_buffering on` (the directive is simply absent). Diagnostic fronts set `client_max_body_size 64m` and/or `fastcgi_request_buffering off` inside the PHP location. All fronts use:

```nginx
fastcgi_read_timeout 300;   # non-default (default 60s); no test exceeded 20s
client_body_temp_path /var/cache/nginx/client_temp;
```

`client_body_temp_path` temp files are created and **immediately unlinked** by nginx; directory `du` is therefore useless. Buffered bytes were measured by scanning the nginx worker FDs (`/proc/PID/fd` as user `nginx`, `stat -Lc %s`), see `lab/tempfds.sh`.

ASLR `kernel.randomize_va_space = 2`. Host: Linux, local loopback.

### 2.3 Request bodies

`bodies/SHA256SUMS`:

```
8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6  a1.bin   1,060,211 B
7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236  a2.bin     279,369 B
b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2  b1.bin  33,128,677 B
```

`a1`/`a2` are 9bie A-stage producer bodies (A2 uses `PHPSESSID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, 32×`a`). `b1` is the 33 MB fill body; it is **not** the stage-3 consumer/RCE body. A2 always OOMs PHP at request startup:

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
WARNING: [pool www] child N exited with code 70
```

nginx observes this as **502 Bad Gateway**. A1 behaves the same on a 64m front (1,060,211 B > stock 1m). B1 exceeds `post_max_size=8M` and returns HTTP 200 with `post=0` on the 64m fronts; stock 1m rejects it with 413.

---

## 3. Sequential baseline (no concurrency)

| Test | Front | n | Result |
|---|---|---|---|
| A2 | stock5 | 10 | **10×502**, 10 child `exit 70`, p50 0.019 s |
| A1 | stock5 | 3 | 3×413 (1 MiB limit) |
| B1 | stock5 | 3 | 3×413 (1 MiB limit) |
| A1 | diag5 | 2 | 2×502, 2 exits |
| A2 | diag5 | 2 | 2×502, 2 exits |
| B1 | diag5 | 2 | 2×200 (`post=0`) |

The producer outcome is deterministic and does not improve with concurrency.

---

## 4. T1 — 200 parallel **complete** mixed A1/A2/B1 requests

Mix: `a1:67, a2:67, b1:66` (200 total). `scripts/lab.py burst`.

| Front | Pool | Codes | FPM `exit 70` | p50 / p95 / max | Peak active | Listen-queue high-water |
|---|---|---|---|---|---|---|
| stock5 (1m, buffering on) | 5 | **133×413 + 67×502** | **67** | 0.664 / 1.149 / 1.240 s | 2 (sampled) | **48** |
| diag5 (64m, buffering on) **[NON-STOCK limit]** | 5 | **134×502 + 66×200** | **134** | 2.032 / 3.388 / 3.599 s | **5** | **123** |

(The 200-mixed runs on the pool-50 fronts are in §8.4; they were executed later in the session.)

Notes:
- 413 = A1+B1 rejected at nginx header parse because `Content-Length > 1m`; the body is never read.
- 502 = A1/A2 startup OOM; **every 502 corresponds to exactly one FPM `exit 70`** (global audit: 961 = 961).
- 200 = B1 reaching PHP on 64m fronts, immediately rejected by `post_max_size=8M` (`post=0`, no upload).
- 200 parallel is **slower** than sequential (A2 p50 0.019 s sequential vs 1.80 s at n=200 on pool 5), because requests queue in the FPM listen backlog. No success/UAF improvement.

### 4.1 The 200-parallel status samples (pool 5)

`evidence/T1_diag5_200/status.jsonl` during the burst:

```
listen queue 0 → 36, max listen queue 123, active processes 5, idle 0,
total processes 5, max children reached 1
```

`evidence/T1_stock5_200/status.jsonl`:

```
max listen queue 48, active 2, total 2
```

The status page is served **by a worker of the same pool**, so its own samples consume a worker and time out when the pool is saturated (visible in T3).

---

## 5. T2 — buffering **on** (stock): slow headers / slow bodies / huge CL / chunked

Harness: `scripts/slowtest.sh NAME PORT CONTAINER MODE CL RATE HOLD N PATH [finish]`.
Slow clients send the header set, then trickle body bytes at `RATE` B/s for `HOLD` seconds; `finish` additionally sends the remainder and reads the response.

| Test | Front | n | Body | FPM active | nginx temp fds / buffered | Fast-probe latency | PHP saw body? | nginx codes | exits |
|---|---|---|---|---|---|---|---|---|---|
| slow headers | stock5 | 200 | none (hold 20 s) | **1–2 (status only)** | 0 / 0 | p50 1.1 ms, max 8 ms | **0** | 200×400 | 0 |
| slow body | stock5 | 200 | CL 900,000 (30 KB/s, 20 s) | **1 (status only)** | **200 / 114,272,713 B** | p50 1.1 ms, max 21 ms | **0** | 200×400 | 0 |
| huge CL | stock5 | 200 | CL 8,000,000 (>1 MiB) | 1 | 0 / 0 | p50 1.4 ms, max 22 ms | **0** | 200×413 (immediate) | 0 |
| huge CL | diag5 / nobuf5 | 1 each | CL 100,000,000 (>64 MiB) | — | 0 / 0 | — | 0 | 413 in **0.5–0.6 ms** | 0 |
| chunked | diag5 | 200 | chunked, 100 KB/s, 15 s | **1 (status only)** | **200 / 293,560,911 B** | p50 1.1 ms, max 37 ms | **0** | 200×400 | 0 |
| complete slow body | diag5 | 20 | CL 2,000,000 (100 KB/s, 20 s), `finish` | **1** | 20 / 38,579,608 B | p50 1.1 ms | **20, only after completion** | 200×200 | 0 |

Key raw evidence:

- Stock slow body `evidence/T2_stock5_slowbody/`: `temp_fds_max=200`, `temp_buffered_max_bytes=114272713`, `reqlog entries: 0`, `accepted_conn_delta` = probes+status only, `max active processes` unchanged, `probe p50=0.001`.
- Complete body (`evidence/T2_diag5_finish/`): nginx `rt≈20.05 s`, `urt≈0.017–0.019 s`, 20 `/logprobe` entries only after the 20 s transfer, `200×20`. This is the direct proof that nginx waited for the full body before opening FastCGI.
- Huge `Content-Length` is checked against `client_max_body_size` while parsing the headers: 8 MB on stock → 413 instantly (200×413, no body read); 100 MB on a 64m front → 413 in <1 ms.
- Temp files are unlinked at creation; the buffered bytes above are exact open-FD sizes, not directory `du`.

**Stock conclusion:** a slow body/slowloris never reaches FPM. nginx is the absorber (memory/disk-backed temp files, one per connection); FPM occupancy stays at the status probe.

---

## 6. T3 — buffering **off** (non-stock diagnostic): worker occupancy

| Test | Front | n | Body | FPM peak active | Listen queue | Status probe | Fast probe | PHP saw body | nginx | exits |
|---|---|---|---|---|---|---|---|---|---|---|
| slow headers | nobuf5 | 200 | hold 20 s | **1–2 (status only)** | 0 | ok | p50 1.1 ms | 0 | 400×200 | 0 |
| slow body | nobuf5 | 200 | CL 2,000,000, 100 KB/s, 20 s | **5 (all workers)** | **209** | **1 ok / 9 timeout** | **3/3 timeout at 5.00 s** | **200 (only at end)** | 400×200 + 499×4 | 0 |
| huge CL, > `post_max_size` | nobuf5 | 20 | CL 20,000,000 (100 KB/s, 20 s) | **5** | 29 after test | **0 ok / 10 timeout** | **3/3 timeout** | **20 (only at end)** | 400×20 | 0 |
| chunked (no CL) | nobuf5 | 50 | chunked, 100 KB/s, 20 s | **1–3 (no occupancy)** | 0 | ok | p50 1.1 ms | **50 immediately** | 200×50 | 0 |
| slow body | nobuf50 | 200 | CL 2,000,000, 100 KB/s, 20 s | **50** | **191** | **1 ok / 10 timeout** | **3/4 timeout** | 200 | 400×200 + 499×4 | 0 |
| slow body | nobuf50 | 50 | CL 2,000,000, 100 KB/s, 20 s | **50** | 14 after test | 10 timeouts during ramp | **3/5 timeout** (dynamic ramp) | 50 | 400×50 | 0 |

"FPM peak active" is the in-test sample, an after-snapshot `max active processes`, or an increment of `max children reached` (which ticks when the pool hits `max_children`). The status endpoint is served by a worker of the same pool, so it competes with the load and times out under saturation.

Raw evidence and interpretation:

- **`evidence/T3_nobuf5_slowbody/`**: status before/after shows `max active processes 5`, `max listen queue 123 → 209`, `listen queue 209` in the after snapshot; probe JSONL is 3 requests, all `TimeoutError` at ~5.004 s; `reqlog entries: 200`. nginx access log for the slow bodies: `rt=20.18 urt=20.18` — the upstream (FPM worker) was attached for the full 20 s, i.e. it was blocked reading the request body. Recovery: listen queue dropped to 0 within 3 s after the clients closed, probes returned to 0.8 ms.
- **Huge CL > `post_max_size` (20 MB > 8 MB)** still holds the worker for the full trickle (`rt=urt≈20.07`, 20 reqlog entries only at end, status/probes timed out). So `post_max_size` does **not** shield the pool when buffering is off; FPM/PHP drains the request body before the worker is released. This is a diagnostic-side nuance, not a stock behavior.
- **Chunked (no `Content-Length`)** is the exception: PHP sees `CONTENT_LENGTH` absent → `content_length=0`, runs the script immediately (`urt≈0.02 s`, 50 reqlog entries at once), while nginx keeps the client connection open (`rt≈20.1 s`) and discards the chunks. No worker occupancy. (With buffering **on**, chunked bodies sit in nginx temp files instead: 200 fds / 293 MB, FPM untouched.)
- Pool 50: `max active processes 50`, `max listen queue 191`, status timeouts, probes time out during the dynamic ramp. The dynamic pool starts 10 workers and grows; the first samples show `active=2`, then 50. `pm.max_children=50` raises the ceiling but not the exploit outcome.
- `slow requests = 0` in all tests: FPM's slowlog measures script execution, not the time spent reading a request body. Do not use it as an occupancy indicator.

---

## 7. T4 — prime → trigger, worker affinity, same session

### 7.1 Prime with a blocking app endpoint (stock5, buffering on)

Prime: 4 concurrent `GET /sleep.php?s=15` (each occupies a worker for 15 s).
State while primed: `active processes 4`, `idle 0`, `listen queue 1`, total 4 (the status probe uses/queues a worker).

| Measurement | Result |
|---|---|
| Sleeper workers (pids) | 435, 467, 469, 478 |
| 10 sequential `GET /pid.php` | **all 10 → pid 479** (the single free worker) |
| A2 producer while primed | **502 in 0.057 s**, child 479 `exited with code 70` |
| 5 sequential probes after A2 | **all 5 → pid 480** (new respawned worker) |
| Same `PHPSESSID=32×a` after A2 | session file `sess_aaaa…` readable from another worker; contains `upload_progress` state (`done=false`), 515 B at first, 6354 B later |

Evidence: `evidence/T4a_stock_prime/` (`probes_primed_pids.txt`, `probes_after_a2_pids.txt`, `sleep2_*.out`, `a2_while_primed2.json`), FPM log line `child 479 exited with code 70`.

**Interpretation:** with exactly one idle worker, FPM's accept queue dispatches all new requests to that worker (FIFO). This is deterministic routing, not persistent affinity. The producer is dispatched to the same single free worker and kills it. The next request is served by a **new process** (480). No consumer can reuse the producer's memory state; the session *file* survives, but that is ordinary shared storage, not the in-process `PS(id)`/upload state that the bug needs.

### 7.2 Prime with slow bodies (nobuf5, non-stock)

4 slow bodies (`CL 5,000,000`, 50 KB/s) → `active 5 / total 5`, `idle 0`.

| Measurement | Result |
|---|---|
| 10 `GET /pid.php` | **all 10 → pid 482** |
| A2 while 4 bodies held | **502**, child 482 `exited with code 70` |
| 5 probes after A2 | **all 5 → pid 483** |

Evidence: `evidence/T4b_nobuf_prime/`. Same conclusion, reached through the config-dependent slow-body vector.

### 7.3 Same `PHPSESSID` / session file lock

| Test | Same SID | Distinct SIDs |
|---|---|---|
| 200 parallel `sessprobe.php` | 200×200, p50 **19.3 ms**, p95 26 ms, max 27 ms | 200×200, p50 **9.9 ms**, p95 17.1 ms, max 17.5 ms |
| 5× `sesssleep.php?s=2` | wall **10.01 s** (serialized), n increments 1→5, pids 481/480/483/484/485 | wall **2.79 s**, all n=1, pids 486/481/483/484/485 |
| 10× `sesssleep.php?s=1` | status query **empty/timeout** at t+0.8 s; normal probe **2.19 s** (vs 0.0008 s); A2 delayed to **4.01 s**, still 502 + exit 70 | — |

**Interpretation:** PHP's file session handler serializes requests sharing a SID (flock). Same-SID requests therefore queue *inside* `session_start`, each holding a worker while it waits. A wave of same-SID lock-holding requests can occupy the whole pool — a **stock-config DoS primitive if the application has any endpoint that holds a session lock for non-trivial time** (very common: `session_start` + DB/API work). It does not give affinity: the lock holder and waiters are different workers, and the serialization actively scatters requests. It also gives no producer memory reuse. Session file contents (`upload_progress` with `done=false`, 6354 B after crashed A2s) survive the worker death and are readable across workers, which is exactly why they are *not* a UAF/`PS(id)` signal.

---

## 8. T6 — pool 5 vs 50, concurrency 5/10/50/200

### 8.1 A2 producer bursts

| n | pool 5: codes / exits / p50 / p95 | pool 50: codes / exits / p50 / p95 |
|---|---|---|
| 5 | 5×502 / 5 / **0.062 s** / 0.135 s | 5×502 / 5 / **0.069 s** / 0.080 s |
| 10 | 10×502 / 10 / **0.143 s** / 0.281 s | 10×502 / 10 / **0.128 s** / 0.142 s |
| 50 | 50×502 / 50 / **0.525 s** / 0.958 s | 50×502 / 50 / **0.579 s** / 0.819 s |
| 200 | 200×502 / 200 / **1.802 s** / 3.170 s | 200×502 / 200 / **1.332 s** / 2.319 s |

Every request is 502 and every 502 is one `exit 70`. Pool 50 only shaves the 200-parallel p50 (1.80 → 1.33 s); success rate stays zero.

### 8.2 Fast GET bursts (control: normal requests never saturate)

| n | stock5 (pool 5) p50 / p95 / max | stock50 (pool 50) p50 / p95 / max |
|---|---|---|
| 5 | 1.2 / 1.3 / 1.3 ms | 17.0 / 17.6 / 17.6 ms (cold pool ramp) |
| 50 | 2.5 / 3.5 / 3.6 ms | 44.5 / 45.7 / 45.8 ms (ramp) |
| 200 | **7.9 / 12.9 / 13.7 ms** | **25.0 / 35.8 / 36.7 ms** |

Normal traffic completes on both pools; queueing only appears when requests are slow or when they die at startup.

### 8.3 Pool 50 slow-body occupancy

Already in §6: 200 slow bodies on nobuf50 → `max active 50`, `max listen queue 191`, status/probes time out; 50 slow bodies → pool reaches 50, queue 14 after the ramp. Pool 50 absorbs more, but `n > max_children` still queues.

### 8.4 200 mixed on pool 50 (after the pool had been exercised)

| Front | Codes | exits | p50 / p95 / max |
|---|---|---|---|
| stock50 (1m) | 133×413 + 67×502 | 67 | 0.843 / 1.410 / 1.482 s |
| diag50 (64m) | 134×502 + 66×200 | 134 | 3.608 / 4.138 / 4.178 s |

Larger pool does not improve the mixed result; the diag50 mixed latency is actually worse than diag5 (3.61 s vs 2.03 s) because the 33 MB B1 reads and worker-death/respawn churn compete on the same host. This is a measured caveat, not a scaling claim.

---

## 9. DoS / crash / RCE audit (all tests)

Counts across the whole session:

| Metric | Value |
|---|---|
| nginx 502 (all fronts) | **961** |
| FPM `exited with code 70` (fpm5 495 + fpm50 466) | **961** |
| FPM exits on signal / SIGSEGV / SIGABRT / heap corruption | **0** |
| nginx 504 | **0** (all tests ≤20 s; `fastcgi_read_timeout 300`; default 60 s would not have fired either) |
| RCE proof (`uid=33`, command output, canary file) | **0** |
| Leaked `/tmp/php*` upload temp files (crashed workers do not clean up) | 79 (fpm5) + 67 (fpm50) = 146, 408 KB + 524 KB |
| Session files in fpm5 `/tmp` | 218 |
| `slow requests` counter | 0 all tests |
| ASLR | `randomize_va_space=2` |

FPM's own access log is **not** authoritative: it can record `"POST /index.php" 200 pid=N dur=0.000` on the startup-failure path while nginx reports 502. In this run, **319 of 327** `POST /index.php` 200 lines have `dur=0.000` (the genuine B1 responses take ~0.019 s). Always use nginx status codes / `exit` logs. The 961↔961 502↔exit-70 match is exact.

UAF/RCE scope note: no stage-3 consumer/RCE body was sent. `b1.bin` is the 33 MB fill body and is rejected by `post_max_size=8M` (200, `post=0`) even on 64m fronts; on stock 1m it is 413. A1/A2 always die at startup. Therefore this report measures crash/exit behavior, not a full exploit chain, and makes **no RCE claim**.

---

## 10. Why the stock result is negative

1. **nginx request buffering** (`fastcgi_request_buffering on`, default): nginx reads the entire request body from the client into memory/temp files *before* it connects to FastCGI. A slow body is therefore an nginx-side connection, not an FPM one. Completion forwards the request; the upstream time is only the PHP execution time (`urt≈0.017 s` with a 20 s client transfer).
2. **Headers are parsed by nginx first**: incomplete headers never create a FastCGI request at all. A "fast slowloris" (many half-open/partial-header connections) only consumes nginx `worker_connections` and temp/connection state.
3. **`client_max_body_size` is checked from `Content-Length` at header parse**: a huge declared CL gets an immediate 413 without reading the body (0.5 ms), so it cannot hold even nginx for long.
4. **FPM listen queue**: `max_children` caps concurrent execution; complete requests beyond that wait in the listen backlog. 200 parallel requests therefore produce *queueing*, not more concurrency. Latency grows with n while outcomes do not change.
5. **A1/A2 are process-fatal at startup**: each producer OOMs before the request script runs; the worker exits 70. Saturation cannot keep that process alive or share its heap. The master respawns a fresh worker (new pid), which is what serves the next request. That is why the prime→trigger sequence always ends `producer 502/exit 70 → next request on a new pid`.
6. **Session state is file state**: same-SID serialization and cross-worker session-file visibility are real, but they are ordinary file-session semantics. They do not resurrect the dead worker's in-process `PS(id)`/upload state, and they do not improve the exploit timing.

---

## 11. Direct answers

**Does 200 parallel / fast slowloris occupy all FPM workers?**
- Stock: only transiently for complete requests, capped at `pm.max_children`; excess queues. Slow headers and slow bodies do **not** reach FPM at all (buffering on). **No** to "hold workers with slow HTTP under stock".
- Non-stock (`fastcgi_request_buffering off`, 64m): slow bodies **do** hold all workers (`max_children`), with listen queue up to 209 (pool 5) / 191 (pool 50) and fast probes timing out. **Yes to occupancy, but it is DoS only.**

**Does it improve worker affinity/timing for the producer→consumer trick?**
- No. Prime can make routing deterministic (single free worker) and pid measurements prove it (479/482 → death → 480/483), but the producer always `exit 70`s that worker and any following request (including a would-be consumer) is served by a new process. No UAF, no signal, no heap corruption, no RCE, no success-rate change vs sequential.

**Does `pm.max_children=50` help?**
- It raises the occupancy ceiling and absorbs more queue (max queue 191 vs 209 observed at 200 slow bodies; A2-only 200 p50 1.33 s vs 1.80 s), but 200 > 50 still queues and all A-bodies still fail. It does not change the exploit conclusion.

**Does the same `PHPSESSID` help?**
- It serializes requests (5×2 s: 10.01 s vs 2.79 s) and can fully occupy the pool if an endpoint holds the session lock (status timeout; probe 2.19 s; A2 delayed to 4.01 s). That is a separate stock DoS primitive, not affinity, and it does not preserve producer memory state.

---

## 12. Reproduction (exact commands)

```bash
BASE=/tmp/opencode/research/fpm_saturation_20261023T081008Z
cd "$BASE"
cat bodies/SHA256SUMS

# FPM status (per pool; status itself consumes a worker)
curl -s 'http://127.0.0.1:18822/status?json'    # pool 5
curl -s 'http://127.0.0.1:18825/status?json'    # pool 50

# 200 parallel mixed A1/A2/B1
python3 scripts/lab.py burst --port 18810 \
  --mix a1:67,a2:67,b1:66 --bodies bodies --timeout 180 \
  --out out.jsonl --summary summary.json

# slow header/body/chunked with samplers
bash scripts/slowtest.sh T3_nobuf5_slowbody 18812 fsat-web-nobuf5 \
  body 2000000 100000 20 200 /logprobe.php
bash scripts/slowtest.sh T2_diag5_finish 18811 fsat-web-diag5 \
  body 2000000 100000 20 20 /logprobe.php finish

# prime -> trigger (pid routing)
python3 scripts/lab.py single --port 18812 --path /pid.php
python3 scripts/lab.py single --port 18812 --file bodies/a2.bin --timeout 60
```

`scripts/lab.py` subcommands: `single`, `burst`, `slow`, `status`, `probe`; burst/slow support `--cookie` / `--cookie-name` for the same-SID tests. `scripts/slowtest.sh` records status before/after, probe latency, established sockets, exact nginx temp FD bytes (`lab/tempfds.sh`, run as user `nginx` because the container root lacks `CAP_SYS_PTRACE`), nginx code counts, FPM exit deltas and `/tmp/reqlog.txt` entries.

---

## 13. Artifacts

- Lab root: `/tmp/opencode/research/fpm_saturation_20261023T081008Z/`
- Configs: `conf/fpm/www5.conf`, `conf/fpm/www50.conf`, `conf/nginx/{stock5,diag5,nobuf5,stock50,diag50,nobuf50}.conf`
- Harness: `scripts/lab.py`, `scripts/slowtest.sh`, `lab/tempfds.sh`
- Bodies: `bodies/{a1,a2,b1}.bin`, `bodies/SHA256SUMS`
- Evidence: `evidence/seq`, `T1_*`, `T2_*`, `T3_*`, `T4a_stock_prime`, `T4b_nobuf_prime`, `T4c_session_lock`, `T6_*` (per-test `summary.json`, `slow_stdout.txt`, `status_before/after.json`, `probe.jsonl`, `tempfds.txt`, `estab.txt`, `nginx_delta.txt`, request JSONL)
- This report: `report.md`

No shared FPM containers were touched, restarted, or reconfigured; all work was local and unpushed.
