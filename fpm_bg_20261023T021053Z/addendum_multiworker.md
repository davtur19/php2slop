# Addendum — Multi-worker priming matrix for the FPM pre-RINIT serializer-state UAF

**Date:** 2026-10-23
**Parent report:** `report.md` (SHA-256 `98d6fbddb8543be6ea1939c1b40e23d3fe22e6634af3fe2f539d1f98e65c7163`, unchanged)
**Scope:** lab-only, stock PHP-FPM 8.4.26 / 8.5.11 + stock nginx 1.30.1; all FPM workers are ours, no legitimate clients, no competing traffic.
**Question:** can the proven same-worker pre-RINIT `BG(serialize)` / `BG(unserialize)` stale-state UAF be made to cross workers by priming *every* worker with a producer and then triggering consumers across the pool?

---

## 0. TL;DR

1. **No cross-worker transfer was observed.** In every run, a consumer crash occurred only on a PID that had previously served a producer in the same pool. Requests served by unprimed or freshly respawned workers returned `200`. There is no shared-memory channel for `BG(serialize)` / `BG(unserialize)`; the stale state is per worker process.
2. For 8.4.26 (and 8.5.11 with the documented 24k pad), every **primed** worker that received a consumer crashed:
   - dynamic 5 decode: 5/5; dynamic 5 encode: 5/5;
   - dynamic 20 decode: 20/20;
   - dynamic 50 decode: 46/46 distinct primed (42 in wave 1 + 4 leftovers in wave 2);
   - static 5 decode: 5/5; static 20 decode: 20/20 (17 + 3 leftovers);
   - static 50 decode: 45/45 distinct primed (38 + 5 + 2 leftovers).
3. At 50 workers, one 50-way producer batch does **not** reliably prime 50 distinct workers: the kernel/FPM accept distribution can give one fast worker a second producer before another worker accepts its first. Observed distinct coverage: 46/50 (dynamic) and 45/50 (static). This is a coverage/timing limit, not an affinity failure and not a cross-worker effect. Additional consumer waves hit all leftover primed workers; every crash still matched a primed PID.
4. **A1/A2 are exact on a static-2 raw FastCGI pair:** producer pins worker A; a consumer on a second connection hits worker B and returns `200`; a consumer on the pinned connection hits worker A and SIGSEGVs. A ping on the pinned connection first runs `PHP_RINIT`, clears the stale state, and the same-worker consumer then returns `200`.
5. **T1 negative:** the T1 producer's shutdown `serialize()` OOM and the T1 consumer's normal Moodle-shaped session write ran on the **same worker PID**; consumer `200`, no SIGSEGV.
6. **Buffering off (lab-only diagnostic):** 5/5 primed → 5/5 SIGSEGV, identical to stock buffering-on.
7. **8.5.11:** with the documented single 24,000-byte `pad` field, 5/5 primed → 5/5 SIGSEGV. Without that exact pad shape, the same chain survived (5/5 `200`) in this layout, consistent with the parent report's heap-layout dependence.
8. **No RCE, no leak, no marker, no uid change.** The observed primitive is a SIGSEGV on freed free-list metadata (`last_dtor=-1`) or a 0x50-filled fake block. The missing primitives are a **controlled reclaim** of the freed `php_unserialize_data`/HashTable with a valid fake structure, plus an **info leak** of the freed block/pointers. **Affinity is not the missing primitive** at 5/20; at 50 the practical limit is deterministic coverage/consumption timing.
9. The body-embedded hidden-FastCGI-request test is a clean negative: the target request's `POST` contains only `a`; the 377 bytes after the 5,120-byte multipart prefix are drained, and the hidden request produces no stdout and no END_REQUEST.
10. `report.md` was not modified; no push/commit/PR; no shared services were restarted. Only dedicated lab FPM pools/nginx vhosts were used.

---

## 1. Lab assumptions and stock-target labeling

The test assumes the lab-only condition stated by the task: **all FPM workers belong to us**, there is no legitimate traffic, and no competing client can consume a connection. Under that assumption, priming every worker and then sending one consumer per worker is the strongest possible test of cross-worker reuse.

Labels used below:

| Label | Meaning |
|---|---|
| **stock-target** | stock nginx 1.30.1 + stock PHP-FPM 8.4.26/8.5.11 binary; bug is in stock engine code |
| **lab-tuned pool** | `pm=dynamic` with `start_servers=min_spare=max_spare=max_children=N` so all workers are pre-forked. This is **not** the stock `start_servers=2` default; it only guarantees that every worker exists at priming time. |
| **stock option** | `pm=static`, `pm.max_children=N`; valid stock FPM configuration |
| **lab-only diagnostic** | `fastcgi_request_buffering off`, direct raw FastCGI harness, custom producer/consumer endpoints, 64M pool budget for 50 concurrent producers |
| **stock default** | stock nginx buffering on, stock FPM dynamic start values; same-worker stock evidence is in `report.md` |

The stock 8.4.26 dynamic-5 same-worker crash and the stock 8.5.11 dynamic-5 crash are already established in `report.md` (§4.3/§5.3 and `evidence/gdb/`). This addendum extends the question to *all-worker priming* and cross-worker delivery; it does not re-prove the same-worker UAF, whose gdb backtraces remain in the parent report.

---

## 2. Environment and builds

| Component | Value | SHA-256 |
|---|---|---|
| Kernel | Linux 6.12.113+deb13-amd64 x86_64 | — |
| nginx | `nginx/1.30.1` (`/opt/nginx-1.30.1/sbin/nginx`) | `c556c88ac92c36d13f8c417e247bbc0ce49e0d3786fbc830173f7788b44f6678` |
| PHP-FPM 8.4.26 | official stock, `PHP 8.4.26 (fpm-fcgi) (built: Oct 21 2026 00:31:28)` | `d8947ff91518b130d16213010f3d30df7a4d6238daaa8ff171a3b5c7f5ecae55` |
| PHP-FPM 8.5.11 | plain full-extension, `PHP 8.5.11 (fpm-fcgi) (built: Oct 23 2026 03:18:56)` | `fe6db8c4a95536a3c7eb4aeda3e10d681937cb251420ab7cb33731b7d610f0f2` |

Relevant PHP INI (`lab/conf/php-matrix.ini`, 8.4.26; `lab/conf/php-8511matrix.ini`, 8.5.11):

- `display_errors=Off`, `log_errors=On`, `memory_limit=128M` (64M for the 50-worker pools), `post_max_size=8M`;
- `session.save_handler=files`, `session.save_path=.../lab/sessions_matrix`, `session.serialize_handler=php`, `session.use_strict_mode=0`;
- `session.upload_progress.enabled=1`, `cleanup=1`, `prefix=upload_progress_`, `name=PHP_SESSION_UPLOAD_PROGRESS`;
- `output_buffering=4096`.

Pool configurations (`lab/conf/`):

| Config | Port | `pm` | `max_children` | Start/min/max spare | Memory | Role |
|---|---|---:|---:|---|---:|---|
| `fpm-matrix-d5.conf` | 29501 | dynamic | 5 | 5/5/5 | 128M | all-pre-forked dynamic 5 |
| `fpm-matrix-d20.conf` | 29501 | dynamic | 20 | 20/20/20 | 128M | all-pre-forked dynamic 20 |
| `fpm-matrix-d50.conf` | 29501 | dynamic | 50 | 50/50/50 | 64M | all-pre-forked dynamic 50 |
| `fpm-matrix-s5.conf` | 29501 | static | 5 | — | 128M | static control 5 |
| `fpm-matrix-s20.conf` | 29501 | static | 20 | — | 128M | static control 20 |
| `fpm-matrix-s50.conf` | 29501 | static | 50 | — | 64M | static control 50 |
| `fpm-matrix-s2.conf` | 29510 | static | 2 | — | 128M | A1/A2 raw pair |
| `fpm-8511matrix.conf` | 29508 | dynamic | 5 | 5/5/5 | 128M | 8.5.11 all-pre-forked |

nginx matrix vhosts (`lab/conf/nginx-matrix.conf`):

- `127.0.0.1:29511` → `127.0.0.1:29501`, **stock buffering on**;
- `127.0.0.1:29512` → `127.0.0.1:29501`, `fastcgi_request_buffering off` (**lab-only diagnostic**);
- `127.0.0.1:29518` → `127.0.0.1:29508`, 8.5.11.

The FPM access log format used for PID correlation is:

```
access.format = "%p %R %m %s %q %f"
```

`%p` is the worker PID, `%q` is the query string (which carries the run tag), and `%f` is the script path. SIGSEGV is read from the FPM error log (`child <pid> exited on signal 11 (SIGSEGV)`), and HTTP `502` from the nginx access log. A consumer that is served by a surviving worker produces a `200` FPM access line whose PID can be compared to the primed set.

---

## 3. Method

### 3.1 Producer/consumer primitives

**Decode (B1d):**

```
producer: GET /producer_oom.php?n=8000000&tag=<tag>p<i>
          $s = 'a:8000000:{' . str_repeat('i:1;', 8000000) . '}';
          unserialize($s)  -> OOM inside php_var_unserialize -> BG(unserialize) left with level=1
consumer: POST /consumer.php  multipart/form-data
          PHPSESSID=<valid sid>              (first field)
          [optional pad field(s)]           (for 8.5.11 layout)
          PHP_SESSION_UPLOAD_PROGRESS=<key>
          file field "f"
          session file sess_<sid> = p|s:5:"hello";
```

**Encode (B1e):**

```
producer: GET /producer_ser_oom.php?n=300000&tag=<tag>p<i>
          builds an array of 300000 ints and calls serialize() -> OOM inside BG(serialize)
consumer: same multipart; session file sess_<sid> = p|a:2:{i:0;s:5:"hello";i:1;R:2;}
```

The matrix encode producer bails out in a script-level `serialize()` call; the T1 producer (`t1_producer.php`) covers the **shutdown/destructor** variant, where `serialize($this->big)` runs at request shutdown. Both leave the serializer state stale; the matrix uses the script-level form for deterministic batch timing, and T1 is the shutdown negative control. All producers returned `500` (the OOM is inside `unserialize()` / `serialize()`, not in the payload construction; the PHP error log shows the exact “Allowed memory size ... exhausted” line and the stack frame). Consumers were sent as a concurrent batch after the producer batch completed.

### 3.2 Session ID hygiene

PHP session IDs accept only `A-Z a-z 0-9 - ,`; underscores are illegal. The first exploratory `d5dec` run used `m<tag>_c<i>` and every consumer returned `200 SESSION=[]` with no crash. That run is **excluded**; the corrected driver uses `m<tag>-<i>` and all reported runs use legal IDs. This is a methodological correction, not a negative result.

### 3.3 All-worker priming and PID accounting

For each run:

1. send `P` concurrent producers;
2. read the new FPM access lines by run tag and collect the distinct producer PIDs (the **primed set**);
3. send `C` concurrent consumers;
4. classify every consumer crash from the new FPM error lines, and every survivor from the new FPM access lines;
5. compare sets:
   - `crashed_not_primed` — a crash on a PID that never served a producer (would be cross-worker or respawn effect);
   - `survivors_on_primed` — a `200` on a PID that did serve a producer (would mean the stale state did not trigger);
   - `missing_primed_crashes` — primed PIDs not consumed in that wave; they can be tested in a later consumer wave without re-priming.

This set accounting is the core cross-worker test: a crash on a worker that was never primed would be evidence of cross-worker transfer; a survivor on a primed worker would be evidence against same-worker determinism.

### 3.4 A1/A2 raw pair on static 2

`scripts/a1a2_raw.py` uses two raw FastCGI connections to a `pm=static`, `max_children=2` pool:

- **C1:** producer (FastCGI `BEGIN_REQUEST` with `keep=1`) → worker A. After the producer response, worker A remains in the FastCGI keep-alive read loop and is **not accepting** new connections.
- **C2:** consumer B (`keep=0`) → the only other idle worker, B → expected `200`, no stale state.
- **C1:** consumer A (`keep=0`, request id 2) → worker A, primed → expected SIGSEGV.

The access log gives the producer PID and the cross-consumer PID; the SIGSEGV line gives the same-worker crash PID. A **control** inserts a `ping.php` request on C1 between producer and consumer:
`producer → ping (keep=1) → consumer A`; the ping's `PHP_RINIT` clears `BG(unserialize)`/`BG(serialize)`, so the same-worker consumer must return `200`.

This provides both A1 (same worker positive) and A2 (cross worker negative) with exact PIDs, without relying on accept-distribution luck. Stock nginx was left with `fastcgi_keep_conn` off (the stock default); the raw FastCGI `keep=1` flag is the deterministic, lab-only equivalent of the optional `fastcgi_keep_conn on` diagnostic, and it avoids any nginx upstream-pool rotation.

### 3.5 T1 raw cycle on static 2

`scripts/t1_raw.py` sends `t1_producer.php` on C1 (`keep=1`), then `t1_consumer.php` on the same connection:

- `t1_producer.php` allocates 20 MB, sets `memory_limit=24M` in its destructor, and calls `serialize($this->big)` at request shutdown; the OOM is inside `BG(serialize)`.
- `t1_consumer.php` calls `session_start()`, sets `$_SESSION['USER'] =& $GLOBALS['USER']` and `$_SESSION['SESSION'] =& $GLOBALS['SESSION']` (Moodle `manager.php` shape), and writes the session at shutdown.

The expected result is `200` on the same worker and no SIGSEGV; this is a behavioral negative for “any normal session write after a serializer OOM crashes”.

### 3.6 Partial-STDIN body-embedded hidden request

`scripts/t3_raw_fcgi.py smuggle` sends one target FastCGI request whose `CONTENT_LENGTH` is 5,497 bytes:

- a 5,120-byte multipart prefix with parts `a` and `b` (part limit triggers early end of POST parsing), followed by
- a complete 377-byte FastCGI request for `t3_hidden.php`.

If the leftover bytes were interpreted as a hidden request, `REQ2` would have `end=True` and/or `stdout` containing `T3_HIDDEN`. The observed result is a negative (see §4.10).

### 3.7 Excluded / exploratory runs

| Run | Why excluded or not used as a headline |
|---|---|
| `d5dec` | SIDs contained `_`; PHP rejected them; `SESSION=[]`, 5×200. Corrected by `d5dec2`. |
| `8511d` | Driver read the 8.4.26 log paths, so `primed=[]`; not a result. Corrected by `8511d2` with `--fpm-access/--fpm-error`. |
| `8511d2` | Correct log paths, no pad; 5/5 primed, 5/5 `200` in this layout. Kept as a heap-layout data point. |
| `8511dpad` | 3 fields × 8,200 `P`; 5/5 `200`. Not equivalent to one 24,000-byte allocation. |
| `8511dp1`, `8511dp8` | one 8,200 and eight 8,200 `P` fields; 5/5 `200` each. |
| `8511dp24` | one 24,000-byte `P` field; 5/5 SIGSEGV. Used as the 8.5.11 headline. |
| `d50dec` / `s50dec` | 64M pool budget and `n=6000000` to fit 50 concurrent producers; labeled lab-tuned. |

The 8.5.11 pad result is layout-dependent and is not evidence that 8.5.11 is universally deterministic; it is the same chain under the parent report's documented `'P'=0x50` reclaim shape.

---

## 4. Results

### 4.1 Matrix summary

`P` = producer count; `primed` = distinct producer PIDs; `crashed` = consumers that produced a SIGSEGV line in the FPM error log; `502` = nginx 502 responses; `cross` = `crashed_not_primed`. The `50` rows use multiple consumer waves; the total crashed count includes all waves.

| Run / tag | Pool | Type | P | primed | crashed on primed | 502 | cross | Notes |
|---|---|---|---:|---:|---:|---:|---:|---|
| `d5dec2` | dynamic 5 | decode | 5 | 5 | 5 | 5 | 0 | all 5; stock buffering on |
| `d5enc` | dynamic 5 | encode | 5 | 5 | 5 | 5 | 0 | all 5 |
| `d20dec` | dynamic 20 | decode | 20 | 20 | 20 | 20 | 0 | all 20 |
| `d50dec` + `d50dec_wave2` | dynamic 50 | decode | 50 | 46 | 42 + 4 = 46 | 42 + 4 = 46 | 0 | 4 producers duplicated; 4 workers never primed |
| `s5dec` | static 5 | decode | 5 | 5 | 5 | 5 | 0 | all 5 |
| `s20dec` + `s20dec_wave2` | static 20 | decode | 20 | 20 | 17 + 3 = 20 | 17 + 3 = 20 | 0 | all 20 |
| `s50dec` + `s50dec_wave2` + `s50dec_wave3` | static 50 | decode | 50 | 45 | 38 + 5 + 2 = 45 | 38 + 5 + 2 = 45 | 0 | 5 producers duplicated; 5 never primed |
| `d5off` | dynamic 5 | decode | 5 | 5 | 5 | 5 | 0 | `fastcgi_request_buffering off` (lab-only) |
| `8511dp24` | dynamic 5 (8.5.11) | decode | 5 | 5 | 5 | 5 | 0 | one 24,000-byte pad field |
| `a1a2d` | static 2 raw | decode A1/A2 | 1 | 1 | 1 (A1) | 1 | 0 | A2 on worker B `200` |
| `a1a2e` | static 2 raw | encode A1/A2 | 1 | 1 | 1 (A1) | 1 | 0 | A2 on worker B `200` |
| `a1a2ctl` | static 2 raw | decode control | 1 | 1 | 0 | 0 | 0 | ping clears; same worker `200` |
| `t1m` | static 2 raw | T1 | 1 | 1 | 0 | 0 | 0 | same worker `200`, no SIGSEGV |
| partial STDIN | static 1 (29361) | smuggling control | 1 | — | 0 | 0 | — | hidden request no stdout/END |

For every matrix row, `survivors_on_primed` was empty, or (in the exploratory 8.5.11 no-pad rows) the survivors were on primed PIDs and are discussed separately in §4.9/§5.5. For all headline rows, the set accounting is clean: `crashed_not_primed=[]` and `survivors_on_primed=[]`.

### 4.2 Dynamic 5 decode and encode (stock buffering on)

Decode (`d5dec2`) primed and crashed the same five workers:

```
313140 127.0.0.1 GET 500 n=8000000&tag=d5dec2p1 .../producer_oom.php
313141 127.0.0.1 GET 500 n=8000000&tag=d5dec2p3 .../producer_oom.php
313137 127.0.0.1 GET 500 n=8000000&tag=d5dec2p0 .../producer_oom.php
313138 127.0.0.1 GET 500 n=8000000&tag=d5dec2p2 .../producer_oom.php
313139 127.0.0.1 GET 500 n=8000000&tag=d5dec2p4 .../producer_oom.php
```

```
[23-Oct-2026 10:42:20] WARNING: [pool www] child 313140 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:20] WARNING: [pool www] child 313137 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:20] WARNING: [pool www] child 313138 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:20] WARNING: [pool www] child 313139 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:20] WARNING: [pool www] child 313141 exited on signal 11 (SIGSEGV) ...
```

All 5 consumers got nginx `502`; `consumer_survivor_pids=[]`; `crashed_not_primed=[]`.

Encode (`d5enc`) primed `330048–330052` and all five SIGSEGV'd:

```
[23-Oct-2026 10:42:27] WARNING: [pool www] child 330048 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:27] WARNING: [pool www] child 330049 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:27] WARNING: [pool www] child 330050 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:27] WARNING: [pool www] child 330051 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:42:27] WARNING: [pool www] child 330052 exited on signal 11 (SIGSEGV) ...
```

`d5enc` nginx `502=5`, survivors empty.

### 4.3 Dynamic 20 decode

Primed (20 distinct):

```
330753,330754,330755,330756,330757,330758,330759,330760,330761,330762,
330763,330764,330765,330766,330767,330768,330769,330770,330771,330772
```

All 20 appear in the SIGSEGV list; nginx `502=20`; no survivors; `crashed_not_primed=[]`. A representative error line:

```
[23-Oct-2026 10:42:54] WARNING: [pool www] child 330754 exited on signal 11 (SIGSEGV) ...
```

### 4.4 Dynamic 50 decode: one producer batch is not enough for 50 distinct workers

The 50-producer batch produced 50 access lines but only **46 distinct PIDs**:

```
332351,332352,332353,332354,332356,332357,332358,332359,332361,332366,
332367,332368,332369,332370,332371,332372,332373,332375,332376,332378,
332379,332382,332383,332384,332385,332386,332387,332390,332391,332392,
332393,332394,332395,332397,332398,332399,332400,332401,332402,332403,
332404,332407,332409,332414,332417,332418
```

Consumer wave 1 (50 consumers) crashed 42 of them; the 8 survivor responses arrived on only 7 unique fresh/unprimed PIDs (`332388,332396,332408,332410,332935,332976,332977`; `332935` served two survivors). The 4 primed leftovers were:

```
332366,332367,332407,332417
```

A second consumer wave of 50, **without re-priming**, crashed exactly those four and only those four:

```
crashed_pids = [332366, 332367, 332407, 332417]
crashed_in_primed = [332366, 332367, 332407, 332417]
crashed_not_in_primed = []
nginx_502 = 4
nginx_200 = 46
```

Thus **46/46 distinct primed workers crashed**; the first wave's 8 survivors were unprimed respawns, and the four leftovers had retained the stale state on idle workers. The 4 workers never primed by the single producer batch are a coverage artifact of concurrent accept distribution, not a memory-safety difference.

### 4.5 Static controls

**Static 5 (`s5dec`):** 5/5 primed (`337640–337644`), 5/5 SIGSEGV, 5×502.

**Static 20 (`s20dec`):** primed 20 distinct (`338079–338098`); wave 1 crashed 17, survivors on fresh PIDs only. The 3 primed leftovers were:

```
338091,338095,338097
```

Wave 2 crashed exactly those three:

```
crashed_pids = [338091, 338095, 338097]
crashed_in_primed = [338091, 338095, 338097]
crashed_not_in_primed = []
nginx_502 = 3
nginx_200 = 17
```

**Static 50 (`s50dec`):** 45 distinct primed; wave 1 crashed 38; wave 2 crashed 5 of the 7 leftovers

```
339310,339314,339330,339334,339344
```

and wave 3 crashed the last two

```
339326,339345
```

Total 38 + 5 + 2 = **45/45 primed crashed**; `crashed_not_in_primed=[]` in every wave; the 5 other producer requests were duplicates, so those 5 workers were never primed.

Representative static SIGSEGV lines:

```
[23-Oct-2026 10:45:01] WARNING: [pool www] child 337640 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:45:10] WARNING: [pool www] child 338080 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:45:32] WARNING: [pool www] child 339299 exited on signal 11 (SIGSEGV) ...
```

### 4.6 A1/A2 exact same-worker vs cross-worker

**Decode (`a1a2d`):**

```
342842 127.0.0.1 GET 500 n=8000000&tag=a1a2dprod .../producer_oom.php
342843 127.0.0.1 POST 200 tag=a1a2dcB .../consumer.php
[23-Oct-2026 10:47:29] WARNING: [pool www] child 342842 exited on signal 11 (SIGSEGV) ...
```

- C1 producer: worker **342842** (primed).
- C2 consumer (different connection): worker **342843**, `200`, body `CONSUMER PID=342843 ... SESSION=["p"]` — **cross-worker, no crash**.
- C1 consumer (same pinned connection): no access line; SIGSEGV on **342842** — **same-worker, crash**.

**Encode (`a1a2e`):**

```
342843 127.0.0.1 GET 500 n=300000&tag=a1a2eprod .../producer_ser_oom.php
342851 127.0.0.1 POST 200 tag=a1a2ecB .../consumer.php
[23-Oct-2026 10:47:39] WARNING: [pool www] child 342843 exited on signal 11 (SIGSEGV) ...
```

Same structure: producer **342843**, cross consumer **342851** `200`, same consumer crashes **342843**.

**Control (`a1a2ctl`):**

```
342851 127.0.0.1 GET 500 n=8000000&tag=a1a2ctlprod .../producer_oom.php
342974 127.0.0.1 POST 200 tag=a1a2ctlcB .../consumer.php
342851 127.0.0.1 GET 200 tag=a1a2ctlping .../ping.php
342851 127.0.0.1 POST 200 tag=a1a2ctlcA .../consumer.php
```

No SIGSEGV lines. The producer primed **342851**; the cross consumer hit **342974** and returned `200`; the ping ran `PHP_RINIT` on **342851** and cleared the state; the same-worker consumer then returned `200` on **342851**. This isolates the crash to the stale pre-RINIT state, not to the consumer script or session file.

### 4.7 T1 negative: same worker, normal session write, no crash

Raw T1 (`t1m`, static 2):

```
342974 127.0.0.1 GET 200 tag=t1mprod .../t1_producer.php
342974 127.0.0.1 GET 200 sid=mt1-t1m&tag=t1mcons .../t1_consumer.php
```

PHP error log (UTC) for the same worker:

```
[23-Oct-2026 08:53:40 UTC] T1_PRE pid=342974 mem=23072768 limit=32M
[23-Oct-2026 08:53:40 UTC] T1_DTOR_START pid=342974 mem=23072768 limit=24M
[23-Oct-2026 08:53:40 UTC] PHP Fatal error:  Allowed memory size of 25165824 bytes exhausted
(tried to allocate 20975616 bytes) in .../t1_producer.php on line 14
```

The raw producer response begins with `Status: 500 Internal Server Error` (the destructor OOM happens at shutdown; the FPM access log records `200`), while the consumer returned:

```
T1_CONSUMER pid=342974 status=2 sid=mt1-t1m keys=["p","USER","SESSION"]
USER=stdClass SESSION=stdClass
```

`producer_pid == consumer_pid == 342974`; `sig11_pids=[]`. The T1 consumer's normal Moodle-shaped session write on the same worker **did not crash**. This matches the parent T1 evidence (`evidence/t1/`) and is a behavioral negative.

### 4.8 Buffering off (lab-only diagnostic)

`d5off` via nginx 29512 (`fastcgi_request_buffering off`): primed 5/5 (`360678–360682`), 5/5 SIGSEGV, 5×502, no survivors. Representative lines:

```
[23-Oct-2026 10:53:52] WARNING: [pool www] child 360678 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:53:52] WARNING: [pool www] child 360679 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:53:52] WARNING: [pool www] child 360680 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:53:52] WARNING: [pool www] child 360681 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:53:52] WARNING: [pool www] child 360682 exited on signal 11 (SIGSEGV) ...
```

Buffering-on stock (`d5dec2`) and buffering-off diagnostic are identical at 5/5. Buffering is not the primitive; the pre-RINIT handler still runs when PHP reads the multipart body.

### 4.9 8.5.11: pad shape controls the layout

With the documented **single 24,000-byte `pad` field** (`8511dp24`), 8.5.11 behaved like 8.4.26 at the all-worker level:

```
406145 127.0.0.1 GET 500 n=8000000&tag=8511dp24p0 .../producer_oom.php
406143 127.0.0.1 GET 500 n=8000000&tag=8511dp24p3 .../producer_oom.php
406144 127.0.0.1 GET 500 n=8000000&tag=8511dp24p4 .../producer_oom.php
406146 127.0.0.1 GET 500 n=8000000&tag=8511dp24p2 .../producer_oom.php
406147 127.0.0.1 GET 500 n=8000000&tag=8511dp24p1 .../producer_oom.php
```

```
[23-Oct-2026 10:57:25] WARNING: [pool www] child 406145 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:57:25] WARNING: [pool www] child 406143 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:57:25] WARNING: [pool www] child 406144 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:57:25] WARNING: [pool www] child 406146 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 10:57:25] WARNING: [pool www] child 406147 exited on signal 11 (SIGSEGV) ...
```

5/5 primed, 5/5 crashed, 5×502, cross=0.

Without the exact pad shape, the same chain survived:

| 8.5.11 run | Pad shape | Primed | Crashed | nginx 200 |
|---|---|---:|---:|---:|
| `8511d2` | none | 5 | 0 | 5 |
| `8511dpad` | 3 fields × 8,200 P | 5 | 0 | 5 |
| `8511dp1` | 1 field × 8,200 P | 5 | 0 | 5 |
| `8511dp8` | 8 fields × 8,200 P | 5 | 0 | 5 |
| `8511dp24` | **1 field × 24,000 P** | 5 | **5** | 0 |

This is consistent with the parent report: the 8.5.11 crash is heap-layout dependent, and a single 24,000-byte allocation is not equivalent to three 8,200-byte allocations for reclaiming the freed `php_unserialize_data` block. The 0x50 (`'P'`) words are the hostile fill; they overwrite free-list metadata, but they are not a valid fake structure. The 8.4.26 chain does not need the pad.

### 4.10 Partial-STDIN body-embedded hidden request: clean negative

`evidence/matrix/partial_stdin/smuggle.out`:

```
# partial-STDIN hidden-request negative, 2026-10-23T08:59:02Z
# port 29361 static-1 8.4.26; target body=5120 prefix + 377 hidden FCGI records
REQ1 end=True app_status=0 stdout=b'X-Powered-By: PHP/8.4.26\r\nContent-type: text/plain;charset=UTF-8\r\n\r\nT3_TARGET pid=86216 method=POST uri=/t3_target.php ct=multipart/form-data; boundary=T3BOUND clen=5497 post=["a"]\n' stderr=b''
REQ2 end=False app_status=None stdout=b'' stderr=b''
```

The target request is parsed with `post=["a"]` only; the 377 bytes of hidden FastCGI records after the 5,120-byte multipart prefix are drained by `sapi_deactivate_module()` and are not parsed as a second request (`REQ2 end=False`, no stdout, no stderr). This is a negative for body-embedded request smuggling. It is **not** a test of body bytes beyond `CONTENT_LENGTH` on a direct-to-FPM socket; stock nginx buffers and forwards a bounded body, so that variant is not reachable through the stock nginx target. The hidden-request primitive remains direct-FPM-only at best and is not part of the cross-worker UAF chain.

---

## 5. Analysis

### 5.1 Why there is no cross-worker crash

`BG(serialize)` and `BG(unserialize)` are per-request/per-process globals in the PHP executor (`basic_functions.c`), not shared memory and not a pool-level structure. A producer OOM on worker A leaves A's globals stale; worker B's globals are separate and are zeroed by B's own `PHP_RINIT(basic)`. A consumer served by B therefore has no stale `php_unserialize_data` to dereference. The only way to hit the UAF is for the next request on **A** to perform a session decode/encode before A's `PHP_RINIT` clears the state.

The A1/A2 pair is the direct proof:

- A1: `342842` producer → `342842` SIGSEGV on the same pinned connection;
- A2: `342842` producer → `342843` consumer `200` on a different connection;
- control: `342851` producer → `342851` ping `200` → `342851` consumer `200`, no SIGSEGV.

The control is important: it shows the consumer request itself (session file, multipart body, script) is not crashing; only the pre-RINIT state on the primed worker causes the SIGSEGV.

### 5.2 Why every primed worker crashes

The producer OOM is inside `unserialize()` / `serialize()`:

- decode: `php_var_unserialize_init()` allocates `php_unserialize_data`; the 8M-element array then attempts a 320MB `zend_hash_real_init_mixed()`, hits `memory_limit`, and `zend_mm_safe_error()` → `_zend_bailout()` skips the destroy. `BG(unserialize)` keeps `level=1` and the freed `php_unserialize_data` pointer/backing block.
- encode: the 300k-int array `serialize()` exhausts memory inside `BG(serialize)`; the bailout skips the serializer cleanup.

On the next request on that worker, `php_request_startup()` builds `$_POST` before `PHP_RINIT(basic)`. The upload-progress handler calls `php_session_initialize()` (decode) or `php_session_flush(1)` (encode) while the previous request's serializer state is still in the globals. The decode path dereferences the freed `php_unserialize_data` in `var_tmp_var`; the parent report's gdb shows `last_dtor=-1` and `si_addr=0xffffffffffffffff`. The encode path writes into the freed hash in `php_add_var_hash` (`data->n += 1`, `zend_hash_index_find`, `zend_hash_index_add_new`). Both are same-worker, pre-RINIT UAFs.

The matrix does not add a new gdb backtrace; it relies on the parent report's `evidence/gdb/crash_8426.log` (8.4.26) and `evidence/gdb/crash_8511.log` (8.5.11) for the exact crash sites. The matrix's new evidence is the PID-level delivery pattern.

### 5.3 The 50-worker coverage/timing limit

At 50 workers, the listen socket is shared by 50 processes. Concurrent producers are accepted non-deterministically: a worker that finishes an OOM quickly can return to `accept()` and take a second producer before another idle worker takes its first. The first batch therefore has **duplicates** and distinct coverage below 50:

- dynamic 50: 50 producer requests → 46 distinct PIDs;
- static 50: 50 producer requests → 45 distinct PIDs.

The same race applies to consumers after crashes: the master respawns a new worker, and a queued consumer can be accepted by the fresh (unprimed) worker, producing a `200`. That is exactly what the wave-1 survivors are: fresh PIDs, not primed. The leftover primed workers are still alive and still stale; a second/third consumer wave hits them and crashes them (dynamic 50: 4/4 leftovers; static 50: 5 + 2 leftovers). The set `crashed_not_primed` is empty in every wave, and `survivors_on_primed` is empty for every headline run.

This is a **practical coverage** limit, not an affinity or memory-safety failure. The "all workers are ours" assumption removes competing clients, but it cannot make the kernel's accept wakeups deterministic or prevent FPM from respawning a crashed worker while a consumer batch is in flight. A truly deterministic 50/50 single-batch test would need a synchronization barrier inside FPM's accept loop or a per-worker connection pinning mechanism; neither is stock behavior. The 5/20 pools show the effect is 100% when the accept distribution is small enough to cover all workers in one batch.

### 5.4 Security impact: no RCE, no leak

No RCE, marker execution, or uid change was observed. The consumers either return `200` (unprimed worker), return `502` (primed worker crash), or produce a SIGSEGV line. There is no response-body leak: `display_errors=Off`; the only body seen on survivors is the planted session key (`SESSION=["p"]`) or the T1 shapes, not freed memory.

The exact missing primitives are:

1. **Controlled reclaim** of the freed `php_unserialize_data` (decode) or `php_var_serialize_data` hash (encode) with a **valid fake structure**. The 24,000-byte `'P'` pad overwrites the block with `0x50505050...`; it is enough to turn the UAF into a deterministic SIGSEGV, but `0x50505050...` is not a valid Zend pointer/refcount/hash structure, so the crash occurs in free-list metadata or fake-pointer dereference rather than a controlled write.
2. **Info leak** of the freed block address/heap base (and a valid pointer to place in the fake structure). No leak was found; the survivors do not echo the freed block, and `display_errors=Off` suppresses diagnostics. Without a leak, a fake `var_hash`/HashTable cannot be pointed at a controlled address under ASLR.
3. **Affinity is not missing** for 5/20; A1/A2 proves same-worker delivery. At 50, the practical obstacle is coverage/timing, not affinity. The stale state is not transferred across workers, so priming more workers only increases the chance that a given consumer lands on a primed one; it does not create a cross-worker primitive.

The crash itself is a denial of service (worker SIGSEGV, nginx `502`), already established in the parent report. The new matrix shows the DoS scales to all primed workers in 5/20 pools and to 46/45 distinct workers in 50 pools, but remains same-worker.

### 5.5 Stock-target vs lab-only conclusions

| Question | Stock-target conclusion | Lab-only caveat |
|---|---|---|
| Does the stale serializer state cross workers? | **No.** A1/A2 exact: cross-worker `200`, same-worker SIGSEGV. | Direct raw FastCGI harness; static 2; no stock nginx for A1/A2. |
| Does priming all workers yield all-worker crashes? | **Yes for every primed worker.** 5/5, 20/20, 46/46, 45/45. | 50 pools use 64M and `n=6M`; dynamic pools are all-pre-forked, not stock start values. |
| Does stock nginx buffering matter? | **No.** 5/5 with buffering on and off. | Buffering off is lab-only diagnostic. |
| Is 8.5.11 affected? | **Yes, with the documented 24k `'P'` pad**; 5/5. Without the pad shape, layout-dependent survival. | Pad size/field shape is lab-tuned; 8.5.12 fixed control is in the parent report. |
| Does a normal session write after a serializer OOM crash? | **No.** T1 same-worker consumer `200`; parent T1 evidence agrees. | T1 is a faithful Moodle shape, not a full Moodle install. |
| Can a hidden FastCGI request be smuggled in the body? | **No** in this test; target POST only `a`, hidden `end=False`. | Direct-to-FPM; body bytes beyond `CONTENT_LENGTH` are a separate, non-stock-nginx variant. |
| RCE / leak? | **No.** Missing controlled reclaim + info leak; affinity is not the blocker. | No exploit attempt beyond crash/reclaim shaping. |

### 5.6 Relation to the parent report

The dedicated-vs-stock comparison here is a dedicated lab single-upstream pool behind stock nginx versus the stock nginx/FPM single upstream; a pool shared with unrelated applications was not tested because the lab assumption excludes competing clients. The per-worker isolation argument is unaffected by co-tenancy, but accept timing would differ.

The parent report already establishes:

- the exact UAF sites and gdb backtraces (`var_tmp_var`, `php_add_var_hash`, `last_dtor=-1`);
- stock same-worker dynamic-5 crashes on 8.4.26 and 8.5.11, and the 8.5.12 fix;
- the T1 behavioral negative and the direct-FPM session-upload-progress primitive.

This addendum adds:

- all-worker priming at 5/20/50 in dynamic and static pools;
- exact PID-set accounting and the 50-worker accept-duplication/coverage result;
- deterministic A1/A2 same-worker vs cross-worker with a static-2 raw pair and a RINIT-clear control;
- buffering-off diagnostic;
- the 8.5.11 24k-pad matrix result;
- a fresh T1 same-worker negative;
- the body-embedded hidden-request negative.

It does not modify the parent report or its conclusions.

---

## 6. Limitations

1. **No Apache comparison.** Neither `apache2` nor `httpd` is installed; the stock-target web server is nginx 1.30.1. Apache MPM/mod_php or mod_proxy_fcgi behavior is out of scope.
2. **No full Moodle install.** The T1 consumer replicates the relevant `core\session\manager` session shape (`session_start`, `$_SESSION['USER']`, `$_SESSION['SESSION']`, references, shutdown write); it is not a full Moodle application/DB. The stock-app claim is engine-faithful, not a full-app exploit.
3. **50-worker pools are memory-tuned.** `memory_limit=64M` and `n=6000000` were used to fit 50 concurrent OOM producers. The UAF site is the same (`unserialize` OOM at the array allocation); the limit changes the precise allocation sizes but not the stale-state mechanism. Dynamic 50/static 50 are all-pre-forked, not stock start values.
4. **8.5.11 is layout-dependent.** The 24,000-byte single pad is the documented shape that crashed in this layout; 1×8,200, 3×8,200 and 8×8,200 survived. This is consistent with the parent report's heap-layout dependence, not a claim of universal determinism. 8.5.12 was not rerun here; the parent report's fixed control remains authoritative.
5. **Partial-STDIN is direct-to-FPM.** The negative applies to a body-embedded hidden FastCGI request with `CONTENT_LENGTH` covering the whole body. Bytes beyond `CONTENT_LENGTH` on a direct socket are a different test and are not reachable through stock nginx's bounded forwarding; they were not promoted to a stock-target claim.
6. **No controlled reclaim/leak.** The matrix demonstrates crash/DoS and same-worker locality, not exploitation. The pad is a crash-shaping field, not a valid fake structure. No info leak or RCE was achieved.
7. **No shared pool with competing clients.** The lab assumption is all workers ours; a real shared pool adds legitimate traffic and different accept timing, but the per-worker isolation argument is unchanged. The parent report's stock dynamic-5 evidence covers the default-start stock configuration; the all-pre-forked matrix isolates coverage from the bug.
8. **No push/commit/PR.** This is a local research artifact; no repository operation was performed. Existing reports were not modified.

---

## 7. Reproduction

All commands run from `/tmp/opencode/research/fpm_bg_20261023T021053Z`.

### 7.1 Start a matrix pool

```bash
# 8.4.26 all-pre-forked dynamic 5
/tmp/opencode/research/fpm8426_20261022T031921Z/libs/php-fpm \
  -y $PWD/lab/conf/fpm-matrix-d5.conf \
  -c $PWD/lab/conf/php-matrix.ini -F

# 8.5.11 (needs ICU/onig library path)
LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib \
  /tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm \
  -y $PWD/lab/conf/fpm-8511matrix.conf \
  -c $PWD/lab/conf/php-8511matrix.ini -F
```

### 7.2 B1 matrix

```bash
# dynamic 5 decode, stock buffering on (nginx 29511)
python3 scripts/matrix_run.py --type decode --producers 5 --consumers 5 \
  --tag d5dec2 --port 29511 --outdir evidence/matrix/d5dec2

# dynamic 5 decode, buffering off (nginx 29512, lab-only)
python3 scripts/matrix_run.py --type decode --producers 5 --consumers 5 \
  --tag d5off --port 29512 --outdir evidence/matrix/d5off

# dynamic 50 decode (64M pool; n=6000000)
python3 scripts/matrix_run.py --type decode --producers 50 --consumers 50 \
  --n 6000000 --tag d50dec --port 29511 --outdir evidence/matrix/d50dec

# leftover primed workers, no re-priming
python3 scripts/matrix_consumer_wave.py --type decode --count 50 \
  --tag d50w2 --outdir evidence/matrix/d50dec_wave2 \
  --primed 332366,332367,332407,332417 --port 29511

# 8.5.11 decode with the documented single 24,000-byte pad
python3 scripts/matrix_run.py --type decode --producers 5 --consumers 5 \
  --tag 8511dp24 --port 29518 --pad-size 24000 --pads 1 \
  --outdir evidence/matrix/8511dp24 \
  --fpm-access $PWD/lab/logs/fpm-8511matrix-access.log \
  --fpm-error $PWD/lab/logs/fpm-8511matrix-error.log
```

### 7.3 A1/A2 and T1

```bash
# static 2 pool on 29510
/tmp/opencode/research/fpm8426_20261022T031921Z/libs/php-fpm \
  -y $PWD/lab/conf/fpm-matrix-s2.conf \
  -c $PWD/lab/conf/php-matrix.ini -F

python3 scripts/a1a2_raw.py --type decode --tag a1a2d \
  --outdir evidence/matrix/a1a2d --port 29510
python3 scripts/a1a2_raw.py --type encode --tag a1a2e \
  --outdir evidence/matrix/a1a2e --port 29510
python3 scripts/a1a2_raw.py --type decode --tag a1a2ctl \
  --outdir evidence/matrix/a1a2ctl --port 29510 --control-ping
python3 scripts/t1_raw.py --tag t1m --outdir evidence/matrix/t1m --port 29510
```

### 7.4 Partial-STDIN negative

```bash
python3 scripts/t3_raw_fcgi.py smuggle --port 29361 --prefix-len 5120 \
  --target-script t3_target.php --hidden-script t3_hidden.php --wait 3 \
  > evidence/matrix/partial_stdin/smuggle.out 2>&1
```

The output must show `REQ1 ... post=["a"]` and `REQ2 end=False ... stdout=b''`.

---

## 8. Artifacts and hashes

### 8.1 Parent report unchanged

```
98d6fbddb8543be6ea1939c1b40e23d3fe22e6634af3fe2f539d1f98e65c7163  report.md
```

The parent report was read but not edited. This addendum is a separate file.

### 8.2 Key binary/config/script hashes

```
d8947ff91518b130d16213010f3d30df7a4d6238daaa8ff171a3b5c7f5ecae55  /tmp/opencode/research/fpm8426_20261022T031921Z/libs/php-fpm
fe6db8c4a95536a3c7eb4aeda3e10d681937cb251420ab7cb33731b7d610f0f2  /tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm
c556c88ac92c36d13f8c417e247bbc0ce49e0d3786fbc830173f7788b44f6678  /opt/nginx-1.30.1/sbin/nginx
490e476557984aa0dab3ba18729f321603c38d74bd68ec6569fa56cf50025187  lab/conf/nginx-matrix.conf
3486a3152eec218a4b033592ca7974ccbedb904b2ecb3c432d3d60d26581f633  lab/conf/php-matrix.ini
6f02d73469138c956d0449acf6f314b7799a7636fc05ad8cddb58f9561660ce1  lab/conf/fpm-matrix-d5.conf
079e2e68a22f23329bc2132c28b8c6ea0092dfd114789dd10ac508a07db7896f  lab/conf/fpm-matrix-d20.conf
f772f6624af542277e906ccf339bc733c63dff469ae3c356c788b88ecbde0a01  lab/conf/fpm-matrix-d50.conf
ddff01154ffaca0c601ad80b205ccaa2ade47ae9664928c9f1862d42dfb01572  lab/conf/fpm-matrix-s5.conf
ef4560a46b45d543a5287213a80d610cb3e0d95f8dcbe71dd2f183a85ad91a12  lab/conf/fpm-matrix-s20.conf
2a600933bef60417e875d3fe6e288095488ef05049a08a3abd822f5e6e74f281  lab/conf/fpm-matrix-s50.conf
6f83161924f63a193da45b5b4d92773d895acc8392fcae72b4dd0ad86177d8a5  lab/conf/fpm-matrix-s2.conf
fb52555e725456535c0ae0b8982085fd9e50ba1a08f1c64280c618072f5beba8  lab/conf/fpm-8511matrix.conf
34fa8914fc46966eb3ee5b1a9a0ccdb3247e489261d6d4d4316fbf105db71368  lab/conf/php-8511matrix.ini
686c547db48665def748358b461cee1f1dacbe8598de39a0a98d4c2ccde59890  scripts/matrix_run.py
b4d0b9090f276280fd945f3d38af17980e53995170548b2ebd7bbca8c6dff11a  scripts/matrix_consumer_wave.py
e1d4092e184cb30c33ddca6e836db01c1aba289dbd90ae6ac367aea878d20492  scripts/a1a2_raw.py
96c140843e67fc2854d986dfd80bb645fed7b3e051e262c7a87244688c3fb3c6  scripts/t1_raw.py
6030ae6bfcf56a6cc531e5c753165d32396635d161378373dfd2befbec397572  scripts/t3_raw_fcgi.py
```

### 8.3 Evidence manifest

`evidence/matrix/SHA256SUMS` contains the SHA-256 of every matrix evidence file (104 files), including all `result.json`, access/error slices, and the partial-STDIN output:

```
dd1f0150a54768b5aa346bb9f1556e3667d6a7a09bfe60cecd6206546fc3346e  evidence/matrix/SHA256SUMS
```

The addendum's own SHA-256 is written to `addendum_multiworker.md.sha256` after this file is written.

### 8.4 Logs and evidence paths

FPM/nginx/PHP logs:

- `lab/logs/fpm-matrix-access.log`, `lab/logs/fpm-matrix-error.log`, `lab/logs/php_matrix_error.log`;
- `lab/logs/nginx-matrix-access.log`, `lab/logs/nginx-matrix-error.log`;
- `lab/logs/fpm-s2-access.log`, `lab/logs/fpm-s2-error.log`;
- `lab/logs/fpm-8511matrix-access.log`, `lab/logs/fpm-8511matrix-error.log`, `lab/logs/php_8511matrix_error.log`;
- `lab/logs/fpm-t3-access.log`, `lab/logs/fpm-t3-error.log` (partial-STDIN target, port 29361).

Per-run evidence directories under `evidence/matrix/`:

```
d5dec2  d5enc  d20dec  d50dec  d50dec_wave2
s5dec  s20dec  s20dec_wave2  s50dec  s50dec_wave2  s50dec_wave3
d5off  8511d2  8511dpad  8511dp1  8511dp8  8511dp24
a1a2d  a1a2e  a1a2ctl  t1m  partial_stdin
```

Each directory contains `result.json`, `fpm_access_producers.txt`, `fpm_access_all.txt` and/or `access_new.txt`, `fpm_error_new.txt`/`error_new.txt`, and the corresponding nginx access slice. The parent report and its `evidence/gdb/` files remain the source for the exact UAF backtraces.

### 8.5 Compliance

- `report.md` not modified; its hash is unchanged.
- No push, commit, or pull request; no repository operation.
- No shared service was restarted. The matrix used dedicated lab FPM pools on 29501/29508/29510 and existing lab nginx vhosts 29511/29512/29518. The T3 pool on 29361 and the lab nginx instances were left running and untouched; unrelated Docker nginx/php-fpm were not touched.
- The T1/Moodle-shaped consumer is a lab replica, not a production Moodle install; the stock-target conclusion is about the PHP-FPM engine primitive, not a full Moodle exploit.
