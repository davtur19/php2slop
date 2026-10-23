# Fork-stable ASLR vs. 1–2 byte partial pointer overwrite on the FPM `BG` serializer UAF

**Run root:** `/tmp/opencode/research/fpm_aslr_20261023T073345Z/`
**Date:** 2026-10-23 (log timestamps UTC; file mtimes UTC+2)
**Status:** local lab evidence only. No push, commit, PR, advisory or shared service was touched.
**Prior work used as the bug baseline:** `/tmp/opencode/research/fpm_bg_20261023T021053Z/report.md`
(pre-RINIT reuse of stale `BG(unserialize)` / `BG(serialize)` after an OOM bailout; proven on
stock PHP-FPM 8.4.26 and 8.5.11, fixed in 8.5.12).

---

## 1. Question and verdict

Question: **do fork-stable ASLR bases make a 1–2 byte partial pointer overwrite practical against
the proven FPM `BG` serializer UAF?** The overwrite primitive is the attacker-controlled multipart
`pad` field, which (before the session decode) reuses the freed request chunk and can rewrite the
stale 72-byte `php_unserialize_data` / `php_serialize_data` structure.

**Verdict:**

| Lane | Classification | Why |
|---|---|---|
| 1–2 byte partial overwrite (decode `last`, `first_dtor`, `last_dtor`; encode `arData`, `pDestructor`) | **DEAD** | Every partially-overwritten pointer either (a) keeps its high bytes aimed **inside the request chunk** (decode fields are chunk pointers or `NULL`), or (b) points into a **read-only garbage block** (encode `arData` was observed inside the `r--p` PIE segment in the stale state), or (c) is **never called** (encode `pDestructor`). A 1–2 byte retarget therefore cannot reach a useful writable out-of-chunk object. |
| Full 8-byte pointer / full-address brute force | **DEAD on stock; “noisy-but-possible” only off-stock** | The base is genuinely fork-stable per master (all workers and respawns identical), so it is a fixed-target search. But it is still unknown with **page-granular 2^28 entropy**, and the measured oracle rate is **~8 crash-oracle events/s on a stock 5-child dynamic pool** and **~22/s on a dedicated single-worker pool**. 50 % coverage = **70–194 days**, ~1.3×10^8 guesses, ~9–10 TB of pad traffic and ~10^8 worker kills/FPM warnings. With a hypothetical 100+ child pool the 50 % point drops to ~14 days, which is noisy-but-possible, but that is not a stock configuration. |

Exactly which pointer must be guessed:

- **Never guessed:** the stale pointer itself. `BG(unserialize).data` / `BG(serialize).data` and the
  address `X` of the stale structure are supplied by the UAF. The parsed pad starts at a
  deterministic `V = chunk+0x6c000`, so a pad byte at offset `0x11000` lands exactly on `X` with
  **no address knowledge at all** (proven below).
- **Must be guessed for any out-of-chunk effect:** the *target* address written into
  `last_dtor` (`X+0x10`) or `first_dtor` (`X+0x8`) on the decode side, or `ht.arData`
  (`X_ser+0x10`) on the encode side. All of these are absolute 8-byte pointers. A 1–2 byte
  overwrite preserves the high 6–7 bytes of the *existing* field; none of the existing fields
  has high bytes aimed at a usable writable out-of-chunk object.
- **Base stability:** stable enough for a *fixed-target* search, not stable enough to help a
  partial overwrite. The base is identical across all workers, across worker crashes/respawns and
  across Apache children of one master (tables in §3); it changes only when the master itself is
  restarted/reloaded.

---

## 2. Environment and method

### 2.1 Lab

| Role | Version | Front end | Pool | Notes |
|---|---|---|---|---|
| Target, stock | PHP-FPM 8.4.26 (docker stock binary) | nginx 1.30.1 :29320 | :29321 `pm=dynamic`, `max_children=5`, `start_servers=2` | primary stock target |
| Target, stock | PHP-FPM 8.4.26 | nginx :29355 | :29356 `pm=static`, `max_children=1` | dedicated deterministic oracle |
| Target | PHP-FPM 8.5.11 (locally built plain PHP) | nginx :29352 | :29351 `pm=static`, `max_children=1` | deterministic oracle |
| Target | PHP-FPM 8.5.11 | nginx :29354 | :29353 `pm=dynamic`, `max_children=5` | stock-shaped |
| Control (fixed) | PHP-FPM 8.5.12 | nginx :29330 | :29331 `pm=dynamic` | fix control |
| Control (fixed) | PHP-FPM 8.5.12 | nginx :29357 | :29358 `pm=static`, `max_children=1` | fix control, single worker |
| ASLR layout control | Apache prefork + mod_php 8.4.26 | 127.0.0.1:19381 | master + 6 children | base-stability control only |
| Stability sweeps | 8.4.26 / 8.5.11 / 8.5.12 | — | 10-worker `pm=static` pools :29322/:29323/:29324 | 2 kill/restart cycles each |

Machine state: `/proc/sys/kernel/randomize_va_space = 2` (ASLR on). Both FPM INIs use
`display_errors = Off`, `log_errors = On`, `session.serialize_handler = php`. Stock nginx defaults
(`client_max_body_size` 1 MiB — a 1.5 MiB pad returns 413, so all pads are ≤ 900 000 bytes).
`/proc/sys/vm/mmap_rnd_bits` is **not readable** by the unprivileged lab user; the 28-bit x86-64
Linux default is used in the model and corroborated by the observed 4 KB-granular bases.

The UAF itself (producer OOM inside `php_var_unserialize` / `php_var_serialize`, stale `BG` state,
pre-RINIT session decode of the next multipart upload-progress request on the same worker) is the
one proven in the prior report; this report does **not** re-derive it. Producers here are
`producer_oom.php?n=8000000` (decode side, 8 M-element array → OOM bailout) and
`producer_ser_oom.php?n=300000` (encode side 8.5.11), run against the same worker that later
serves `/consumer.php` with `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS`.

### 2.2 Measurement tools

- `bin/maps.py <pid>` and raw `/proc/<pid>/maps` copies in `evidence/maps/`.
- `bin/oracle.py` — sends producer→consumer, reads the FPM error log, times every phase.
- `bin/batch.py` — concurrent producer batch + concurrent consumer batch on a dynamic pool.
- `bin/uaf_send.py` — multipart sender (`PHPSESSID`, `pad`, `PHP_SESSION_UPLOAD_PROGRESS`).
- gdb scripts: `bin/fake2.gdb` (decode struct dump / fake struct), `bin/partial.gdb` (partial
  overwrite words + target dump), `bin/place.gdb` (pad start marker), `bin/ser_probe.gdb`
  (encode-side `php_serialize_data` dump).

---

## 3. Base stability (the “fork-stable” premise)

### 3.1 FPM: all workers of a master share the same bases

10-worker `pm=static` pools, master + 10 children sampled in 8 phases (baseline, kill cycle 1
idle/in-flight, respawn idle/in-flight, kill cycle 2 idle/in-flight). **Every one of the 11 PIDs in
every phase had the identical values below.**

| Version | fpm PIE base | libc base | request chunk base (2 MB rw-p) | observations |
|---|---|---|---|---|
| 8.4.26 stock | `0x555d50800000` | `0x7fb2e2f03000` | `0x7fb2e2000000` | 11 PIDs × 8 phases |
| 8.5.11 | `0x55dfd9000000` | `0x7f2511372000` | `0x7f250e5af000` | 11 PIDs × 8 phases |
| 8.5.12 | `0x55bef2200000` | `0x7f9d54c0c000` | `0x7f9d51faf000` | 11 PIDs × 8 phases |

Raw JSON: `evidence/maps/8426_*.json`, `8511_*.json`, `8512_*.json`; raw maps
`evidence/maps/raw_<ver>_<phase>_<pid>.map`.

The request chunk is **page-aligned, not reliably 2 MB-aligned** (`0x7f250e5af000`,
`0x7f9d51faf000`), so the mmap base entropy is page-granular: up to 2^28 pages (4 KB) under the
default x86-64 `mmap_rnd_bits=28`. The 8.4.26/8.5.11 post-reboot masters happened to be
2 MB-aligned, which is luck, not a property.

### 3.2 FPM: the base survives worker crashes and respawns

Post-reboot dedicated 8.4.26 single-worker pool, killed by the real UAF+pad:

| Phase | child PID | fpm PIE | libc | chunk |
|---|---|---|---|---|
| before crash/in-flight | 249993 | `0x5611f9600000` | `0x7fb0c9cd9000` | `0x7fb0c8e00000` |
| after SIGSEGV + respawn | 250856 | `0x5611f9600000` | `0x7fb0c9cd9000` | `0x7fb0c8e00000` |

Raw: `evidence/maps/raw_8426s_before_249993.map`, `raw_8426s_after_250856.map`.
The 8.5.11 static pool likewise reproduced `X = 0x7f4e85c7d000` (chunk
`0x7f4e85c00000` + `0x7d000`) across the crash oracle’s three respawns, and the 8.5.12 static pool
kept the same worker and the same chunk across the whole control.

### 3.3 Apache prefork + mod_php 8.4.26

Master 25809 and children 25845/25846/25847/25849/25850, plus children respawned after a kill
(42965, 42978, 42979): **all have identical bases**:

| Mapping | Address |
|---|---|
| libphp | `0x7fc66af6a000` |
| apache2 | `0x55af710f9000` |
| libc | `0x7fc66c407000` |
| inherited request chunk (2 MB rw-p) | `0x7fc669200000` |

Raw: `evidence/maps/raw_ap8426_*.map`. The prefork model gives the same fork-stable,
fixed-target property as FPM.

**Conclusion:** fork stability is real and strong. It converts the brute force into a search over a
*fixed* 2^28-page window per master rather than a re-randomized target per attempt. It does **not**
reduce the size of that window and it does not help a partial overwrite escape the region its
preserved high bytes already point at.

---

## 4. The overwrite primitive: arbitrary struct bytes at a deterministic X

### 4.1 Deterministic geometry (8.5.11 static, post-reboot master)

| Quantity | Value | How measured |
|---|---|---|
| chunk base | `0x7f4e85c00000` | `/proc/pid/maps` 2 MB rw-p anon |
| pad parsed-value start `V` | `chunk+0x6c000` = `0x7f4e85c6c000` | 16-byte magic at pad offset `0x100` found at `V+0x100` (`evidence/gdb/place1.log`) |
| stale decode struct `X` | `chunk+0x7d000` = `0x7f4e85c7d000` | `php_var_unserialize_init` udata at first pre-RINIT decode |
| pad offset that lands on `X` | `X-V = 0x11000` | fixed-struct run: W0..W7 exactly as written (`evidence/gdb/fake2.log`) |
| stale encode struct `X_ser` | `chunk+0x82040` = `0x7f4e85c82040` | `php_var_serialize_init` sdata (`evidence/gdb/ser_probe.log`) |
| pad offset that lands on `X_ser` | `X_ser-V = 0x16040` | geometry above |

For 8.4.26 the decode struct is at `chunk+0x6f000`
(`X = 0x7fb0c8e6f000`, chunk `0x7fb0c8e00000`, `evidence/gdb/fake2_8426.log`).

`V` was identical for a 68 KB pad and a 900 KB pad, and `X` was identical across consecutive
producers, workers and respawns. No address needs to be known to hit `X`; the attacker only needs
the correct pad byte offset.

### 4.2 Full struct control is proven on both versions

- **8.5.11:** 900 000-byte pad of `'A'` → at the first pre-RINIT decode all eight words at `X`
  read `0x4141414141414141`; crash in `var_tmp_var` with `rax=0x4141414141414141`
  (`evidence/gdb/fake2.log`, `evidence/req/pad_fake1.bin`). NUL bytes in the pad survive (a
  DEADBEEF prefix + zero body produced zeros at `X`, not truncation).
- **8.4.26:** same pad → `X=0x7fb0c8e6f000`, all eight words `0x4141…`, `SIGSEGV` in
  `var_tmp_var` with `rax=0x4141414141414141` (`evidence/gdb/fake2_8426.log`).

### 4.3 A fully valid fake struct is accepted (8.5.11)

Pad (`evidence/req/pad_fake2.bin`, struct at offset `0x11000`):

```
last       = X+0x38        first_dtor = 0
last_dtor  = T = X+0x2000  allowed = 0, ref_props = 0
cur_depth  = 0             max_depth = 0x1000
entries.used_slots = 0     entries.next = 0
```

Result: **HTTP 200**, no crash, and the decoder used `last_dtor=T` as a `var_dtor_entries` table:

- `T+0x00` (`used_slots`): `1 → 3 → 5` across the request’s decode passes.
- `T+0x10`: `0x00007f4e85c57200` (a heap `zend_string*` of the decoded session value).
- `T+0x18`: observed `0` (`IS_UNDEF` type_info) in this 8.5.11 build; the 8.4.26 source path
  (`var_push_dtor_value` → `ZVAL_COPY_VALUE`) sets the type word as well. This detail is not
  load-bearing for the ASLR verdict: the primitive is a 16-byte dtor-slot write whose first word is
  a decoder-owned heap pointer and whose counter word is attacker-visible.

So the attacker can place **any 72 bytes** at `X` with no address knowledge. The constraint is not
*what* can be written there, it is *where else* those bytes can point.

---

## 5. 1–2 byte partial overwrite: measured, and confined

The partial overwrite is done by choosing the pad length so the copy ends inside a field.
Because the parsed value is copied as a `zend_string` of length `L` **plus its NUL terminator**,
`L = (X - V) + n` writes `n+1` bytes: the pad’s last `n` value bytes plus the terminator. On 8.5.11,
`V=0x6c000`, `X=0x7d000`; `L=0x11000` gives 1 byte (`n=0`, terminator only) and `L=0x11001` gives
2 bytes (offsets verified because the pad start is deterministic).

### 5.1 1-byte overwrite of decode `last` (`X+0x0`)

Pad `evidence/req/pad_p0.bin`: 0x11000 bytes. The multipart value is copied as a `zend_string`
of length `L` **plus its NUL terminator**, so a pad ending at `X-1` writes the terminator byte at
`X`: the single byte landing on the field is `0x00`.

| Observation | Value |
|---|---|
| stale `last` before pad | `0x7f4e85c7d038` |
| `last` after 1-byte pad | **`0x7f4e85c7d000`** (low byte `0x38 → 0x00`, high 7 bytes preserved) |
| target region | same 256-byte window, `chunk+0x7d000…+0x7d0ff`, **inside the 2 MB request chunk** |
| decoder used it? | yes — `SIGSEGV` in `php_var_unserialize_internal`, `rax=0x7f4e85c7d000`, via `php_session_decode` → `php_session_initialize` |

Log: `evidence/gdb/partial_p0.log`.

### 5.2 2-byte overwrite of decode `last` (`X+0x0`)

Pad `evidence/req/pad_p1.bin`: 0x11001 bytes. The two bytes that land at `X`/`X+1` are the
value's last byte `0x40` and the `zend_string` NUL terminator `0x00`.

| Observation | Value |
|---|---|
| stale `last` before pad | `0x7f4e85c7d038` |
| `last` after 2-byte pad | **`0x7f4e85c70040`** (low 16 bits `0xd038 → 0x0040`, high 6 bytes preserved) |
| target region | same 64 KB block `0x7f4e85c70000…+0xffff`, **inside the request chunk** |
| decoder used it? | yes — the rewritten pointer was consumed as the `var_entries` table; a follow-up int-session run left `used_slots=0x2e` and `data[]` pointers at `0x7f4e85c70040` |

Logs: `evidence/gdb/partial_p1.log`, `evidence/gdb/partial_int.log`.

Both overwrites work mechanically, both preserve the expected high bytes, and both were
dereferenced by the decoder. The target is in every case still inside the **same request chunk**
that the attacker already controls. This is the decisive point: the stale decode structure contains
**no absolute pointer aimed outside the chunk**:

```
last            = chunk+0x7d038   (chunk pointer; embedded entries)
first_dtor      = NULL
last_dtor       = NULL            (producer_oom path)
allowed_classes = NULL
ref_props       = NULL
entries         = embedded in the struct
```

A 1–2 byte rewrite of any of those fields can only land within ±64 KB of a chunk address or at
`0x0000…00xx`; there is no out-of-chunk pivot to preserve. To write outside the chunk, the full
8-byte `last_dtor` (or `first_dtor` / `allowed_classes`) must be supplied — a full-address guess.

Note: `last_dtor = 0` in this producer. A different producer path (`producer_mix`, prior report)
can leave a real `last_dtor` chunk pointer, but it is still a chunk pointer and the same confinement
argument applies.

---

## 6. Encode-side stale structure: the one out-of-chunk pointer is unusable

`php_serialize_data` at `X_ser = chunk+0x82040` (8.5.11 static), measured in
`evidence/gdb/ser_probe.log` after `producer_ser_oom.php?n=300000`:

```
ht.gc          = 0x0000000700000001
ht             = packed (nTableMask = -2), nNumUsed = 0, nTableSize = 0x10
ht.arData      = 0x55eb00adff48   <-- inside the r--p PIE segment
ht.pDestructor = 0x55eaffbe92f0   <-- ZVAL_PTR_DTOR in the PIE
data.n         = 0x4a4713080001dffb (garbage)
```

Mapping check: `0x55eb00adff48` lies in
`55eaffe01000-55eb00bca000 r--p` (the **read-only** php-fpm segment), while the writable PIE
segment starts at `55eb00cb0000`. So in this stale state `arData` is a garbage read-only pointer,
not a usable bucket array. (The field is uninitialised in the stale state, so other OOM timings can
leave a different garbage value; a value in a writable mapping would make a 2-byte retarget a
64 KB-window heap corruption, but the pDestructor conclusion below is independent of that value and
the observed state did not provide a writable bucket array.)

Why `pDestructor` does not save the partial lane: `php_add_var_hash()` performs only
`zend_hash_index_find()` + `zend_hash_index_add_new()`. In `Zend/zend_hash.c`
(`_zend_hash_index_add_or_update_i`):

- packed table, existing slot, `HASH_ADD_NEW`: `if (flag & HASH_ADD) return NULL;` — returns
  **before** any `pDestructor` call;
- mixed table: the find is skipped unless `ZEND_DEBUG`; the insert path does not call
  `pDestructor`;
- resize/`packed_to_hash` conversion moves buckets; it does not call `pDestructor`.

Therefore the only code pointer in the stale encode structure (`pDestructor`, a PIE address whose
1–2 byte partial rewrite would stay in the same 64 KB/256 B PIE neighbourhood) is **never
dereferenced**. The only *used* out-of-chunk field is `arData`, and a 1–2 byte rewrite of
`0x55eb00adff48` keeps the target in the read-only 64 KB block `0x55eb00ad0000…+0xffff`; the packed
table with `nNumUsed=0` and a huge insertion index then follows the
`zend_hash_packed_to_hash` → `efree(arData)` path, i.e. an **invalid free of a read-only address**
(a crash oracle), not a controlled write. The prior report cross-checks this exact crash path.

A *full* fake encode struct (`arData` = attacker-chosen writable address) would reach that
`efree(arData)` with an absolute target — a controlled-free primitive, but again an 8-byte
full-address guess, not a 1–2 byte one.

---

## 7. Brute-force model and measured oracle

### 7.1 The oracle is fast and unambiguous on a pinned worker

`bin/oracle.py`, 900 KB `'A'` pad, single-worker pools:

| Pool | Reps | producer | consumer | crash log after consumer | ping after |
|---|---|---|---|---|---|
| 8.4.26 stock, static 1 | 3/3 crashed | 30.7 / 31.8 / 33.6 ms | 502 in 3.5 / 3.6 / 3.9 ms | 3.7 / 3.8 / 4.0 ms | 200 |
| 8.5.11, static 1 | 3/3 crashed | 41.3 / 40.5 / 42.1 ms | 502 in 3.6 ms | 3.8 ms | 200 |
| 8.5.12, static 1 (fixed) | 0/2 crashed | 500 | **200**, `SESSION=unset`, same PID 249529 | — | 200 |

Raw: `evidence/req/oracle_8511s.json`, `.../oracle_*.json`, `lab/logs/fpm-*-error.log`.
A miss is a **502 in ~4 ms**; a hit (mapped writable target) is a **200**. The producer is the cost
centre at 30–42 ms.

### 7.2 Stock dynamic pools: affinity is the limiter

Without priming, producer→consumer pairs on the stock `pm=dynamic` pools frequently land on
**different** workers, and the UAF does not fire: 3/3 pairs returned 200 with no crash on 8.4.26
:29320, and 2/2 on 8.5.11 :29354. The stale `BG` state is per-worker; the consumer must hit the
producer’s worker.

Priming all workers concurrently (`bin/batch.py`: 5 concurrent producers, then 5 concurrent
consumers) on the stock 5-child pools produced **exactly 2/5 crashes per batch, reproducibly**:

| Pool | batches | crashes/batch | batch wall | implied rate |
|---|---|---|---|---|
| 8.4.26 stock dynamic | 3 | 2/5, 2/5, 2/5 | 279 / 243 / 259 ms | ≈ 8 crash events/s |
| 8.5.11 dynamic | 2 | 2/5, 2/5 | ~250 ms | ≈ 8 crash events/s |

The other three consumers either reached unprimed/new workers or a worker whose heap layout the
900 KB pad did not cover; they returned 200 and produced no oracle signal. So the *effective* stock
rate is ~8/s, not 5×22/s.

### 7.3 Brute-force time table

Search space: one fixed target per master with the mmap base randomized over 2^28 pages (4 KB
granularity, 1 TB window). `50 %` = 2^27 guesses; `100 %` = 2^28. Rates from §7.1–7.2.

| Rate (guesses/s) | time to 50 % | time to 100 % | configuration |
|---|---|---|---|
| 8 | **194 days** | 388 days | measured stock 5-child dynamic pool |
| 22 | **70.6 days** | 141 days | measured dedicated single-worker static pool |
| 110 | 14.1 days | 28.2 days | theoretical best case: 5/5 stock workers primed every cycle (not observed) |
| 1000 | 1.55 days | 3.1 days | requires ~45–50+ children, non-stock |

Per-attempt volume: the pad must reach `X` at offset `0x11000` and carry the 72-byte struct, plus
multipart overhead ≈ **70 KB per guess**. 2^27 guesses ≈ **9.4–10 TB** on the wire; the 8.5.11
900 KB variant would be ~120 TB. Each attempt also runs a producer that allocates ~8 M zvals
(hundreds of MB of allocator churn) and OOMs, and each miss kills a worker and writes a
`child N exited on signal 11 (SIGSEGV)` FPM warning and a master respawn. At 2^27 misses that is
**~1.3×10^8 worker kills and log lines** — trivially visible to any monitoring/IDS, and a
self-inflicted DoS on the pool.

The base resets on any master restart/reload/deploy. The search must therefore complete inside a
single master lifetime; a deploy every few weeks makes even the 14-day theoretical case
unreliable.

### 7.4 Classification

- **Partial overwrite lane: dead.** It cannot leave the request chunk / the stale garbage block;
  the measured targets in §5 are both inside the chunk the attacker already controls, and §6’s only
  partially-rewritable out-of-chunk fields are inert or read-only. There is no 2^8/2^16 search that
  reaches a security-relevant object.
- **Full-address brute force: dead on stock.** 70–194 days at 50 % on the measured rates, ~10 TB,
  10^8 detectable worker crashes, and a master-lifetime constraint. It becomes “noisy-but-possible”
  only in a non-stock, long-lived, 100+ child configuration (~14 days at 50 %), which is why the
  honest label is **noisy-but-possible in principle / not viable on stock**.

---

## 8. Controls

### 8.1 8.5.12 (fixed)

Producer 500 (OOM still occurs), consumer **200**, `SESSION=unset`, same worker PID 249529, no
SIGSEGV, session file unchanged (`p|s:5:"hello";`). 2/2 on the dedicated static pool and 2/2 on the
8.5.12 dynamic pool. The fix in `php_basic_early_rinit()` clears the stale level before the
pre-RINIT session handling, so no stale structure is reused and the whole lane (partial or full) is
absent.

Raw: `evidence/req/oracle_*.json`, `lab/logs/fpm-8512s-error.log`.

### 8.2 Apache prefork + mod_php 8.4.26

Base stability only (scope): master + children + respawns identical (§3.3). Request-time UAF
behaviour under mod_php was not re-tested in this run; the ASLR argument is version/lab independent
and the prefork control confirms the same fork-stable property.

---

## 9. What would change the verdict

- Any **absolute pointer leak** (a heap/libc/PIE address) would collapse the 2^28 search to one
  guess, and would also give a meaningful full fake struct target.
- A stale field whose *existing* high bytes already point at a writable out-of-chunk object. None
  was found: decode fields are chunk-local or `NULL`; encode `arData` is read-only garbage;
  `pDestructor` is never called.
- An oracle that does not require re-running the producer per miss. None was found: the state is
  per-worker and a miss crashes the worker, so each attempt needs a fresh producer.
- An environment with materially lower mmap entropy (e.g., 32-bit, `mmap_rnd_bits` small, or a
  container runtime with a fixed mapping layout). Not the case here (ASLR=2, page-granular
  28-bit mmap randomization).

---

## 10. Artifact manifest

```
evidence/maps/
  8426_*.json 8511_*.json 8512_*.json          # 10-worker stability phases (11 PIDs each)
  raw_8426_baseline_*.map … raw_8512_*.map     # raw /proc/pid/maps
  raw_8426s_before_249993.map
  raw_8426s_after_250856.map                   # crash → respawn, identical bases
  raw_ap8426_*.map                             # Apache master/children/respawns
  summary_*.json

evidence/gdb/
  place1.log          # V = chunk+0x6c000 via marker at pad+0x100
  fake2.log           # 8.5.11 valid fake struct; T writes (used_slots 1→3→5, heap ptr)
  fake2_8426.log      # 8.4.26 full 0x41 control; X=chunk+0x6f000; rax=0x4141…
  partial_p0.log      # 1-byte: last 0x…d038 → 0x…d000, decoder used it
  partial_p1.log      # 2-byte: last 0x…d038 → 0x…0040, decoder used it
  partial_int.log     # var_entries used_slots=0x2e at the 2-byte target
  magic.log probe_*.log
  ser_probe.log       # encode struct: RO arData, PIE pDestructor, garbage n

evidence/req/
  pad_fake1.bin pad_fake2.bin pad_magic.bin
  pad_p0.bin pad_p1.bin pad_p2.bin pad_place_11001.bin
  oracle_8511s.json chain_8426_decode_decode.json probe_*.raw

bin/
  maps.py oracle.py batch.py uaf_send.py
  fake2.gdb partial.gdb place.gdb ser_probe.gdb stab10.py
conf/
  nginx.conf fpm-*.conf php-*.ini
lab/
  www/ (producer_oom.php producer_ser_oom.php consumer.php ping.php …)
  sessions/ (sess_padsid1 p|s:5:"hello"; sess_bgser1 …; sess_intsid1 p|i:1; sess_arrsid1 …)
  logs/ (fpm-*-error.log, fpm-*-access.log)
```

**Digests:** `evidence/sha256.txt` contains SHA-256 for every pad, gdb log, raw map, pool config and
PHP binary used in this report. Key entries:

| Artifact | SHA-256 |
|---|---|
| `evidence/req/pad_fake1.bin` | `125ed855fd4bd8487b298cb9c1c06250f73cec3921b9107e86fcda2a8bc2dcc8` |
| `evidence/req/pad_fake2.bin` | `6440256fd528141573c872e687ad36b4d4868815186bd9300a0cd05954d64c40` |
| `evidence/req/pad_p0.bin` (1-byte) | `011c79a93e9d22c41898a2aac99f9f2768140427b38c088b2cbfa942ba2d0c4a` |
| `evidence/req/pad_p1.bin` (2-byte) | `b1ce3c4d007e46c9f778439fe93826df677123de38ec12c2040176772acafea7` |
| `evidence/gdb/fake2.log` | `d243eb9b762c207648a77b3b2783ec0e93416bb47e691e992a8744929fde877f` |

Reproduce the crash oracle:

```sh
python3 bin/oracle.py --port 29355 --log lab/logs/fpm-8426s-error.log --reps 3
python3 bin/oracle.py --port 29352 --log lab/logs/fpm-8511s-error.log --reps 3
python3 bin/oracle.py --port 29357 --log lab/logs/fpm-8512s-error.log --reps 2   # fixed: 200
python3 bin/batch.py  --port 29320 --log lab/logs/fpm-stock-error.log  --n 5 --batches 3
```

Partial overwrite reproduction: `bin/partial.gdb` with a producer + `uaf_send.py
--sid intsid1 --pad-file evidence/req/pad_p0.bin` (1 byte) or `pad_p1.bin` (2 bytes).

---

## 11. Limitations

- The producers are lab wrappers that force the OOM at a controlled point; the underlying UAF
  chains are the prior report’s, not re-derived here.
- The 8.5.11 binary is a locally built plain PHP; 8.4.26 is the stock docker binary. The ASLR /
  oracle conclusions are about the OS/allocator and FPM, not about a distro patch set.
- `/proc/sys/vm/mmap_rnd_bits` was not readable in the lab; 28 bits is the x86-64 default and is
  consistent with the observed 4 KB-granular bases, but the exact configured value could not be
  confirmed.
- The encode-side `arData`/`pDestructor` observation is one stale state (OOM timing dependent); the
  “`pDestructor` unreachable” conclusion is enforced by source inspection of
  `php_add_var_hash`/`_zend_hash_index_add_or_update_i`, which is version-controlled code, not by
  that single dump.
- The 2-byte decode target was observed used (`used_slots=0x2e`) in a follow-up request on the same
  worker; the target address was reused across requests, which is expected because `X` and `V` are
  deterministic per master.
- No working exploit chain was attempted beyond the destructive probes. The value written by the
  valid fake struct on 8.5.11 was a decoder-owned heap pointer with observed `IS_UNDEF` type info;
  even a correct full-address target therefore yields a constrained write/free primitive, not
  immediate code execution.
- Apache was measured for base stability only; the request-time UAF under mod_php is out of scope
  for this run.

---

## 12. Bottom line

1. Fork-stable ASLR is **real and strong**: every worker and every respawn of a master, and every
   Apache prefork child, shares identical fpm/libc/chunk bases, and the stale structure `X` is at a
   deterministic chunk offset.
2. It does **not** rescue the 1–2 byte partial overwrite. The only pointers that can be partially
   rewritten are chunk-local or `NULL` (decode), or read-only/inert (encode). The measured 1-byte
   and 2-byte rewrites both landed inside the attacker-controlled request chunk; the encode
   `arData` rewrite lands in the read-only PIE block, and `pDestructor` is never called.
3. The full-address brute force is a fixed-target search, but the target window is 2^28 pages and
   the stock oracle rate is 8–22 guesses/s, i.e. **70–194 days for 50 %**, ~10 TB of traffic and
   ~10^8 worker crashes. That is **dead on stock**; it is “noisy-but-possible” only in a non-stock
   100+ child, long-lived-master configuration (~14 days at 50 %).
4. A single absolute pointer leak would change the answer immediately; none is available from the
   UAF as measured.
