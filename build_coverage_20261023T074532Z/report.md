# Affected-build coverage — CVE-2026-109618 / CVE-2026-109619 (stock mod_php, prefork)

**Run dir:** `/tmp/opencode/research/build_coverage_20261023T074532Z`
**Date:** 2026-10-23 (UTC). **Scope:** coverage (§1–§8) plus the full-chain extension in §9 (8.0 / 8.1 / 8.2 / 8.3 / 8.5; 8.4.26 is used only as a positive control and is excluded from the requested matrix).
**Status:** all requested branches sampled. **No RCE is claimed for 8.0 / 8.1 / 8.2 / 8.3 / 8.5**: exact blockers are recorded in §9.4. The only full-chain RCE in this report is the 8.4.26 positive control (3/3 independent runs, §9.2). No push, commit, PR, or advisory. Local evidence only.

---

## 1. Verdict in one table

| Build | Branch | Test | Result | Classification | Evidence |
|---|---|---|---|---|---|
| **8.5.0** | 8.5 | A1 as-is → B1 as-is | A1 500 (274 B, **cookie sent**), B1 max 40 B | parse-OOM (as-is body), no leak | `out/850/result_run1.json`, `out/850/b1_*.resp` |
| **8.5.0** | 8.5 | A1 8.5-tuned → B1 8.5 | A1 500 (210 B, **no cookie**), B1 **819,208 B** leak @i=4 | **leak reached** | `out/850/b1_85_4.resp` |
| **8.5.5** | 8.5 | A1 as-is → B1 as-is | A1 500 (274 B, cookie sent), B1 max 40 B | parse-OOM, no leak | `out/855/result.json` |
| **8.5.5** | 8.5 | A1 8.5-tuned → B1 8.5 | A1 500 (210 B), B1 **819,208 B** @i=4 | **leak reached** | `out/855/b1_85_4.resp` |
| **8.5.11** | 8.5 | A1 as-is (one-off) | A1 500 (275 B, cookie sent) | parse-OOM (as-is body) | `out/8511/a1_asis.resp` |
| **8.5.11** | 8.5 | A1 8.5-tuned → B1 8.5 | A1 500 (211 B), B1 **819,208 B** @i=4 | **leak reached** | `out/8511/b1_85_4.resp` |
| 8.5.12 | 8.5 | A1 as-is | **200 OK**, no OOM, normal cookie | **fixed control** | `out/8512/result.json` |
| **8.3.0** | 8.3 | A1 as-is | **200** (no OOM) | no-OOM | `out/830/result.json` |
| **8.3.0** | 8.3 | A1 sweep 820/880/920/1000/1060 + B1 | 820→200; ≥880→500; B1 **34 B** (miss) | **parse-OOM only** | same |
| **8.3.10** | 8.3 | A1 as-is + sweep | identical to 8.3.0 | **parse-OOM only** | `out/8310/result.json` |
| **8.3.20** | 8.3 | A1 as-is + sweep | identical to 8.3.0 | **parse-OOM only** | `out/8320/result.json` |
| **8.3.35** | 8.3 | A1 as-is + sweep | A1 500 (211 B); sweep 820→200, ≥880→500; B1 **34 B** | **parse-OOM only** | `out/8335/result.json`, `logs/g8335.log` |
| 8.3.36 | 8.3 | A1 as-is | **200** | **fixed control** | `out/8336/result.json` |
| **8.2.0** | 8.2 | A1 as-is + sweep | 860→200; 820→200; ≥880→500; B1 **34 B** | **parse-OOM only** | `out/820/result.json` |
| **8.2.15** | 8.2 | A1 as-is + sweep | identical to 8.2.0 | **parse-OOM only** | `out/8215/result.json` |
| **8.2.34** | 8.2 | A1 as-is + sweep | 860→**500**, ≥880→500, B1 **34 B** | **parse-OOM only** | `out/8234/result.json` |
| 8.2.35 | 8.2 | A1 as-is | **200** | **fixed control** | `out/8235/result.json` |
| **7.4.0** | 7.4 | A1 as-is | **200** (no OOM) | no-OOM | `out/740/result.json` |
| **7.4.0** | 7.4 | 109619 A→B ×3 | A **500 ×3** (OOM), B 200 ×3 + session-write warning, **no corruption** | **UAF probe negative** | `out/740/pair_*.resp` |
| **7.4.33** | 7.4 | A1 as-is + 109619 A→B | identical to 7.4.0 | **UAF probe negative** | `out/7433/result.json` |
| **7.2.0** | 7.2 | A1 as-is + 109619 A→B | A1 200; A **200 ×3** (no OOM); B 200 | **benign / no producer** | `out/720/result.json` |
| **7.2.34** | 7.2 | A1 as-is + 109619 A→B | identical to 7.2.0 | **benign / no producer** | `out/7234/result.json` |
| **7.0.33** | 7.0 | A1 as-is + 109619 A→B | A1 200; A 200 ×3; B 200 | **benign / no producer** | `out/7033/result.json` |
| **5.6.40** | 5.6 | A1 as-is + 109619 A→B | A1 200; A 200 ×3; B 200 | **benign / no producer** | `out/5640/result.json` |
| **7.0.0** | 7.0 | — | image unavailable (schema1) | **inferred only** | see §5 |
| **5.6.0** | 5.6 | — | image unavailable (schema1) | **inferred only** | see §5 |
| **8.1.33** | 8.1 | A1 as-is → B1 as-is | A1 500 (211 B), B1 **34 B** (miss) | **parse-OOM, no leak** (comparison only) | `out/8133/result.json` |
| **8.1.0** | 8.1 | — | not run | **source-equivalent only** | §4 |
| **8.4.26** | 8.4 | A1 as-is → B1 as-is (control) | A1 500 (211 B), B1 **819,208 B** @i=0 | control, harness validated | `out/8426/b1_0.resp` |

Notes on the classifier:
* "parse-OOM" = PHP died during multipart parsing (`Allowed memory size … exhausted`), no session state is consumable afterwards.
* "leak reached" = a subsequent B1 request returns a forged `Set-Cookie` far larger than a session id. This is the operational definition of the END-phase state in this report; it is not a claim of RCE.
* B1 "34 B" is the normal session-cookie length on 8.1/8.2/8.3 (32-hex id + `; path=/` minus encoding), i.e. a miss.
* No A2/B2 stage was run for any row in this table, so no row here is classified RCE; the 8.4.26 positive control (three full-chain runs) is in §9.2, and the requested-branch blockers are in §9.4.

---

## 2. Configuration and method (what was actually run)

| Item | Value |
|---|---|
| Images | official `php:<version>-apache` (mod_php, Apache 2.4.x prefork), digests in §7 |
| Workers | **stock prefork** (default 5 children) for every coverage row; the 8.4.26 control used the single-worker diagnostic (`conf/prefork1.conf`) |
| INI | each image's **own** `/usr/local/etc/php/php.ini-production` copied to `php.ini` (verified in-container: `display_errors=''` (Off), `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`, `max_execution_time=30`, `output_buffering=4096`, `max_input_vars=1000`, `session.upload_progress.enabled=1`) |
| Docroot | `www/index.php` = `<?php echo "OK ", PHP_VERSION, " pid=", getmypid(), "\n";` |
| ASLR | on (`kernel.randomize_va_space=2`, not modified) |
| A1 as-is | 9bie `mk_a1b.py` defaults, 1,060,211 B, `sha256 8e8fc166…` |
| B1 as-is | `mk_leak_b2.py` `G:511:0x137`×14,`G:400:0x137`,`G:511:0x137`,X:900, fake-len 0xC8000, 33,128,677 B |
| A1 8.5-tuned | `mk_a1b.py --big 78 --big-name-len 32 --tail 12`, 1,063,865 B, `sha256 ba775359…` (matches the prior 8.5.11 receipt byte-for-byte) |
| B1 8.5 | 16×`T:0x1fd300` + X:900, fake-len 0xC8000, 33,399,541 B |
| 109619 pair | generic producer `sess_A.bin` (3,000,438 B) + consumer `sess_B.bin` (219 B) from `oom109619_modphp_20261022T111008Z/lab` |
| Transport | A1/B1 chunked (bypasses the 8M `post_max_size` gate without config change); pair sent with Content-Length |

Delivery against the images: A1 → `POST /index.php?q0000000..4=v`, B1 → `POST /index.php`, `Connection: close`, no keep-alive, no pinning, no restarts between A and B except where stated.

Harness provenance check: an early attempt with a hand-written 9-line INI produced a 275-byte A1 with a normal `Set-Cookie` and **no** leak on 8.4.26. The cause was the missing `output_buffering=4096`; with the image's own `php.ini-production` the same build reproduces the documented reference exactly (A1 500 / **211 B**, B1 **819,208 B**). All rows in this report therefore use the image's production INI. This is recorded because it is the same failure mode that explains the prior 8.5.11 row (§3).

---

## 3. Correction to the prior 8.5.11 row (important)

The deep 8.5.11 lane reported: *"B1 PARTIAL — 8,200 B decoded, no libphp/main pointers"* and concluded a **leak-quality blocker** ("id page 0x1FD300 leaves only 0x2D00 B of usable window").

With the same image (`php@sha256:47e6d884…`, identical to that receipt's digest), the same A1 body (`sha256 ba775359…`), stock prefork and the production INI, this run measures:

| Build | B1 fake_len | decoded | pointer clusters | dominant cluster |
|---|---|---|---|---|
| 8.5.0 | 0xC8000 | **819,208** | 3 | 51 hits @ off 0x28 |
| 8.5.5 | 0xC8000 | **819,208** | 3 | 51 hits @ off 0x28 |
| 8.5.11 | 0xC8000 | **819,208** | 3 | 51 hits @ off 0x28 |
| 8.4.26 (control) | 0xC8000 | 819,208 | 4 | 7,495 / 1,095 / **87** / 79 hits |

`8,200 = 0x2000 + 8`, which is exactly `mk_leak_b2.py`'s **default** `--fake-len 0x2000` plus the 8-byte tag. This is not an inference: the prior lane's own B1 body is still on disk at `modphp_109619_20261023T010232Z/work/b1_8511_t.bin` (`sha256 33cd6b09…`), and its forged `zend_string` headers carry `len = 0x2000`. Byte-comparing it with a regeneration using the default fake length yields **64 differing bytes = 16 headers × 4 tag bytes, with every length field identical and equal to 0x2000**; the prior A1 body `work/a1_8511_t12.bin` hashes to `ba775359…`, i.e. byte-identical to the A1 used here.

The prior row is therefore **proven** to be a body-parameter artifact, not a build property: with the default fake length the cookie is 8,200 B, and with 0xC8000 the same image returns 819,208 B. **The "0x2D00 usable window" interpretation is not supported by this measurement.**

What *is* still true, and must not be overstated: the **content** of the 8.5 window differs from 8.4.

* 8.4: `head = "BBBB/BBBAAAAAAAA"`, **8,756** pointer qwords, dense spray; the chunk base appears as 87 hits at offset 0x59ff8 (the "main bucket 87" of the prior work).
* 8.5.0/.5/.11: `head = "BBBB/BBB\x00<hex>"` (a freed session-id string, not the A-spray), only **53** pointer qwords, 3 clusters; one 2 MiB-aligned base repeated 51× at offset 0x28.

So the 8.5 B1 does return a genuine 819 KB heap read containing a dominant 2 MiB-aligned base, but it is **sparse**, not the dense 8.4 pointer field, and no libphp code pointer is present in it. Whether that single cluster is sufficient for the 8.5 chain's `S = main + 0xF8398` step is **inferred, not tested** (A2/B2 not attempted). The correct summary is: **the "8,200 B window" blocker is withdrawn; a residual content-quality difference remains open.**

---

## 4. Branch-wide vs build-specific

| Branch | Builds tested here | Outcome | Verdict |
|---|---|---|---|
| **8.5** | 8.5.0, 8.5.5, 8.5.11 (+8.5.12 fixed) | all three: tuned A1 → 500/210-211 B; B1 → **819,208 B**, identical cluster geometry | **branch-wide and continuous**; the previously reported blocker does not reproduce on any sampled build |
| **8.3** | 8.3.0, 8.3.10, 8.3.20, 8.3.35 (+8.3.36 fixed) | all four: no consumable END-phase state; ≥880 parts → parse-OOM 500; B1 always 34 B | **branch-wide** (4/4). The OOM *threshold* is build-specific: 860 parts → 200 on .0/.10/.20 but 500 on .35 |
| **8.2** | 8.2.0, 8.2.15, 8.2.34 (+8.2.35 fixed) | all three: no consumable state; ≥880 → parse-OOM; B1 34 B | **branch-wide** (3/3) |
| **8.1** | 8.1.33 runtime, 8.1.0 source | A1 500, B1 34 B (no leak) | **source-equivalent**; comparison only, out of official CVE scope |
| **7.4** | 7.4.0, 7.4.33 | 109619 producer OOMs (500 ×3); consumer runs, touches session write, **no corruption/abort** | **branch-wide** (2/2): producer exists, UAF does not manifest |
| **7.2** | 7.2.0, 7.2.34 | producer **does not OOM** (200 ×3) | **branch-wide** (2/2): blocked at the producer |
| **7.0** | 7.0.33 runtime, 7.0.0 source | producer 200 ×3 | **branch-wide** by source + tip |
| **5.6** | 5.6.40 runtime, 5.6.0 source | producer 200 ×3 | **branch-wide** by source + tip |

### Source-equivalence axis (tested vs inferred)

`php_session_rfc1867_callback` — the function that implements the 109618/109619 producer/consumer — was extracted from each tag and hashed (`logs/source_functions.txt`, `func_hash.py`):

| Branch | Tags compared | Callback |
|---|---|---|
| 8.5 | 8.5.0, 8.5.5, 8.5.11 | **identical** `353b25177d` |
| 8.3 | 8.3.0, 8.3.10, 8.3.20, 8.3.35 | **identical** `4cd81b418a` |
| 8.2 | 8.2.0, 8.2.15, 8.2.34 | 8.2.0 = 8.2.15 (`cfac8d1a3b`), 8.2.34 differs (`4f665743cb`) — behaviour identical in all three |
| 8.1 | 8.1.0, 8.1.33 | **identical** `cfac8d1a3b` (same as 8.2.0/.15) |
| 7.4 | 7.4.0, 7.4.33 | **identical** `34e06406b8` |
| 7.2 | 7.2.0, 7.2.34 | **identical** `34e06406b8` |
| 7.0 | 7.0.0, 7.0.33 | **identical** (whole-file hash differs only outside this function) |
| 5.6 | 5.6.0, 5.6.40 | **identical** (same caveat) |

Other relevant deltas found: 8.5 `php_session_initialize` changes between 8.5.5 and 8.5.11 (`7a1a05c3e7` → `e476f4dceb`) **without changing the measured leak outcome**; 8.3 `php_session_reset_id` changes at 8.3.20; 8.2 `php_session_start` changes at 8.2.15. None of these changes moved a build across a classification boundary in the sample.

---

## 5. Tested vs inferred (explicit)

**Runtime-tested (measured, this run):** 8.5.0, 8.5.5, 8.5.11, 8.5.12, 8.3.0, 8.3.10, 8.3.20, 8.3.35, 8.3.36, 8.2.0, 8.2.15, 8.2.34, 8.2.35, 7.4.0, 7.4.33, 7.2.0, 7.2.34, 7.0.33, 5.6.40, 8.1.33, 8.4.26 (control).

**Inferred, not runtime-tested:**
1. **7.0.0 and 5.6.0** — the official images are Docker *schema 1* manifests, disabled by default in Docker 26 (`[DEPRECATION NOTICE] Docker Image Format v1 … support is disabled by default`); pulls of 7.0.0/7.0.1/5.6.0/5.6.1 all fail. Covered instead by: byte-identical `php_session_rfc1867_callback` at 7.0.0 vs 7.0.33 and 5.6.0 vs 5.6.40, plus the runtime tip rows. The producer's non-OOM behaviour is inferred to be branch-wide.
2. **8.1.0** — source-equivalent to 8.1.33 (identical callback, identical `php_session_initialize`/`flush`/`reset_id`; `php_session_start` does differ at .33 but is not the function implicated in the blocker); no runtime row.
3. **8.5 "leak is usable for the chain"** — the 819,208 B window and its dominant 2 MiB cluster are measured; the mapping to `S = main + 0xF8398` and any A2/B2 success are **not** tested here.
4. **8.3/8.2 END-phase negative** — "no consumable state" is measured via B1 (34 B). That an END-phase state could exist at an un-sampled id offset is not excluded (see §6).
5. **All patch builds not listed** — see §6.

**Deliberate non-claims:** no RCE on any build; no claim that 8.5.11/8.3.35/8.2.34 are exploitable; no claim about the 8.4.x line beyond the control row (prior workers own it).

---

## 6. Could expanding to every patch build change the result?

* **8.5 (0 → 11 sampled):** no. Three builds spread across the branch (early/mid/last) give an identical A1 shape and an identical B1 signature (819,208 B, 51/53 pointers on one base). The session callback is byte-identical across all three. Expanding to 8.5.1–8.5.10 is very unlikely to change the classification.
* **8.3 (0 → 35 sampled):** the *classification* (parse-OOM, no leak) held on 4/4, but the **OOM threshold is build-specific** — 860 parts gives 200 on 8.3.0/.10/.20 and 500 on 8.3.35. A build whose threshold happens to land in the END-phase window would change the row, and 4 samples cannot exclude that. Expansion would be the only way to settle it; the callback source is identical, so any such window would be a parser/allocator threshold effect, not a session-code difference.
* **8.2 (0 → 34 sampled):** same reasoning as 8.3; 3/3 identical outcome, threshold moves between .15 and .34.
* **8.1:** source-identical within the branch; a runtime sweep would add little because the branch is out of official CVE scope and no RCE is claimed.
* **7.4 / 7.2:** 2/2 identical within each branch, sources identical; expanding would not change the classification.
* **7.0 / 5.6:** tip-tested + source-identical to the untested .0 builds; expanding to the .0 images is not possible on this Docker (schema 1).

**Bottom line:** for 8.5 the earlier blocker is **build-artifact, not branch-wide** (in fact not present at all in the sample). For 8.3 and 8.2 the blocker is **branch-wide in outcome but threshold-sensitive across builds**; for 7.4/7.2/7.0/5.6 it is **branch-wide** (producer absent below 7.4, no corruption at 7.4).

---

## 7. Images (exact digests) and artifacts

| Build | RepoDigest |
|---|---|
| 8.5.0 | `php@sha256:1d825469e3c69b10baf6a8a63b1e766b81c6edb44a01f91509fc148bfd0e5f3e` |
| 8.5.5 | `php@sha256:e55e196fca35436fd26ba36e6fd2f2d9846142d0561dc35f74c7d25db1d54318` |
| 8.5.11 | `php@sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b` |
| 8.5.12 | `php@sha256:5fec3fb1f0322c20a01c8af35a09a96f3a83aa369650b0fed161e91cb84056ed` |
| 8.3.0 | `php@sha256:14acfecd6a6e414677bf8330ded6696a23b5b064e78fbbe7709098815ba46c51` |
| 8.3.10 | `php@sha256:bec863a30ab37f03d5ef0b238a1cfbdac2f695a809bd0db485f4a59f699adeda` |
| 8.3.20 | `php@sha256:44e44b615af547ad25ff3ca5e36c6c8e4644cb6db3da2720e064cf89bd231661` |
| 8.3.35 | `php@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` |
| 8.3.36 | `php@sha256:756c2884677bedea30afaa95811b42cd3ff251203291c5820c1ad209e86c9fb4` |
| 8.2.0 | `php@sha256:739420c858b1f447490c55971416298699678203353ba13e47e4e57b8318c94f` |
| 8.2.15 | `php@sha256:f2b47cc5bdae7fbd710565cedf66a9c41f30e6880d2a4c7e2720aed05ea27294` |
| 8.2.34 | `php@sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` |
| 8.2.35 | `php@sha256:fa8966fbaaa06981e549e7a33eb8a68f4cf677d6a82e1d6350adc5d85fe8f740` |
| 7.4.0 | `php@sha256:686af696a87d3836c694380588368ff4e7ad3e30f1faef387c545890b340edee` |
| 7.4.33 | `php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d` |
| 7.2.0 | `php@sha256:91ae1deefbbc178a2a017b0249934b98fa1f3772991b9fe91721a0bf254a3126` |
| 7.2.34 | `php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8` |
| 7.0.33 | `php@sha256:1d34b2e491a02ba7a8d26478132015e197a5ffea37f0a93b42621d11cfe042cc` |
| 5.6.40 | `php@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d` |
| 8.1.33 | `php@sha256:1ab8fdfd44a083969ceb493d8a837324b4caf0dc8f7d8feef74b7014678e4036` |
| 8.4.26 (control) | `php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |

Artifacts under the run dir: `out/<build>/result.json` (per-test status, limits, PHP version, container state, crash markers), `out/<build>/*.resp` (225 raw responses), `logs/` (run logs, `source_functions.txt`, `bodies.sha256`), `bodies/` (all request bodies + hashes), `src/` (fetched `session.c`/`rfc1867.c` per tag), `harness.py`, `func_hash.py`.

Verification performed on this report: every digest in §7 was re-checked by script against `out/*/result.json`; the §3 prior-body claims were checked by hashing and byte-comparing `modphp_109619_20261023T010232Z/work/{a1_8511_t12,b1_8511_t}.bin`; the §4 function hashes come from `logs/source_functions.txt`, regenerated by `func_hash.py` from the fetched tag sources.

Bodies: `a1_84.bin 8e8fc166…`, `a1_85.bin ba775359…`, `b1_84.bin 74672d06…` (33,128,677 B), `b1_85.bin de996029…` (33,399,541 B), `a1_p820/880/920/1000/1060.bin`.

---

## 8. Limitations

1. **No RCE stage for the requested branches.** A2/B2 was not run for 8.0–8.3 or 8.5 (no seedable leak); the 8.5 "leak reached" rows are leak-stage only. The only full-chain runs are the 8.4.26 positive control in §9.2 (excluded from the requested matrix).
2. **No gdb state probe.** END-phase vs parse-OOM is inferred from the operational signal (A1 response shape + B1 consumption), not from `PS(send_cookie)`/`PS(id)` in the worker. The 8.4.26 reference row validates the operational signal (211 B / no cookie / 819,208 B leak).
3. **8.3/8.2 id geometry was not re-calibrated.** A "no leak" row could in principle be a geometry miss rather than absent state. The sweep (5 parts values, restart before each) bounds this, but does not eliminate it.
4. **Image/INI deltas:** 7.2.0's image ships no `php.ini-production`, so a 12-line production-equivalent INI was mounted (disclosed; `display_errors=''` verified). The 8.4.26 control is single-worker.
5. **7.0.0 / 5.6.0** runtime images are unavailable (schema 1); those rows are source-inferred.
6. The run used loopback-only containers; no shared service was restarted; no container of another worker was touched.

---

## 9. Full-chain extension (CVE-2026-109619) — per-version matrix

**Added 2026-10-23 UTC.** This section supersedes §8 limitation 1 and replaces the page-0x137 classification with a full-chunk probe for the builds re-tested here. Environment unchanged: stock `php:<ver>-apache` (mod_php, prefork, 5 children), each image's own `php.ini-production` (`memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`, `max_execution_time=30`, `display_errors=Off`, `output_buffering=4096`, `max_input_vars=1000`, ASLR on). Loopback only; no shared service restarted; no other worker's container touched; no push/commit.

### 9.1 Method (new tooling and why the earlier classifier changed)

1. **Offsets per build, never reused.** `docker run --rm … readelf -sW /usr/lib/apache2/modules/libphp.so` for 18 builds gives `zif_system` and `zval_ptr_dtor` (§9.5, raw: `offs/symbols.txt`). 8.4.24 / 8.4.26 match the prior receipts (`0x464530/0x65d1e0`, `0x465370/0x65eb60`), which validates the extraction.
2. **Chain driver.** `modphp_109619_20261023T010232Z/scripts/chain_conc.py` (imports the 9bie repo's `cheap_oom_a`, `fake_ref_b`, `mk_ht`): A1 (END cleanup OOM) → B1 (forged `PS(id)` leak) → A2 → B2 (`zif_system`).
3. **Tagged sparse B1 — a page/offset-independent END-state detector.** 16 × 2 MB multipart fields (511 pages each); each value contains a valid fake `zend_string` header at *every* page boundary and every `0x100` offset, with the 8-byte tag encoding `(<offset index>, <page low byte>)`. If the A1 left a dangling `PS(id)` anywhere `0x100`-aligned in a reused 2 MB chunk, one of five concurrent B1 requests leaks 819,208 B and the cookie head reports the exact address (e.g. `/037BBBB` = `0x137000`, `/3FDBBBB` = `0x1FD300`). If no state exists, all five return a normal-size cookie. This removes the page guess that §1 used.
4. **Exact-address leak:** once the address is known, a `T:<offset>` body (value stops 8 bytes after the forged header) produced a pointer-rich window on 8.4.26 (**11,944** pointers) and is the leak-quality primitive used here. The multi-header universal bodies (headers at every page/offset) leak the correct length but returned **0** pointers on 8.4.26, so they are used strictly as state detectors. (The validated single-forge 8.4 body `b1_8426` is `G:`-shaped and does produce pointers; the difference is the multi-header geometry, not `G` vs `T` alone.)
5. **Calibration on 8.4.26:** tagged probe head `/037BBBB` → `0x137000`; `T:0x137000` ×16 + X:900 → 11,944 pointers, `zval_ptr_dtor` = `0x7f1c4f73bb60` → `lib = 0x7f1c4f0dd000` (page-aligned). Evidence `out/probe8426/`, `out/tag8426/`, `out/t8426/`.
6. **Calibration on 8.5.0:** `/3FDBBBB` → `0x1FD300`, reproducing the prior lane exactly. **16 big fields is the minimum** that reliably reuses the dangling id's 2 MB chunk: 1 / 2 / 4 / 8 fields abort with `zend_mm_heap corrupted` and no cookie, 16 fields leak.

### 9.2 Positive control — 8.4.26 (excluded from the requested matrix)

| Run | Marker | A1 | B1 | A2 | B2 | Proof |
|---|---|---|---|---|---|---|
| 1 | `V8426` | 500 / 211 B (no cookie) | 1,696,120 B raw → 819,208 B | run | `RESULT True uid=33(www-data)` | `out/V8426_ctl/` |
| 2 | `V8426b` | 500 / 211 B | 1,660,696 B raw → 819,208 B | run | `RESULT True uid=33(www-data)` | `out/V8426b/` |
| 3 | `V8426c` | 500 / 211 B | 1,666,592 B raw → 819,208 B | run | `RESULT True uid=33(www-data)` | `out/V8426c/` |

Distinct markers, distinct runs, restarted container before each; proof files inside `bcov2-8426`: `/out/p1_conc_V8426`, `/out/p1_conc_V8426b`, `/out/p1_conc_V8426c`, each containing `uid=33(www-data) …` plus the marker. `--zif-off 0x465370 --zdtor-off 0x65EB60 --s-off 0xF8398` (the only anchor derived in this work). 8.4 is out of the requested matrix.

### 9.3 Requested-version matrix

| Build | `zif_system` | `zval_ptr_dtor` | A1 result | B1 / leak | Chain stage | RCE / blocker | Reliability | Evidence |
|---|---|---|---|---|---|---|---|---|
| **8.0.30** | `0x3495d0` | `0x4319a0` | 860 parts: **200** (no OOM); 1200/1600/2000/2400 parts: 200, **no Set-Cookie** (`max_input_vars=1000` truncation) | none | **0 — no A1** | no END-phase producer: the 8.4 geometry does not OOM at all; part scaling is truncated before the parser, so it cannot reach the limit | 1 default + 4 part counts, all negative | `out/probe8.0.30/` (`a1.resp` 268 B, `parts1200.resp` 210 B) |
| **8.1.33** | `0x36f300` | `0x456fd0` | 500 / 211 B (no cookie) | full-chunk tagged probe: normal cookies only | **0 — no A1** | parse-OOM; no dangling id at any `0x100`-aligned page/offset in a 2 MB chunk; prior gdb `status=1` | 5 concurrent B1 per probe | `out/probe8.1.33/` |
| **8.2.34** | `0x39b8a0` | `0x487650` | 500 / 211 B | full-chunk tagged probe: normal cookies only | **0 — no A1** | parse-OOM; same negative | 5 concurrent B1 per probe | `out/probe8234/` |
| **8.3.35** | `0x3ac080` | `0x49ec50` | 500 / 211 B; progress-len 4000–196512 (48 points) all 500 | full-chunk tagged probe: normal cookies only (also at the no-cookie boundary V=16288) | **0 — no A1** | parse-OOM; cookie flips at V=16288 but no state; prior gdb `status=1` | 2 probes (default + V=16288) + 48-point scan | `out/tag8335/`, `out/probe8335v/`, `out/tune8335/` |
| **8.5.0** | `0x56a420` | `0x781fe0` | 500 / 210 B (no cookie) | 819,208 B at `0x1FD300`; tagged run: **3 pointers**, no lib candidate | **B1 — leak** | B1 leak-quality: window is chunk-end free list, no `libphp` code pointer → `lib` unknown; no main bucket → `S` unknown | reproduced with tuned A1; prior run `leak_0.bin` 819,208 B | `out/t850ctl/` (`b1_4.resp` 986,830 B); prior `modphp_109619…/out/pin8500_G2/` |
| **8.5.5** | `0x570de0` | `0x789ae0` | 500 / 210 B (prior lane; not re-run this session) | 819,208 B at `0x1FD300` | **B1 — leak** | same as 8.5.0 | prior lane, same body/digest | prior `modphp_109619…/out/pin855_G2/` (`leak_0.bin` 819,208 B) |
| **8.5.11** | `0x5996e0` | `0x7b47a0` | 500 / 211 B | 819,208 B; **53 pointers, all distinct, stride 0x40, 0 lib candidates** | **B1 — leak** | same blocker; `lib`/`zif_system` runtime base unrecoverable; A2/B2 impossible blind | 2 independent runs (prior + this session) | `out/leak8511/` (`b1_0.resp` 829,526 B); prior `…/out/pin8511_G2/` |
| **8.5.12** | `0x59fae0` | `0x7c11a0` | **200 OK**, normal cookie | — | **control** | **fixed** | 1 run | `out/ctl8512/a1.resp` (274 B) |
| 8.4.26 (control, excluded) | `0x465370` | `0x65eb60` | 500 / 211 B | 819,208 B, `lib` recovered | **RCE** | **3/3** | `out/V8426*` |

No new-branch RCE was achieved, so the ≥3-reproduction rule is not triggered for a new claim; every row above is a measured blocker, not a success.

### 9.4 Exact blockers

1. **8.0.30 — no A1 producer.** The 8.4 END-OOM body returns **200** (no OOM) at 860 parts. Enlarging to 1200/1600/2000/2400 parts does **not** OOM either: the response is 200 with **no** `Set-Cookie`, i.e. `max_input_vars=1000` truncation stops the upload-progress parser before the session path. No OOM means no END cleanup failure and therefore no dangling `PS(id)`. Part scaling is blocked at `max_input_vars=1000`; larger-value fillers (instead of more parts) are the remaining option and were not exhausted — with the tested shapes the full-chunk probe is negative.
2. **8.1.33 / 8.2.34 / 8.3.35 — the OOM is parse-phase.** A1 returns 500 / 211 B with a 4096-byte failing allocation (parser page), and a following full-chunk tagged B1 produces only normal cookies. 8.3.35 additionally: 48 progress-length points (4000–196512, step 4096) all 500; `Set-Cookie` present ≤12192 and absent ≥16288; the tagged probe at V=16288 is negative. Prior gdb measured `status=1` (no active session). This is a producer blocker, not a page miss. *(8.2.0/.15 and 8.3.0/.10/.20 were not re-probed this session; their §1 rows still rest on the page-0x137 miss plus the parts sweep.)*
3. **8.5.0 / .5 / .11 — B1 leak quality.** END state is real (500 / 210–211 B, no cookie; 8.5.12 fixed control 200). The leak is exactly 819,208 B at `0x1FD300`, but the window is the chunk-end free list: 3 pointers (8.5.0 tagged) and 53 pointers all distinct at stride 0x40 (8.5.11), with **zero** qwords where `q - zval_ptr_dtor` is page-aligned. Consequently: no `lib` base → `zif_system` runtime address unknown; no main-chunk bucket → no `S` anchor. A2/B2 cannot be built. Moving the id page is not a body-shape knob: the id is allocated at session init (before the body is parsed); `--tail 24` changed the response to a shutdown OOM but produced no leak at any page.
4. **Fixed/last-build controls:** 8.5.12 → 200 OK, normal cookie (this session); 8.3.36 and 8.2.35 → 200 (prior coverage).

### 9.5 Offsets (readelf, per build — not reused)

| Build | `zif_system` | `zval_ptr_dtor` |
|---|---|---|
| 8.0.30 | `0x3495d0` | `0x4319a0` |
| 8.1.33 | `0x36f300` | `0x456fd0` |
| 8.1.34 | `0x36f470` | `0x457150` |
| 8.2.0 | `0x393ce0` | `0x47b730` |
| 8.2.15 | `0x391310` | `0x478c90` |
| 8.2.34 | `0x39b8a0` | `0x487650` |
| 8.2.35 | `0x3a1da0` | `0x491910` |
| 8.3.0 | `0x3a78a0` | `0x495570` |
| 8.3.10 | `0x3a04e0` | `0x48e1b0` |
| 8.3.20 | `0x3a21d0` | `0x491bd0` |
| 8.3.35 | `0x3ac080` | `0x49ec50` |
| 8.3.36 | `0x3b2a00` | `0x4a9510` |
| 8.4.24 | `0x464530` | `0x65d1e0` |
| 8.4.26 | `0x465370` | `0x65eb60` |
| 8.5.0 | `0x56a420` | `0x781fe0` |
| 8.5.5 | `0x570de0` | `0x789ae0` |
| 8.5.11 | `0x5996e0` | `0x7b47a0` |
| 8.5.12 | `0x59fae0` | `0x7c11a0` |

Bucket/anchor: only the 8.4-family `S = main + 0xF8398` was derived (prior lane, reused for the three 8.4.26 control runs). For 8.0–8.3 and 8.5 no anchor can be derived because no leak with a main-chunk bucket was obtained.

### 9.6 Reliability and compliance

- The only full-chain RCE in this session is the 8.4.26 positive control: **3/3** independent runs (`V8426`, `V8426b`, `V8426c`), each `RESULT True` with `uid=33(www-data)` and a distinct marker.
- No RCE is claimed for 8.0 / 8.1 / 8.2 / 8.3 / 8.5. Instead each blocker is recorded with its raw response files; the 8.5.11 leak was reproduced twice independently with the same 819,208 B / 53-pointer / no-code-pointer signature.
- No shared service was restarted; only my `bcov2-*` containers were created/restarted. Other workers' `m109-*` containers were not touched. No push, commit, PR, or advisory; all evidence is local.

### 9.7 Evidence index (this session)

| Path | Content |
|---|---|
| `offs/symbols.txt` | readelf-derived offsets, 18 builds |
| `out/V8426_ctl/`, `out/V8426b/`, `out/V8426c/` | 8.4.26 control: A1 211 B, A2 211 B, B1 1.66–1.70 MB raw; B2 proof |
| `bcov2-8426:/out/p1_conc_V8426{,b,c}` | `uid=33(www-data)` + marker proof files |
| `out/probe8426/`, `out/probe8426b/`, `out/pf2/`, `out/pf4/`, `out/pf8/`, `out/pf16/` | 8.4.26 probe calibration: 1/2/4/8 fields abort, 16 fields leak |
| `out/tag8426/`, `out/t8426/` | tagged address (`/037BBBB`) and `T:` pointer-rich leak (11,944 pointers) |
| `out/t850ctl/` | 8.5.0 state + leak at `0x1FD300` (`/3FDBBBB`), a1 210 B |
| `out/leak8511/` | 8.5.11 `T:` leak, 819,208 B, 53 pointers, no lib candidate |
| `out/ctl8512/` | 8.5.12 fixed control, 200 OK + cookie |
| `out/tag8335/`, `out/probe8335v/`, `out/tune8335/` | 8.3.35 full-chunk probes, V=16288 probe, progress-len boundary |
| `out/probe8234/`, `out/probe8.1.33/`, `out/probe8.0.30/` | 8.2.34, 8.1.33, 8.0.30 full-chunk probes; `parts1200.resp` (200, no cookie) |
| `modphp_109619…/out/pin8500_G2/`, `pin855_G2/`, `pin8511_G2/` | prior-lane 8.5.0/.5/.11 leaks (`leak_0.bin` 819,208 B) |
| `modphp_109619…/out/{8234_default,8335_default,8512_ctrl}/` | prior-lane coverage responses reused above |
