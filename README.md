# php2slop

**Status: WIP.** Research exploit for the PHP `session.upload_progress` UAF
(CVE-2026-109618/109619). No stock-default RCE chain was demonstrated by the
project's own 109618/109619 work in the original write-up. Results are split by
whether they satisfy the chain validity rules below.

**2026-10-22 reconciliation (appended).** A stock-default chain is now measured
conditionally for one target: the external 9bie two-CVE chain on fresh PHP
8.4.26 + Apache prefork 5/150 + stock `php.ini-production` + WordPress 7.1.3,
with B1 on the stock core `/wp-content/index.php` and A2/B2 on `/` or
`/index.php`. It is the old, patched CVE-2026-109618 + CVE-2026-109619 pair, not
a new vulnerability. It fails on warm state, MediaWiki, and 8.5.11 with the
stock A1; 8.4.27/8.5.12 are fixed. See "2026-10-22 full-chain reconciliation"
below.

## All PHP versions — current status (2026-10-23)

Status legend: ✅ full-chain RCE proven · ⚠️ leak/primitive only · ❌ blocked/negative · 🧪 active · 🛠 config-induced, not stock · — not tested.

This table is a measured status snapshot, not a claim that every version is solved. Reports are linked inline and are included in this tree.

### mod_php

| Version | Status | Evidence / caveat |
|---|---|---|
| 5.6 / 7.0 / 7.1 / 7.2 / 7.3 / 7.4 | 🧪 active | Full-chain matrix active; prior 109619 probes negative/no heap corruption; no RCE yet. [modphp_109619](modphp_109619_20261023T010232Z/report.md), [php75_exploit](php75_exploit_20261023T022509Z/report.md) |
| 8.0.30 | ❌ | 109619 no A1 producer; 109618 active. [report](modphp_109619_20261023T010232Z/report.md) |
| 8.1.33 / 8.2.34 / 8.3.35 | ❌ | 109619 parse-OOM; 109618 active; 8.3.36 fixed control. [report](modphp_109619_20261023T010232Z/report.md) |
| 8.4.0–8.4.9 | 🧪 active | Early-8.4 gap; 8.4.1–8.4.8 blocked (early cleanup/no stale `PS(id)`); 8.4.0/8.4.9 under test. [report](modphp_84_matrix_20261023T074116Z/report.md) |
| 8.4.10–8.4.26 (upstream) | ✅ | 17/17 full-chain RCE; per-build offsets; generic session endpoint. **Endpoint prerequisite:** the target must expose/accept the generic session endpoint used by the upload-progress request; the WordPress 7.1.3 proof exists, but the stock-WordPress/no-cheat audit is pending, so this is not yet a stock-WordPress-only claim. [report](modphp_84_matrix_20261023T074116Z/report.md) |
| 8.4.24 Debian 13 package (`8.4.24-1~deb13u1`, mod_php) | ✅ full blind RCE (4/4) | Distro build, not FPM. `S = main + 0xF7398`, `fillers=116`, `zif_system=lib+0x24cdd0`; 4/4 blind successes with `uid=33(www-data)` + `DEB116R1..R4`, B2 hit at attempt 4. Controls fail: `fillers=115` + same `S` → all B2 200, no proof; wrong anchor `S=main+0xF8398` → no proof. `SHA256SUMS` 73/73; report hash `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`. [report](modphp_84_matrix_20261023T074116Z/report.md), [proofs](modphp_84_matrix_20261023T074116Z/out/proofs/) |
| 8.4.27 | ❌ | Fixed control. [report](modphp_84_matrix_20261023T074116Z/report.md) |
| 8.5.0 / 8.5.5 / 8.5.11 | ⚠️ | 109619 leak-only (819,208 B, sparse, no libphp code pointers); 109618 active. [report](build_coverage_20261023T074532Z/report.md) |
| 8.5.12 | ❌ | Fixed control. [report](build_coverage_20261023T074532Z/report.md) |

### FPM

| Version | Status | Evidence / caveat |
|---|---|---|
| 5.6 / 7.0 / 7.1 / 7.2 / 7.3 / 7.4 | 🧪 active | Pre-8 full-chain matrix active. CVE-2019-11043 is config-induced only on 7.1.32/7.2.23/7.3.10; fixed 7.2.24/7.3.11; stock nginx/Debian `fastcgi-php.conf` fails; 7.4 unaffected. [report](fpm_80x_chain_20261023T085337Z/report.md), [11043 report](fpm_11043_targets_20261023T085412Z/report.md) |
| 7.3.9-1~deb10u1 (Debian 10) / CVE-2019-11043 | 🛠 config-induced only | Package is vulnerable: canonical **non-stock** nginx PHP-FPM pattern gives unauthenticated RCE as `uid=33(www-data)`, verified with WordPress 5.3.2, MediaWiki 1.33.1 and a plain probe. **Blocked:** stock Debian nginx `snippets/fastcgi-php.conf` (`try_files $fastcgi_script_name =404;` → 404 before FPM); WordPress recommended config (no empty `PATH_INFO`; 301); MediaWiki recommended config (end-anchored PHP location never matches; 404). Fixed controls clean: Debian 7.3.11, upstream 7.2.24, 8.4.26. [report](fpm_11043_targets_20261023T085412Z/report.md) |
| 8.0.30 / 8.1.34 / 8.2.34 / 8.3.35 | ❌ / ⚠️ | 109619 negative (A2 OOM/exit 70; 8.0 size-threshold; B1 413; no state inheritance); 109618 same-worker primitive, no RCE; fixed 8.2.35/8.3.36. [report](fpm_109619_20261023T010421Z/report.md) |
| 8.4.26 | ❌ / ⚠️ | 109619 stock negative; 109618 source-positive, same-worker primitive, no RCE; BG/T1 strictly per-worker, zero cross-worker; ASLR/no known target. [report](fpm_saturation_20261023T081008Z/report.md), [BG report](fpm_bg_20261023T021053Z/report.md) |
| 8.5.11 | ⚠️ | 109619 leak-only; 109618 source-positive; controlled reclaim/PIE leak 6/6 in static-1 lab, no RCE; static-1 is diagnostic, not a stock pool. [report](fpm_aslr_20261023T073345Z/report.md), [alt RCE report](fpm_alt_rce_20261023T084957Z/report.md) |
| 8.4.27 / 8.5.12 | ❌ | Fixed controls. [report](fpm_109619_20261023T010421Z/report.md) |
| FPM overall | ❌ | No qualifying stock RCE yet. Public survey found no alternative FPM RCE on supported 8.2–8.5; CVE-2019-11043 is EOL/config-gated; CVE-2024-4577 is Windows CGI. [survey](fpm_alt_cves_20261023T084756Z/report.md) |

### Bottom line

- Only reliable full-chain family: **mod_php 8.4.10–8.4.26** (upstream), plus the calibrated **Debian 13 mod_php 8.4.24** package at 4/4 blind.
- No stock FPM RCE; 109618 remains a same-worker primitive, and 11043 is config-induced/EOL only.
- “All versions” is not achieved; the active matrices are 5.6–7.4 mod_php/FPM and the early-8.4 gap.
- Last updated 2026-10-23.

## Chain validity rules

- **Allowed:** a file written by the exploit chain itself (e.g. the session
  file PHP creates from `session.upload_progress`).
- **Not allowed / cheating:** pre-staged PHP files, `.user.ini`, custom
  `php.ini`, nginx/FPM config deltas, synthetic sessions, pre-staged `.phar`,
  admin/post-auth, app-specific vulnerabilities, LFI, gdb/operator addresses,
  single-worker/sticky routing.
- The target app must be stock. If it must already call `session_start()` or
  contain a custom `unser.php`/`index.php`, it is a pre-staged app and not a
  stock chain.

## Works (DoS / availability only)

- 128M header flood on stock official images (no `php.ini`, one prefork
  worker, `display_errors=On`, fresh state): 500,000 `X: v` headers /
  3,072,588 B OOMs PHP 8.3.35/8.4.26/8.5.11; 425,000 does not, so the
  threshold is between 425k and 430k. Availability only, not RCE; it needs
  `display_errors=On`, a single worker and fresh state. Dirty 8.3.35: 0/3,
  against 2/2 on fresh containers.
- CVE-2026-109618 on FPM: pre-RINIT OOM makes the child exit 70 with a 502;
  the parser OOM is contained. Availability only: no PHP-origin bytes and no
  code execution.
- No RCE chain satisfied the validity rules in the project's own 109618/109619
  work at the time of writing. **Superseded 2026-10-22:** the external 9bie
  chain meets them conditionally on fresh PHP 8.4.26 WordPress (B1 must use the
  stock core endpoint; see the reconciliation section below).

## Does not work / blocked

- 9bie `display_errors=Off`: no remote leak. The `max_input_vars` warning
  must set `SG(headers_sent)=1`, otherwise `php_session_send_cookie()` clears
  `PS(send_cookie)`. Off stage 2/3 works only in the lab (see below).
- 9bie at 128M: 12 MB field does not OOM; 63 MB gets stage 1/2 2/2 but stage
  3 0/2 (uncalibrated geometry, not impossibility). No FPM evidence for that
  128M line (mod_php only), no PHP 7.x; PHP 8.2.34 is in range but the shipped
  offsets are 8.4.26-specific. *(2026-10-22: separate FPM work now exists —
  8.5.10 custom and 8.2.34 custom; see below.)*
- Stock PHP 8.0/7.2/7.3 negative; PHP 7.4 PIE blocked; PHP 5.x stock blocked.
- Stock Drupal/Joomla use database sessions, so there is no served session
  file.
- CVE-2026-109619: conditional and not stock-default; not claimed as a stock
  chain. *(Updated 2026-10-22: the mechanism is no longer "unverified" — it was
  demonstrated on 8.5.10 FPM only with a custom LFI/`php_binary`/host
  `/proc/<pid>/mem` harness (stock 5-worker pools 0/31), and on 8.2.34 only in a
  custom 8M single-worker lab (17/17). See the reconciliation section.)*

## Lab-only / pre-staged (not chains)

- **8.4.26 FPM (`fpm8426`):** the remote leak and
  `echo finalproof>/tmp/fpm8426_pwn` are real given the pre-staged
  `fpm8426_pre.php`, `fpm8426_state_b.php`, `.user.ini`, custom `php.ini` and
  nginx buffers. The exploit does not plant them; 5-worker end-to-end is
  unproven. *(2026-10-22: the 8.5.10 stock control is 0/17 dynamic and 0/14
  static; see the reconciliation section.)*
- **FPM synthetic-session lane:** synthetic session, `php_binary`, `/sessions`
  path and non-PIE binary; no stock target.
- **Karasawa phar:** 14/15 RCE on PHP 8.5.4 with `display_errors=Off`, but the
  `.phar` is pre-staged and its stub calls `Phar::webPhar()`; there is no
  remote planting.
- **9bie / Datadog mod_php:** custom `unser.php`/`index.php` and/or
  gdb-oracle addresses. Off: stages 2/3 work but there is no remote leak. On:
  the leak works only with `display_errors=On`.
- **mod_php two-stage `Set-Cookie` leak → `zif_system`:** one-shot on
  8.3.35/8.4.26/8.5.11 with `display_errors=On` and a single prefork worker;
  not valid under the rules.
- **Real-app WordPress/Drupal/Joomla:** rely on an mu-plugin, a files-handler,
  a 2M `memory_limit` and/or a served session directory. App/config specific,
  not a stock chain. *(Historical: this describes the earlier mu-plugin route.
  The 2026-10-22 9bie chain uses stock core `/wp-content/index.php` with no
  mu-plugin and no `php_value`; see the reconciliation section. Drupal/Joomla
  remain app/config specific.)*
- **OpenMage 20.10.0:** PIE POP with a second `php_serialize` writer plus a
  slow-upload race; lab-only. The stock 20.17.0 test is pending.

## Pending

- 9bie session OOM: 16 KB OOB cookie for a heap pointer (mod_php PHP 8.4/8.5);
  no pointer yet.
- Stock OpenMage 20.17.0 chain test.
- ~~CVE-2026-109618 source primitive.~~ **Resolved 2026-10-22:** the primitive
  is a blind 32-bit decrement at an attacker-supplied address; mod_php
  `5/5` SIGSEGV, FPM `3/3` exit 70. It is a DoS, not RCE
  (`/tmp/opencode/research/oom109618_source_20261022T132455Z/report.md`).
- PHP 8.5.12 ASAN fuzzer campaign is **still running**; the result is
  **pending** and must not be cited until the campaign is complete.
- A portable 8.5.11 A1 groom that ends with `send_cookie=1` (stock A1 does not;
  49-page B1 sweep found no leak).

## Requirements

- python3 ≥ 3.10, stdlib only; a target you own supplied by the operator (`--target wiki|wp|modphp` → 127.0.0.1, or a URL); `gdb`/`nm`/`readelf` optional for new builds.

## Build and usage

No build step; run in place with `./tool/php2shell.py` or `python3 -m tool`.

```sh
./tool/php2shell.py --target wiki --step recon
# --unser-url is a pre-staged lab endpoint, not a valid stock chain
./tool/php2shell.py --target modphp --step chain \
  --unser-url http://127.0.0.1:8080/unser.php --arm-url http://127.0.0.1:8080/
./tool/php2shell.py --target modphp --step producer --producer unser \
  --unser-url http://127.0.0.1:8080/unser.php --memory-limit 2M
```

`recon`, `producer` and `chain` send to the operator-supplied target; `chain`
is the public end-to-end path. Output: `files/io/<target>-<step>-<timestamp>/`.
Internal calibration stages (`write_stage`, `leak`) are documented in `USAGE.md`.

## Scope and license

Authorized testing on operator-owned targets only. AGPL-3.0; see `LICENSE`; details in `USAGE.md` and `docs/`.

## 2026-10-22 full-chain reconciliation

Dated append. It does not rewrite the sections above; it records what changed
after the morning status text was written. Receipts are under
`/tmp/opencode/research/`; the two primary ones are
`9bie_fullchain_multiw_20261022T130520Z/report.md` and
`9bie_addendum_20261022T160000Z/addendum.md`.

### Two-CVE identity: old and patched, not new

| role in the chain | CVE | GHSA | mechanism |
|---|---|---|---|
| A1/A2 producer | CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | OOM corruption: the OOM path uses `longjmp()` and leaves request-owned memory invalid |
| B1/B2 consumer | CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | stale session globals are read before the next request's normal initialization |

Both are fixed by commit `506e87fa7dcdd306975e5b8f8265ee03527aacbf` ("Avoid
state corruption via bailout") and released in PHP 8.2.35, 8.3.36, 8.4.27 and
8.5.12. PHP 8.4.26 and 8.5.11 are affected. The chunked body, heap groom and
fake `zif_system`/`zval_ptr_dtor` engineering are new work; the underlying
defects are not. **No new CVE/0-day claim is supported.**

### Full chain on stock WordPress 7.1.3

Target: `php:8.4.26-apache` (mod_php, Apache 2.4.69), stock prefork 5/150, stock
`php.ini-production` (`128M`/`8M`), WordPress 7.1.3 with no active plugins. The
only target-side changes are a per-child-PID access-log format and a stock core
endpoint; no `php_value`, no single worker, no LFI, no host calibration.

- **Fresh WordPress: 3/3** in the controlled addendum series (6/6 including the
  earlier fresh variants 900/901/903 and 930–932). Base report: 5/5 broadcast
  plus 4/4 single-A2 on fresh 5-worker targets.
- **Path dependency:** B1 must run on the stock core silence file
  `/wp-content/index.php`; A2/B2 then work on `/` or `/index.php`. B1 on the
  front controller `/index.php` is 0/1 and does not leak.
- **Geometry:** B1 hits the A1 child at request index 4; B2 hits the A2-poisoned
  child at index 4 or 5; every success SIGSEGVs exactly one child, which Apache
  respawns; post-health is `200 OK`.
- **Leak/proof:** 1.65–1.69 MB raw B1 response, 819,208 decoded bytes;
  `zdtor -> libphp`, `S = main + 0xF8398`; `uid=33(www-data)` proof in
  `/tmp/p1_a903` and an HTTP callback to `p2s-cb:19090`. No `/out` mount.
- **Warm, no restart: 0/4.** Attempt 940's 1.69 MB B1 was an
  `implausible_delta` false positive (wrong `lib-main` delta), not a leak.
- **Single-worker no-retry control: 5/6.** A single worker is a diagnostic, not
  a prerequisite; per-child targeting is required.
- **MediaWiki 1.46.2: 0.** Front controller, `action=render` and
  `/opensearch_desc.php` all fail at B1.
- **PHP versions:** 8.4.26 works; 8.5.11 is advisory-affected but the stock
  8.4.26 A1 leaves `send_cookie=0`, a 49-page B1 sweep found no leak, and no
  portable chain is claimed; 8.4.27 and 8.5.12 return `200`/259 B with no OOM
  and no leak (fixed).

### Stock-bar matrix (9bie chain)

| criterion | verdict | evidence |
|---|---|---|
| unauthenticated | **PASS** | no credentials/cookies/login |
| no LFI | **PASS** | core multipart/session only; B1 on stock core file |
| no third-party write (same-chain allowed) | **PASS** | no plugin/theme/webroot write |
| stock defaults | **PASS (qualified)** | stock prefork 5/150 and `php.ini-production`; only vhost log format changed |
| ASLR on | **PASS** | distinct lib/main bases per fresh attempt; leak-derived `S`/`zif` |
| no single/sticky worker | **PASS (qualified)** | five workers; B1 i=4 rotation; per-child targeting required |
| all requested PHP versions | **FAIL** | 8.4.26 works; 8.5.11 not reproducible; 8.4.27/8.5.12 fixed |
| WordPress real app | **PASS (qualified)** | B1 on `/wp-content/index.php`, A2/B2 on `/` or `/index.php` |
| MediaWiki real app | **FAIL** | no leak at the tested endpoints |
| new vulnerability | **FAIL** | both CVEs known and patched |
| warm/no-restart | **FAIL (0/4)** | fresh restart required for this build |

### FPM 8.5.10 stock bar (CVE-2026-109619)

The demonstrated 8.5.10 FPM chain is **lab-only** under the stated bar: custom
LFI, `session.serialize_handler=php_binary`, custom upload-progress/size
settings, host `/proc/<pid>/mem` calibration for `X/P/B0`, and a single or
pinned worker. The requested stock control:

| stock pool | result | routing |
|---|---|---|
| dynamic 5 (`pm.max_children=5`, `start_servers=2`) | **0/17** | set/plant on pid 7, trigger on pid 8 |
| static 5 (`pm=static`, 5 workers) | **0/14** | set/plant/trigger on three different workers |
| total | **0/31** | HTTP 200, no marker, `t2_len=131358`, failure at decode #1 (missing fake `P/B0`) |

The 0/31 signature matches the no-plant control, not the wrong-`X` 502. This is
a negative for this exact chain, not a disproof of the CVE. Receipt:
`remote_fpm_chain_20261022T095656Z/ADDENDUM_STOCK_BAR.md`.

Integrity note: the receipt's §11.3 claim was false when written. The old
pre-addendum manifest (333 entries, `33bdcdd5…`) is preserved as
`SHA256SUMS.pre_addendum`; the regenerated `SHA256SUMS` now covers 1,221
readable files including the addendum, `conf5/`, `stockbar/` and all `phase/`
files, and verifies 1,221/1,221. See §11.3a in that addendum.

### PHP 8.2.34: custom lab only

A 17/17 chain exists on `php:8.2.34-apache` only with `memory_limit=8M`,
`post_max_size=64M`, `session.save_path=/tmp/sess`, `use_strict_mode=0`,
`use_cookies=1`, files handler, a single prefork worker and
`MaxConnectionsPerChild 0`. Stock 8.2.34 (`128M`/`8M`, multi-worker) does not
reach the primitive. The shipped 8.4.26 offsets do not transfer.
Receipt: `php8234_20261022T082540Z/receipt/REPORT.md`.

### Negative results (all 2026-10-22)

- **109619 fix-bypass, 8.5.12:** no Lane A/B bypass. ASAN + Zend MM quarantine;
  84+84 producer/consumer pairs, 48+48 `request_parse_body()` OOM pairs, 24+20
  targeted pairs, 80-case session corpus; **0 ASAN**. Lab producer app and
  single static worker; 8.4.27 not built; extensions excluded.
- **ASAN HTTP fuzzing, 8.4.26:** **0 ASAN** reports; 76,974,471 in-process
  executions; 1,907,061 real FPM requests; 9 artifacts all triaged as
  non-findings. Gaps: mbstring/iconv, Apache, chunked, `filter_input`,
  `parse_str` wrapper.
- **8.5.12 source audit:** negative. GH-23334 DOM template UAF is not reached by
  stock WordPress 7.1.3 or MediaWiki 1.46.2.
- **8.5.12 ASAN fuzzer:** still running — **pending**, no result claimed.
- **109618 source:** blind 32-bit decrement DoS; mod_php 5/5 SIGSEGV, FPM 3/3
  exit 70; 8.1/7.4 source-susceptible, 5.6 not; not RCE.

### Still not claimed

No MediaWiki RCE, no warm/no-restart reliability, no 8.5.11 chain, no stock
multi-worker FPM chain, and no new vulnerability.
