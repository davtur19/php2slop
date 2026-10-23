# php2slop

Research exploit tooling for the PHP `session.upload_progress` use-after-free
(CVE-2026-109618 / CVE-2026-109619).

**Status: WIP research code.** This is not a universal or stock-default
exploit. Chains that were measured under lab conditions required specific
build offsets, pool shapes and, in some lanes, non-default configuration. Treat
every result as lab-conditioned until reproduced on your own target.

This repository contains only the exploitation tool, its per-build offset
profiles, and this documentation.

## Status: what works / what does not

Lab RCE: the per-build 8.4.10–8.4.26 mod_php chain, Debian 13 8.4.24,
Ubuntu 25.04 8.4.5-1ubuntu1.2, and the non-stock `cleanup=0`
CVE-2026-115560 gadget chain on 8.4.26/8.5.11. The 8.5.11 FPM result is
lab-only and conditional on the row's configuration. No stock/all-version
claim.

The newly added distro-package and real-app rows below are negative: no
full-chain RCE, OOB write, or proof; the vulnerable rows show crash/DoS, and
the 26.04 release B1 leak is heap-only with no `libphp`/`S` anchor. They do not
extend the lab RCE claims above.

Legend: ✅ RCE in that exact cell · ❌ tested negative in that exact cell ·
🚫 patched build (basis stated) · — no qualifying RCE / untested (coverage gaps only).

### mod_php

Stock `php:<v>-apache` images, `php.ini-production`, 22-byte endpoint, ASLR on,
exact per-build offsets.

| PHP build | Branch | Status | Result / qualifier |
|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | no RCE; last 5.6 |
| 7.0.33 | 7.0 | ❌ | no RCE; last 7.0 |
| 7.1.33 | 7.1 | ❌ | no RCE; last 7.1 |
| 7.2.0 | 7.2 | ❌ | no RCE; early 7.2 |
| 7.2.34 | 7.2 | ❌ | no RCE; last 7.2 |
| 7.3.33 | 7.3 | ❌ | no RCE; last 7.3 |
| 7.4.0 | 7.4 | ❌ | no RCE; early 7.4 |
| 7.4.33 | 7.4 | ❌ | no RCE; last 7.4 |
| 8.0.30 | 8.0 | ❌ | no RCE; last 8.0 |
| 8.1.33 | 8.1 | ❌ | no RCE; last tested 8.1 mod_php |
| 8.2.0 | 8.2 | ❌ | no RCE; early 8.2 |
| 8.2.15 | 8.2 | ❌ | no RCE; mid 8.2 |
| 8.2.34 | 8.2 | ❌ | no RCE; last vulnerable 8.2 |
| 8.2.35 | 8.2 | 🚫 | fixed control; runtime (A1 200, no OOM) |
| 8.3.0 | 8.3 | ❌ | no RCE; early 8.3 |
| 8.3.10 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.20 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.35 | 8.3 | ❌ | no RCE; last vulnerable 8.3 |
| 8.3.36 | 8.3 | 🚫 | fixed control; runtime (A1 200, no OOM) |
| 8.4.1–8.4.8 | 8.4 | ❌ | 0/8; no leak-capable A1 state |
| 8.4.10–8.4.26 | 8.4 | ✅ | per-build tested, not a single-build extrapolation; 17/17 RCE (engine-level lab chain); 5/5 representative re-validation (8.4.10, 8.4.15, 8.4.20, 8.4.24, 8.4.26) with distinct `uid=33(www-data)` proofs; exact offsets; handler-independent |
| 8.4.27 | 8.4 | 🚫 | fixed; runtime (A1 200, B1 no leak) |
| 8.5.0 | 8.5 | ❌ | leak only; no libphp code pointer |
| 8.5.5 | 8.5 | ❌ | leak only |
| 8.5.11 | 8.5 | ❌ | leak only; 53 pointers, 0 `zval_ptr_dtor`, no 87-bucket |
| 8.5.12 | 8.5 | 🚫 | fixed; runtime (A1 200, normal cookie) |

### FPM

Stock `php:<v>-fpm` images fronted by nginx; stock production INI,
`pm=dynamic`, `max_children=5`; stock 1 MiB nginx body cap unless noted.

| PHP build | Branch | Status | Result / qualifier | Basis |
|---|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | A2 OOM/SIGSEGV; no B1; no B2 | runtime |
| 7.0.33 | 7.0 | ❌ | B1 leak only | runtime |
| 7.1.33 | 7.1 | ❌ | B1 leak only | runtime |
| 7.2.34 | 7.2 | ❌ | B1 leak only | runtime |
| 7.3.33 | 7.3 | ❌ | B1 leak only | runtime |
| 7.4.33 | 7.4 | ❌ | B1 leak only | runtime |
| 8.0.30 | 8.0 | ❌ | A2 200 under 128M; A1 64M 200, no OOM | runtime |
| 8.1.34 | 8.1 | ❌ | A2 502/exit 70; no state carry-over | runtime |
| 8.2.34 | 8.2 | ❌ | A2 502/exit 70; no chain | runtime |
| 8.2.35 | 8.2 | 🚫 | fixed control; Debian package runtime (A1/A2 200, 0 exit-70) | runtime (distro) |
| 8.3.35 | 8.3 | ❌ | A2 502/exit 70 | runtime |
| 8.3.36 | 8.3 | 🚫 | fixed control; A2 200, `PEAK=46137344` | runtime |
| 8.4.26 | 8.4 | ❌ | 109618 primitive; no controlled destructor | runtime |
| 8.4.27 | 8.4 | 🚫 | upstream fix; FPM runtime control not run (G11) | upstream fix |
| 8.5.11 | 8.5 | ✅ | lab: plain full-extension build, `pm=static`, `max_children=1`, same-worker known target + trigger script; blind leak-derived `C`/`PIE`; fake dtor → `zif_system`; 3/3 | runtime |
| 8.5.11 | 8.5 | ❌ | stock `pm=dynamic` pool: leak only | runtime |
| 8.5.12 | 8.5 | 🚫 | fixed; plain full-extension build + stock nginx | runtime |

FPM `5.6.40` produced no B1 leak; the B1-only range is `7.0.33–7.4.33`.

### nginx + mod_php

nginx terminates HTTP and proxies to Apache prefork + mod_php.

| Build / package | Status | Conditions / result |
|---|---|---|
| 8.4.24 Debian 13 (`8.4.24-1~deb13u1`) | ✅ | non-stock: 64 MiB body, `post_max_size=64M`, 4 MiB buffers, keepalive; Debian offsets |
| 8.4.26 official | ❌ | stock nginx 1 MiB: A1 1,060,211 B / B1 33,128,677 B → 413 |
| 8.4.26 official | ✅ | non-stock: 64 MiB body + 4 MiB buffers + keepalive |
| 8.4.27 | 🚫 | fixed; A1/B1 6×200, 0 leak, 0 OOB (stock and non-stock) |

### nginx + FPM

Stock nginx front, stock FPM pool.

| PHP build | Status | Conditions / result |
|---|---|---|
| 8.0.30 | ❌ | A2 200; A1 64M 200, no OOM |
| 8.1.34 | ❌ | A2 502/exit 70; no state carry-over |
| 8.2.34 | ❌ | same 502/exit-70 shape |
| 8.2.35 | 🚫 | fixed control; 64M diag A1/A2 200, 0 exit-70 |
| 8.3.35 | ❌ | same 502/exit-70 shape |
| 8.3.36 | 🚫 | fixed; A2 200 |
| 8.4.26 | ❌ | stock 1m 413; 64M diag 502/OOM; no chain |
| 8.4.27 | 🚫 | upstream fix; runtime control missing (G11) |
| 8.5.11 | ❌ | B1 leak only under stock `pm=dynamic`; the single-worker 3/3 result is in the FPM table, not this pool |
| 8.5.12 | 🚫 | plain full-extension build + stock nginx; A1 200 |

### Distro packages

Tested rows only; exact package strings.

| Distro / release | Exact package | SAPI | Status | Result / qualifier |
|---|---|---|---|---|
| Debian 13 (trixie) | `8.4.24-1~deb13u1` | mod_php | ✅ | engine-level lab chain; 6/6 total (2/2 fresh + prior 4/4); package-specific constants; package default; warm 25/25 |
| Debian 13 (trixie) | `8.4.27-1~deb13u1` | mod_php | 🚫 | fixed control; package revision includes the 109618/109619 fix |
| Debian 12 (bookworm) | `8.2.35-1~deb12u1` | mod_php + FPM | 🚫 | fixed control; A1 200, A2 200, 0 FPM exit-70; package revision includes the 109618/109619 fix |
| Debian 12 (bookworm) | `8.2.32-1~deb12u1` | mod_php + FPM | ❌ | A1 500 parse-OOM, A2 500, 2 FPM exit-70; B1 no leak; crash/DoS only; B1 leak/address recovery blocker |
| Ubuntu 25.04 (plucky) | `8.4.5-1ubuntu1.2` | mod_php | ✅ | package-specific; 2/2 full-chain RCE; symbol offsets `0x245810`/`0x424fc0`; `fillers=116`; `S=main+0xF7398`; upstream 8.4.5 not claimed vulnerable |
| Ubuntu 22.04 LTS | `8.1.2-1ubuntu2.28` | mod_php + FPM | 🚫 | fixed control; A1 200 (no cookie), A2 200, 0 FPM exit-70; package revision carries the branch fix |
| Ubuntu 22.04 LTS | `8.1.2-1ubuntu2` | mod_php + FPM | ❌ | A1 500 parse-OOM, A2 500, 2 FPM exit-70; B1 no leak; crash/DoS only; B1 leak/address recovery blocker |
| Ubuntu 24.04 LTS | `8.3.6-0maysync1` (release `8.3.6`, pre-update) | mod_php + FPM | ❌ | 109618 CL body: mod_php SIGSEGV 4/4 (OOM 12,288 B); Apache+FPM HTTP 200 empty, OOM 12,288 B, child exit 70, no SIGSEGV, next GET 200; CL A1 OOM 4,096 logged; nginx 64 MiB A1 child exit 70/request; no RCE/OOB/proof; crash/DoS only |
| Ubuntu 24.04 LTS | `8.3.6-0ubuntu0.24.04.13` | mod_php + FPM | 🚫 | fixed control; mod_php 14,497,878 B chunked body -> 200 `OK`, PHP warning `Actual POST length does not match Content-Length, and exceeds 8388608 bytes`, no OOM; A1 200, 0 FPM exit-70; fixed mod_php A2/B2 not run |
| Ubuntu 26.04 LTS | `8.5.4-0ubuntu1` (release) | mod_php + FPM | ❌ | 109618 CL body: mod_php SIGSEGV 4/4 (OOM 12,288 B); Apache+FPM HTTP 200 empty, OOM 12,288 B, child exit 70, no SIGSEGV, next GET 200; CL A1 OOM 4,096 logged; nginx 64 MiB A1 child exit 70/request; B1 819,208 B heap leak 1/8, no libphp/S anchor; no ASLR break; no RCE/OOB/proof; crash/DoS only |
| Ubuntu 26.04 LTS | `8.5.4-0ubuntu1.5` | mod_php + FPM | 🚫 | fixed control; mod_php 14,497,878 B chunked body -> 200 `OK`, PHP warning `Actual POST length does not match Content-Length, and exceeds 8388608 bytes`, no OOM; A1 200, 0 FPM exit-70 |
| Alpine 3.20 | `8.3.15-r0` | mod_php (apache2) | ❌ | 8.3 A1 parse-phase OOM 500; B1 0/3, 34-byte cookies |
| Alpine 3.21 | `8.4.27-r0` | mod_php (apache2) | 🚫 | fixed; A1 200, B1 normal cookie |
| Arch Linux rolling | `8.5.12-1`; `php-legacy 8.3.36-1` | mod_php | 🚫 | fixed versions; no vulnerable package in repos |
| Arch ini transplant | Arch `php.ini` on official `8.4.26` | mod_php | ✅ | **not an Arch package**; shipped ini is chain-compatible |
| Rocky Linux 9 | `8.0.30-8.el9_8.1` | FPM only | ❌ | no `libphp.so`; no `Set-Cookie`; 8.0 resets `send_cookie` |

Positive control in the same run: official `8.4.26` mod_php reproduced the
full chain (A1 500, B1 819,208-byte leak, A2 500, B2 `uid=33(www-data)`), so
the distro negatives are measured against a working harness. None of the newly
tested negative distro packages produced a full-chain RCE or an OOB write; the
vulnerable revisions show only crash/DoS (mod_php A1/A2 OOM and 109618 worker
SIGSEGV; FPM `exit 70`). The 26.04 release B1 leak is heap-only with no
`libphp`/`S` anchor, so no ASLR break was obtained. The B1 body geometry is
8.4-derived, so a build-specific leak offset cannot be excluded.

**Ubuntu 24.04/26.04 gap closure (2026-10-23).** Release `8.3.6`
(`8.3.6-0maysync1`) and `8.5.4-0ubuntu1` are crash/DoS-only: the Apache+FPM
Content-Length 109618 body returns HTTP 200 empty, OOM 12,288 B, FPM child
exit 70, no SIGSEGV, next GET 200; the CL A1 OOM 4,096 is logged; nginx
64 MiB A1 loses one child (exit 70) per request. Fixed
`8.3.6-0ubuntu0.24.04.13` and `8.5.4-0ubuntu1.5` return 200 `OK` for the
14,497,878 B chunked body with the PHP warning `Actual POST length does not
match Content-Length, and exceeds 8388608 bytes` and no OOM. No RCE, OOB write,
or proof was obtained; the release rows are ❌ with a crash/DoS-only blocker. No
ASLR break and no `/tmp/dc_*` proof file on any target.

Debian-family packages use a different geometry from upstream: `fillers=116`
and `S=main+0xF7398` (upstream: `fillers=115`, `S=main+0xF8398`).
`zif_system`/`zval_ptr_dtor` also move per build: Debian 13 8.4.24 is
`0x24cdd0`/`0x424ff0`, Ubuntu 25.04 8.4.5-1ubuntu1.2 is
`0x245810`/`0x424fc0`. Do not transplant offsets between builds.

### Applications

| App / version | PHP + SAPI | Endpoint / config | Status | Class / qualifier |
|---|---|---|---|---|
| WordPress 7.1.3 | 8.4.26 mod_php | `/wp-content/index.php` (silence file) | ✅ | engine-level, lab-conditioned; 6/6 |
| WordPress 7.1.3 | 8.4.26 nginx+mod_php non-stock | `/index.php` front controller | ✅ | engine-level; 6/6 OOB; pre-app — WP not installed (`mysqli` missing), HTTP 500 |
| WordPress 7.1.3 | 8.4.26 nginx+mod_php non-stock | `/wp-content/index.php` | ✅ | engine-level; non-stock 64M; 6/6 |
| WordPress 7.1.3 | 8.4.26 FPM | `/index.php` | ❌ | multipart OOM only (502/exit 70) |
| WordPress 7.1.3 | 8.5.11 FPM | `/index.php` | ❌ | OOM only |
| WordPress 7.1.3 | 8.3.35 FPM | `/index.php` | ❌ | OOM only |
| Roundcube 1.7.5 | 8.4.26 FPM | nginx 1m/25m/64m; `/` and `/static.php` | ❌ | no chain/RCE; DB sessions (not file); `/static.php` allowlisted but still enters PHP; `PHPSESSID` POST ignored; A1 at 128M exits 70, no session file; B1 no leak; stock 1 MiB 413; 25/64M still no leak |
| Nextcloud 35.0.2 | 8.4.26 FPM | docs 10G/512M; 10G/128M | ❌ | no chain/RCE; documented 512M stack removes OOM; 10G/128M A1 exits 70, no session file; B1 no leak |
| Drupal 11.4.11 | 8.5.10 FPM (lab build) | file sessions + `.user.ini` + 2M + `static1` | ✅ | app-assisted, **not stock**; 3/3 fresh ASLR |
| Drupal 11.4.11 | 8.4.26 FPM | 64M; stock DB sessions | ❌ | no chain/RCE; 64M A1 exits 70, no session file; B1 no leak |
| Joomla 5.4.10 | 8.5.10 FPM (lab build) | file sessions + 2M + `cleanup=0` | ✅ | app-assisted, **not stock** |
| MediaWiki 1.46.2 | 8.4.26 FPM | `/index.php` | ❌ | OOM only |
| MediaWiki 1.46.2 | 8.5.11 FPM | `/index.php` | ❌ | OOM only |
| MediaWiki 1.46.2 | 8.3.35 FPM | `/index.php` | ❌ | OOM only |
| Moodle 5.0.10 | 8.5.11 FPM | normal request | ❌ | fresh serializer at RINIT |

App controls: PHP 8.4.27 at 64M returned 200 with no OOM, and disabling
`session.upload_progress` moved the failure to an app-level 500 (worker
survives) but still produced no B1 leak. B2 was not attempted after a negative
B1. The app rows above therefore show reachability and availability failures,
not a memory-corruption primitive.

### Other CVEs

| CVE | Builds | Config | Status | Class / result |
|---|---|---|---|---|
| CVE-2026-115560 | 8.4.26 / 8.5.11; mod_php + FPM | `cleanup=0`, app gadget, `php_binary`/`php_serialize` → `php` | ✅ | app-gadget RCE; no memory corruption; ASAN/LSan clean |
| CVE-2026-115560 | stock `cleanup=1` | stock | ❌ | poisoned record deleted before app code |
| CVE-2026-115560 | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | `cleanup=0` | ✅ | still reproduces; 109618/109619 fixes do not address this CVE |
| CVE-2026-6722 | 8.4.20 / 8.5.5; SOAP | mod_php | ❌ | unauthenticated remote DoS, no RCE; handlers call primitive, no ASLR bypass |
| CVE-2026-6722 | 8.4.21 / 8.5.6 | mod_php | 🚫 | fixed |
| CVE-2019-11043 | 7.1.32 / 7.2.23 / 7.3.10; FPM | nginx with path-info config | ✅ | config-induced RCE |
| CVE-2019-11043 | same | stock Debian/WordPress/MediaWiki config | ❌ | blocked |
| CVE-2019-11043 | 7.1.33 / 7.2.24 / 7.3.11; FPM | fixed | 🚫 | fixed |

### Coverage gaps

39 numbered entries; every row is `—` (no qualifying RCE or untested), never ❌.

| ID | Status | Lane | Untested cell | Existing evidence / note | Priority |
|---|---|---|---|---|---|
| G01 | — | Distro | Debian 11 `7.4.33` + mod_php | none for package | P2 |
| G02 | — | Distro | Debian 11 `7.4.33` + FPM | none | P2 |
| G03 | — | Distro | Debian 12 `8.2.32` + mod_php (other 8.2.x untested) | tested ❌; A1/A2 500 parse-OOM, 0/13 B1 leaks (34 B); B1 blocker, not an offset miss | P0 |
| G04 | — | Distro | Debian 12 `8.2.x` + FPM | 8.2.32 FPM: A1/A2 502, 2 exit-70, no B1 leak; other 8.2.x untested | P0 |
| G05 | — | Distro | Debian 13 `8.4.24-1~deb13u1` + FPM | mod_php tested | P1 |
| G06 | — | Distro | Ubuntu 20.04 `7.4.3` + mod_php | upstream 7.4.33 | P2 |
| G07 | — | Distro | Ubuntu 20.04 `7.4.3` + FPM | upstream 7.4.33 | P2 |
| G08 | — | Distro | Ubuntu 22.04 pre-update `8.1.2` + mod_php | tested ❌; A1/A2 500 parse-OOM, 0/13 B1 leaks; fixed at `8.1.2-1ubuntu2.28` | P0 |
| G09 | — | Distro | Ubuntu 22.04 `8.1.2` + FPM | base FPM: A1/A2 502, 2 exit-70, no B1 leak; fixed at `.28` | P0 |
| G10 | — | Build | FPM `8.2.35` fixed control | runtime: A1/A2 200, 0 exit-70; no qualifying RCE | P0 |
| G11 | — | Build | FPM `8.4.27` fixed control | source only | P1 |
| G12 | — | Build | mod_php `8.4.9` | between 0/8 and 17/17 | P1 |
| G13 | — | Build | mod_php `8.4.0` | none | P2 |
| G14 | — | Build | mod_php `8.1.34` | 8.1.33 and FPM 8.1.34 tested | P2 |
| G15 | — | Build | 5.6.0 / 7.0.0 / 7.1.0 runtime | tips only | P3 |
| G16 | — | SAPI/OS | nginx+mod_php `8.4.10` | mod_php warm chain | P2 |
| G17 | — | SAPI/OS | nginx+mod_php `8.4.20` | mod_php warm chain | P2 |
| G18 | — | SAPI/OS | nginx+mod_php `8.5.11` | mod_php leak only | P2 |
| G19 | — | SAPI/OS | direct FastCGI full chain `8.4.26` / `8.5.11` | framing tests only | P3 |
| G20 | — | SAPI/OS | FreeBSD 13/14 + Apache + mod_php (ports) | build-specific offsets | P2 |
| G21 | — | SAPI/OS | FreeBSD 13/14 + nginx + FPM (ports) | build-specific offsets | P2 |
| G22 | — | SAPI/OS | Windows Server + IIS 10 + FastCGI (8.3/8.4/8.5 NTS) | no FPM on Windows | P2 |
| G23 | — | SAPI/OS | Windows + Apache + mod_php | optional | P3 |
| G24 | — | App | WordPress 7.1.3 installed with `mysqli`/DB | `/index.php` 6/6 pre-app; tree was 500/no DB | P1 |
| G25 | — | App | WordPress 7.1.3 nginx+FPM full chain | OOM only | P1 |
| G26 | — | App | WordPress 7.1.3 mod_php 8.3.35 / 8.5.11 | only 8.4.26 tested | P2 |
| G27 | — | App | Drupal 11.4.11 **stock** DB sessions | tested ❌ at 8.4.26 FPM 64M; A1 exit-70, no B1 leak | P1 |
| G28 | — | App | Drupal 10.6.20 | none | P2 |
| G29 | — | App | Joomla 5.4.10 **stock** DB sessions | lab file-session only | P1 |
| G30 | — | App | Joomla 6.2.0 | none | P2 |
| G31 | — | App | MediaWiki 1.46.2 mod_php / other FPM | FPM OOM only | P2 |
| G32 | — | App | Laravel 13 | none | P1 |
| G33 | — | App | Symfony 8.1 | none | P1 |
| G34 | — | App | Roundcube 1.7.4 | 1.7.5 tested ❌ (DB sessions, no B1 leak); 1.7.4 not run | P0 |
| G35 | — | App | Nextcloud 35 | 35.0.2 tested ❌ (512M no OOM, 128M exit-70, no B1 leak); 34/33 in G39 | P1 |
| G36 | — | App | phpMyAdmin 5.2.3 | none | P2 |
| G37 | — | App | Magento 2.4.9 | optional | P3 |
| G38 | — | App | OpenCart 4.x | optional; version unverified | P3 |
| G39 | — | App | Laravel 12 / Symfony 7.x/6.4 / Nextcloud 34/33 | secondary versions | P3 |

No evidence artifacts (receipts, bodies, binaries, dumps or per-run reports)
are shipped in this repository; only the tool, its offset profiles and this
document are.

## Layout

| path | contents |
|---|---|
| `tool/php2shell.py` | chain driver (`recon`, `producer`, `write_stage`, `leak`, `g2`, `chain`) |
| `tool/debian8424.py` | standalone Debian 13 `libapache2-mod-php8.4` 8.4.24 four-stage runner (A1→B1→A2→B2); dry by default |
| `tool/phpcheck.py` | passive PHP version/build CVE candidate checker; no exploit traffic |
| `tool/run` | POSIX shell wrapper: `./tool/run --help` |
| `tool/modules/` | request/producer builders, chain stages, per-build profiles (see `tool/modules/README.md`) |
| `tool/stages/` | fingerprint and probe stage |
| `addresses/` | per-build offset profiles loaded by `g2_chain.py` and `leak_stage.py` |

`addresses/g2_fpm_*.json` are runtime inputs for `--step g2` and
`addresses/apache_libphp.json` for `--step leak`; without them those steps
cannot resolve a build.

## Requirements

- Python 3.8 or newer, standard library only (no third-party packages).
- A POSIX shell for `tool/run`.

There is nothing to install; `requirements.txt` is intentionally empty apart
from a comment.

## Usage

```sh
./tool/run --help

# read-only fingerprint/probe against a registered target
./tool/run --target wiki --step recon

# send a producer payload to an explicit target
./tool/run --target wp --step producer --body-bytes 5700000

# mod_php end-to-end chain (ordered producer + consumer sequence)
./tool/run --target modphp --step chain --url http://127.0.0.1/ --command id

# offline FPM G2/G6 record plan from explicit addresses (no transport)
./tool/run --step g2 --g2-profile 8.5.10 --g2-decode zif_system \
    --g2-x 0x7f0000000000 --g2-x2 0x7f0000001000 --g2-p 0x7f0000002000 \
    --g2-b0 0x7f0000003000
```

Steps: `recon` (read-only receipt), `producer` (send a producer payload),
`write_stage` (build the final forged multipart, no send), `leak` (mod_php
calibration plan, no transport), `g2` (offline FPM G2/G6 record plan, no
transport), `chain` (mod_php ordered chain; FPM targets use the legacy
blocker-hold + rearm + forged staged multipart).

Registered targets and per-build constants live in `tool/modules/profiles.py`.
Receipts are written under `files/io/` by default and are git-ignored.

### Debian 13 mod_php 8.4.24 four-stage runner

`tool/debian8424.py` is a separate, research-derived runner for the exact
Debian package `libapache2-mod-php8.4 8.4.24-1~deb13u1`. It is deliberately
not a `--profile` entry and does not change the existing `--step chain`
semantics. The target shape is prefork mod_php with
`output_buffering=4096` and a 22-byte PHP endpoint
(`<?php echo "OK\n"; ?>`); the package must match, because the constants are
build-specific.

Dry-run is the default and sends no traffic; `--live` sends one exact
A1 → B1 → A2 → B2 sequence. A1/B1/A2/B2 are 1,060,211 / 33,128,677 /
279,432 / 451,384 bytes and are hash-checked before sending.

```sh
# offline: generate and verify bodies, no socket
python3 -m tool.debian8424 --url http://127.0.0.1:8080/ --dry-run

# live, with a built-in loopback HTTP callback collector
python3 -m tool.debian8424 --url http://127.0.0.1:8080/ \
    --command id --lhost 127.0.0.1 --lport 9001 --timeout 180 \
    --output files/io/debian8424-run1 --live
```

Use `--callback http://HOST:PORT` with `--callback-log FILE` for an external
collector, or `--proof-file PATH` / `--error-log PATH` when the runner shares
the target filesystem (bare-metal local use). Success is reported only when
the marker is observed through one of those channels; an HTTP 200/500 response
alone is not success. There is no `docker exec` and no container-filesystem
read. B1 is probabilistic, and the B2 command must fit the 200-byte `ht`
carrier.

### Passive version/build checker

`tool/phpcheck.py` maps a PHP version (optionally with a distro package
revision) and SAPI to CVE-2026-109618/109619 candidate status. It sends no
exploit traffic: without `--url` it is offline, and `--url` performs one
unauthenticated GET and reads response headers only. Requires Python 3.10 or
newer.

```sh
python3 tool/phpcheck.py --version 8.4.24 --sapi mod_php
python3 tool/phpcheck.py --package 'libapache2-mod-php8.4=8.4.24-1~deb13u1' \
    --distro debian13 --sapi mod_php --json
python3 tool/phpcheck.py --list-cves
```

`VULNERABLE-CANDIDATE` is a lead, not proof: pass `--package`/`--distro` for
build identity and verify the listed conditions separately.

## Scope and authorization

Use only against systems you own or are explicitly authorized to test. The
tool sends malformed multipart bodies that can crash or exhaust PHP workers by
design.

## License

AGPL-3.0; see `LICENSE`.
