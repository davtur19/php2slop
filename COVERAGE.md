Full coverage ledger. `README.md` carries the summary; this file carries every
coverage row, including tested negatives, disclosure primitives without
execution, fixed builds, absent releases, not-applicable platforms and untested
applications. The 50 existing rows keep their original ID, evidence note and
priority; G52 and G53 are new. Each row is a cell with no
qualifying RCE (—). Marks are those of `README.md`: ✅ RCE · ❌ tested negative ·
🚫 patched · — no qualifying RCE.

Build caveat: 8.2.34 and 8.3.35 are target-written mod_php proofs from the recovered Oct-24 bodies (2/2 each); the earlier negative rerun is preserved and marked superseded. They are not part of the 50-row ledger.

G25 is covered by the 8.1.34 mod_php result; it is not an open item.

## Open items

| ID | Lane | Cell | Evidence / note | Priority |
|---|---|---|---|---|
| G03 | Distro | Debian 13 `8.4.24-1~deb13u1` + FPM | mod_php tested, including the default multi-worker WordPress cell; FPM not run | P1 |
| G04 | Distro | Ubuntu 20.04 `7.4.3` + mod_php | upstream 7.4.33 | P2 |
| G05 | Distro | Ubuntu 20.04 `7.4.3` + FPM | upstream 7.4.33 | P2 |
| G09 | Distro | FPM leak stage on Debian 11.11/13.7, Rocky 9.3, Amazon 2023.12, Fedora 44 and Alma 9.8 | the large body is rejected by the default `post_max_size` before session code; priming-only, not a valid leak negative; needs a smaller leak body or a declared larger limit | P1 |
| G10 | Distro | PHP 7.4/8.0 leak negatives (Debian 11, Rocky 9.3) | the multipart part cap truncates the 8.4 reference priming geometry, so prior leak negatives for those builds are invalid; the official-image 7.4.33/8.0.29/8.0.30 cells use the 8.0-geometry priming body and do not validate the distro packages | P0 |
| G11 | Distro | Debian 11 `7.4.33` sub-cap priming tuning | a smaller body returned 200 with no OOM; no 7.4-specific priming geometry was searched; no claim of 7.4 safety | P1 |
| G12 | Distro | Arch Linux rolling `8.5.12-1` / `php-legacy 8.3.36-1` | fixed metadata only; no local image or rootfs; repos ship 8.5.12/8.3.36 and no 8.4.26; the Arch-INI transplant is not an Arch package result; not package-tested | P2 |
| G13 | Distro | Alpine edge | fixed metadata only (8.4.27/8.5.12/8.3.36); no native install or chain test | P3 |
| G14 | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` priming onset | onset falls between two neighbouring big-value part counts; the boundary was not bisected | P1 |
| G15 | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` leak read spec | no leak on the default pool or on a pinned single-child pool with the 8.4-derived geometry; no write stage | P1 |
| G16 | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` second stage and write stage | the second stage was sent on FPM only; the write stage is unreachable without a leak | P1 |
| G17 | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` 109618 second band | the first stage is reached; the second band was not observed across the sweep, with no SIGSEGV/AH00052 | P1 |
| G18 | Distro | Amazon Linux 2023.12 `php8.3.36` / `8.5.12` live | repo version/file-list metadata only; no chain test | P3 |
| G20 | Distro | write stage on any distro package | needs a leak plus per-build offsets; no write stage attempted on Amazon/Fedora/Alma | P1 |
| G26 | Build | 5.6.0 / 7.0.0 / 7.1.0 runtime | tips only | P3 |
| G27 | SAPI/OS | nginx+mod_php `8.4.10` | mod_php warm chain | P2 |
| G28 | SAPI/OS | nginx+mod_php `8.4.20` | mod_php warm chain | P2 |
| G29 | SAPI/OS | nginx+mod_php `8.5.11` | mod_php leak only; the Set-Cookie channel is closed with a file part (`send_cookie=0`); per-build offsets in `addresses/apache_libphp_8511.json` | P2 |
| G30 | SAPI/OS | direct FastCGI full chain `8.4.26` / `8.5.11` | framing tests only | P3 |
| G50 | SAPI/OS | OpenLiteSpeed 1.9.3 + lsphp `8.5.11` (LSAPI) | no exact local `lsphp` build or LSAPI-specific trigger; upstream `sapi/litespeed/lsapi_main.c` has the same early return at `php_request_startup()` failure, so the expected shape is 500/exit, not a shutdown crash; not measured; —, not ❌ | P1 |

## Tested negatives

| ID | Lane | Cell | Evidence / note | Priority |
|---|---|---|---|---|
| G01 | Distro | Debian 12 `8.2.32` + mod_php (other 8.2.x untested) | tested ❌; priming and second stage parse-OOM, no leak; blocker, not an offset miss | P0 |
| G02 | Distro | Debian 12 `8.2.x` + FPM | 8.2.32 FPM: both priming shapes exit the worker, no leak; other 8.2.x untested | P0 |
| G06 | Distro | Ubuntu 22.04 pre-update `8.1.2` + mod_php | tested ❌; priming and second stage parse-OOM, no leak; fixed in the later package revision | P0 |
| G07 | Distro | Ubuntu 22.04 `8.1.2` + FPM | base FPM: both priming shapes exit the worker, no leak; fixed in the later revision | P0 |
| G08 | Distro | Rocky Linux 9.3 `8.0.30-8.el9_8.1` FPM only | tested ❌; no mod_php/`libphp`; priming and second stage 200; the leak body is rejected by the default `post_max_size`, so it is not a valid leak negative | P1 |
| G38 | App | Drupal 11.4.11 default DB sessions | tested ❌ on 8.4.26 FPM; worker exit, no leak; Drupal 10.6 file-session rows are in Applications | P1 |

## Disclosure primitives without execution

| ID | Lane | Cell | Evidence / note | Priority |
|---|---|---|---|---|
| G52 | SAPI/OS | FPM `8.4.26` libphp PIE base disclosure | the forged-length `Set-Cookie` read returns `std_object_handlers` at file offset `0x15FF100` in a 168-byte disclosure, so the base is the disclosed value minus `0x15FF100`; the derived base matches the ELF header at that address and the `zif_system` prologue read back from the worker; one disclosure covers every child of the master; no write primitive, so no RCE | P2 |
| G53 | SAPI/OS | FPM `8.4.26` Zend MM main-chunk disclosure | the qword at disclosure offset 56 is a free-slot `next` pointer inside the main chunk, so the chunk base is that qword minus `0x5A140`; 64 bytes suffice, the delta is constant across fresh workers and a container restart, and a warm worker carries the same base at offset 8 with delta `0x590F0`; the staged `htdata` at `+0x690D8` reads zero and a request-time spray places the fake `HashTable` at `+0x6D018`; no write, no RCE | P2 |

Both rows were measured on the default `php.ini-production` with a read-only
docroot. Each disclosure removes one ASLR input for FPM; neither supplies the
write primitive the chain still needs.

## Absent, fixed or not applicable

| ID | Lane | Cell | Evidence / note | Priority |
|---|---|---|---|---|
| G19 | Distro | Fedora 44 `php-fpm 8.5.12-1.fc44` 109618 producer | fixed build, not exercised; priming and second stage 200; the leak body is gated | P3 |
| G21 | Build | FPM `8.2.35` fixed control | runtime: priming requests 200, no worker exits; no qualifying RCE | P0 |
| G22 | Build | FPM `8.4.27` fixed control | source only | P1 |
| G23 | Build | mod_php `8.4.9` | absent upstream: no release, official image or ChangeLog entry; only an abandoned pre-publication tarball; not a vulnerable or fixed cell | P2 |
| G24 | Build | mod_php `8.4.0` | absent upstream: no release, official image or ChangeLog entry; only an abandoned pre-publication tarball; not a vulnerable or fixed cell | P2 |
| G31 | SAPI/OS | FreeBSD 13/14 + Apache + mod_php (ports) | prior inspection found no default 8.4.26 with mod_php and prefork; default 8.4.27/8.5.12 are fixed; a custom old 8.4.26 ports candidate was not proven and produced no target-written proof; not supported/not proven | P2 |
| G32 | SAPI/OS | FreeBSD 13/14 + nginx + FPM (ports) | build-specific offsets; no target-written proof; not proven | P2 |
| G33 | SAPI/OS | Windows Server + IIS 10 + FastCGI | no Windows host; no supported default-config RCE; the reviewed `p2s-win-test` is a Linux mod_php bundle, not a Windows path; CVE-2024-4577 (Windows CGI BestFit) is patched; not claimed | P2 |
| G34 | SAPI/OS | Windows + Apache + mod_php | no Windows host; no supported default-config RCE; not claimed | P3 |

## Untested applications and versions

| ID | Lane | Cell | Evidence / note | Priority |
|---|---|---|---|---|
| G35 | App | WordPress 7.1.3 installed with `mysqli`/DB | the core-file cell is tested; the installed `/index.php` front controller is pre-app; the tree was not installed | P1 |
| G36 | App | WordPress 7.1.3 nginx+FPM full chain | only FPM OOM and worker exits; FPM exits the worker 70 on a failed `php_request_startup()`, and the default nginx cap and `post_max_size` gate both stages; no default nginx+FPM chain | P1 |
| G37 | App | WordPress 7.1.3 mod_php 8.3.35 / 8.5.11 | 8.3.35 tested engine-level on the core file; 8.5.11 untested | P2 |
| G39 | App | Joomla 5.4.10 default DB sessions | file-session variant only | P1 |
| G40 | App | Joomla 6.2.0 | none | P2 |
| G41 | App | MediaWiki 1.46.2 mod_php / other FPM | FPM OOM only | P2 |
| G42 | App | Laravel 13 | none | P1 |
| G43 | App | Symfony 8.1 | none | P1 |
| G44 | App | Roundcube 1.7.4 | 1.7.5 tested ❌ (default DB and explicit file sessions, no leak); 1.7.4 not run | P0 |
| G45 | App | Nextcloud 35 | 35.0.2 tested ❌; other versions untested | P1 |
| G46 | App | phpMyAdmin 5.2.3 | none | P2 |
| G47 | App | Magento 2.4.9 | optional | P3 |
| G48 | App | OpenCart 4.x | optional; version unverified | P3 |
| G49 | App | Laravel 12 / Symfony 7.x/6.4 / Nextcloud 34/33 | secondary versions | P3 |
| G51 | App | WordPress 7.1.3 + `php:8.4.26-apache` default multi-worker | 8.4.26 only; the core-file question is resolved by the WordPress 8.4.26 run; WordPress is not bootstrapped, so a full WordPress-bootstrap cell remains untested; no claim for other builds | P1 |
