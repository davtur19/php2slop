# php2slop — gap-closure plan (README 6bf1d18)

**Generated:** 2026-10-23T20:40:53Z
**Repository:** `/home/davide/ailocal/php2slop`
**README:** `6bf1d184c99a2567e58c1c72f38e63e4a3dfbe36` (`6bf1d18`, sha256 `8ee5188060455b745063d979b953bfd5532bbd17692c76debc8e05433194bfe1`)
**Research root:** `/tmp/opencode/research` (abbreviated `R/` below)
**Plan root:** `/tmp/opencode/research/gap_plan_20261023T202856Z`

This plan only reads and schedules. No exploit test was run for this document, no repository
file was edited, and no README claim is changed. Every numbered README gap (`G01`–`G51`) is
dispositioned exactly once as **covered**, **assigned**, or **blocked**. Unnumbered `—` rows
that matter for the same matrix are tracked as `U01`–`U04`.

---

## 1. Scope, constraints and non-goals

### 1.1 Host constraints

| Constraint | Value / consequence |
|---|---|
| OS | Debian 13, rootless Docker (`DOCKER_HOST=unix:///run/user/1000/docker.sock`) |
| Privilege | no sudo, no host package installs, no host network namespaces outside `unshare -Ur` |
| Windows / FreeBSD | unavailable — `G31`–`G34` cannot be executed here |
| Application LFI | out of scope; no app file-read/write primitive is used |
| Network | local containers only; no third-party target traffic; no outbound payloads |
| Ports | all tasks use `33100`–`33179`; preflight must show them free |
| Container names | all names start `p2sg1-`, `p2sg2-`, `p2sg3-`, `p2sg4-`; no reuse of `p26*`, `p8183*`, `wpsm*`, `rt-*` |

### 1.2 Already-covered work that must not be repeated

These lanes are either finished or owned by an active worker. They are excluded from the task
list and are cited as coverage:

| Lane / directory | Covers | Status |
|---|---|---|
| `R/distro_gap_20261023T153629Z` | Debian 12 8.2.32/8.2.35, Ubuntu 22.04 8.1.2/.28, Ubuntu 24.04 8.3.6 | final |
| `R/distro_rest_20261023T163207Z` | Debian 11/13, Alpine 3.20/3.21, Rocky 9.3, Alma 9.8, Arch/Fedora/Amazon metadata | final |
| `R/distro_meta_20261023T171143Z` | Amazon 2023.12 8.4.26 live, Fedora 44, Alma/Rocky, Arch metadata | final |
| `R/modphp_audit_20261023T173136Z` | Debian 13 8.4.24 stock WordPress audit | final |
| `R/php8426_multiw_20261023T191822Z` | upstream 8.4.26 stock multi-worker WordPress | final |
| `R/modphp_warm_20261023T131308Z` | direct mod_php 8.4.10/8.4.20/8.4.26 warm chain | final |
| `R/nginx_modphp_20261023T132940Z` | nginx → Apache mod_php proxy invariance (8.4.24/26/27) | final |
| `R/apps_modphp_20261023T164153Z` | WP/Laravel/Symfony/Drupal mod_php 8.4.26/8.4.27 | final |
| `R/apps_gap_20261023T163831Z` | Drupal 10.6 file sessions, Roundcube 1.7.5 file sessions, 8.4.27 FPM control | final |
| `R/apps_frameworks_20261023T154615Z` | Joomla 6.2.0, MediaWiki 1.46.2, phpMyAdmin 5.2.3 under nginx+FPM | final |
| `R/apps_roundcube_nextcloud_20261023T153529Z` | Roundcube 1.7.5, Nextcloud 35.0.2, Drupal 11.4.11 | final |
| `R/litespeed_vuln_20261023T165657Z` | OLS 1.9.3 + lsphp 8.4.26/8.4.27 | final |
| `R/php81_83_modphp_20261023T191948Z` | PHP 8.1/8.2/8.3 stock mod_php | **active worker** |
| `R/wp_stock_multi_20261023T175947Z` | target-side WP 8.4.24 Docker setup | **active worker** |
| `R/php81_83_leak_20261023T174709Z` | 8.1/8.2/8.3 leak work | **active worker** |
| `R/local_run_8424_20261023T160013Z` | WP 8.4.24 local run | **active worker** |

### 1.3 Non-goals

- No new offsets are published as universal; every task derives per-build constants.
- No crash, OOM, `exit 70` or HTTP 500 is counted as RCE.
- No task edits the README. Results are written only under `R/<task>_<UTC>/`.
- No task uses a third-party target, an application LFI, or a target-side file write except
  the same-chain `B2` proof file under `/out`.

---

## 2. Disposition summary

| Disposition | Count | IDs |
|---|---:|---|
| Covered | 22 | G01, G02, G06, G07, G08, G10, G14, G17, G21, G22, G25, G27, G28, G30, G35, G36, G38, G40, G42, G43, G45, G51 |
| Assigned | 14 | G03, G04, G05, G12, G15, G16, G23, G24, G37, G39, G41, G44, G46, G50 |
| Blocked | 15 | G09, G11, G13, G18, G19, G20, G26, G29, G31, G32, G33, G34, G47, G48, G49 |
| **Total** | **51** | |

**Blocked means one of three things**, stated per row: the environment does not exist here
(FreeBSD/Windows), the build/package is fixed or absent (no vulnerable artifact), or the test
is structurally impossible under the stated stock transport (B1 geometry / no B1 primitive).

---

## 3. Gap matrix (G01–G51)

Priorities are copied from the README. `R/` is `/tmp/opencode/research`.

| ID | P | Lane | Untested cell | Disposition | Evidence or task |
|---|---|---|---|---|---|
| G01 | P0 | Distro | Debian 12 `8.2.32` + mod_php (other 8.2.x untested) | **covered** | `R/distro_gap_20261023T153629Z/report.md` §4: A1/A2 500 parse-OOM, 0/13 B1 (34 B); 8.2.35 fixed |
| G02 | P0 | Distro | Debian 12 `8.2.x` + FPM | **covered** | same §5: 8.2.32 FPM A1/A2 502, 2 exit-70, no B1; 8.2.35 fixed |
| G03 | P1 | Distro | Debian 13 `8.4.24-1~deb13u1` + FPM | **assigned T04** | mod_php tested; FPM not run |
| G04 | P2 | Distro | Ubuntu 20.04 `7.4.3` + mod_php | **assigned T05** | upstream 7.4.33 only |
| G05 | P2 | Distro | Ubuntu 20.04 `7.4.3` + FPM | **assigned T05** | upstream 7.4.33 only |
| G06 | P0 | Distro | Ubuntu 22.04 pre-update `8.1.2` + mod_php | **covered** | `R/distro_gap...` §4: A1/A2 500, 0/13 B1; `.28` fixed 200 |
| G07 | P0 | Distro | Ubuntu 22.04 `8.1.2` + FPM | **covered** | same §5: A1/A2 502, 2 exit-70, no B1; `.28` fixed |
| G08 | P1 | Distro | Rocky 9.3 `8.0.30-8.el9_8.1` FPM only | **covered** | `R/distro_rest_20261023T163207Z/report.md` §5.5: no mod_php, B1 8M-gated, no primitive |
| G09 | P1 | Distro | FPM B1 on Debian 11/13.7, Rocky 9.3, Amazon 2023.12, Fedora 44, Alma 9.8 | **blocked** | 33,128,677 B B1 exceeds stock `post_max_size=8M`; B1 needs 16×2 MB parts, so a sub-8M B1 does not exist; declared length is rejected before session code |
| G10 | P0 | Distro | PHP 7.4/8.0 B1 negatives (Debian 11, Rocky 9.3) | **covered** (corrected) | `R/distro_rest...` §4.1 + `R/fpm_pre8_chain_20261023T091239Z`: 1,020-part cap truncates the 8.4 A1; prior B1 negatives are invalid; 974-part body 200/no OOM |
| G11 | P1 | Distro | Debian 11 `7.4.33` sub-1,020-part A1 tuning | **blocked** | 974-part body 200/no OOM; direct 7.4 mod_php has no B1 primitive in the tested geometry; no valid 7.4 A1 constructor exists without a new groom |
| G12 | P2 | Distro | Arch Linux rolling `8.5.12-1` / `php-legacy 8.3.36-1` | **assigned T12** | metadata only; no native package run |
| G13 | P3 | Distro | Alpine edge | **blocked** | fixed metadata only (8.4.27/8.5.12/8.3.36); all shipped lines fixed, no vulnerable package |
| G14 | P1 | Distro | Amazon 2023.12 8.4.26 A1 exact onset | **covered** | `R/distro_meta_20261023T171143Z/report.md` §3.5: onset between 860 and 870 big-value parts; `a1_p880` 500/OOM |
| G15 | P1 | Distro | Amazon 2023.12 8.4.26 B1 build-tuned read spec | **assigned T06** | 0/5 stock and 0/5 single-child is the 8.4-derived geometry; no per-build filler sweep |
| G16 | P1 | Distro | Amazon 2023.12 8.4.26 A2/B2 | **assigned T06** | A2 sent on FPM only; B2 unreachable without B1 |
| G17 | P1 | Distro | Amazon 2023.12 8.4.26 109618 S2 band | **covered** | `R/distro_meta...` §3.6: S1 at H=427343; 38 H points, 33 below S1; no S2, 0 SIGSEGV |
| G18 | P3 | Distro | Amazon 2023.12 8.3.36 / 8.5.12 live | **blocked** | both are fixed builds; only metadata, no vulnerable package |
| G19 | P3 | Distro | Fedora 44 `php-fpm 8.5.12-1.fc44` 109618 producer | **blocked** | fixed build, FPM-only, no mod_php; no vulnerable artifact |
| G20 | P1 | Distro | B2 on any distro package | **blocked** | requires a B1 leak plus per-build offsets; no distro B1 leak exists in any measured lane |
| G21 | P0 | Build | FPM `8.2.35` fixed control | **covered** | `R/distro_gap...` §5: A1/A2 200, 0 exit-70, no RCE |
| G22 | P1 | Build | FPM `8.4.27` fixed control | **covered** | `R/apps_gap_20261023T163831Z/report.md`: A1/A2/B1/B2 200, no OOM, no exit-70 |
| G23 | P1 | Build | mod_php `8.4.9` | **assigned T01** | only patch between the measured 8.4.1–8.4.8 block and 8.4.10 RCE |
| G24 | P2 | Build | mod_php `8.4.0` | **assigned T02** | no measurement before 8.4.1 |
| G25 | P2 | Build | mod_php `8.1.34` | **covered** | active worker `R/php81_83_modphp_20261023T191948Z`; do not duplicate |
| G26 | P3 | Build | 5.6.0 / 7.0.0 / 7.1.0 runtime | **blocked** | official schema1 images unavailable; README row is tips-only |
| G27 | P2 | SAPI/OS | nginx+mod_php `8.4.10` | **covered** | `R/modphp_warm_20261023T131308Z` 4/4 warm + `R/nginx_modphp_20261023T132940Z` proxy invariance; exact combined cell not re-run |
| G28 | P2 | SAPI/OS | nginx+mod_php `8.4.20` | **covered** | `R/modphp_warm...` 17/17 warm + proxy invariance for 8.4.24/26/27 |
| G29 | P2 | SAPI/OS | nginx+mod_php `8.5.11` | **blocked** | direct 8.5.11 mod_php is leak-only (53 pointers, no `zval_ptr_dtor`, no 87-bucket); nginx adds only the transport gate |
| G30 | P3 | SAPI/OS | direct FastCGI full chain `8.4.26` / `8.5.11` | **covered** | `R/fastcgi_smuggle_20261023T131351Z/report.md`: config-injection full chain on both; the A1/B1 body path is `post_max_size`-gated |
| G31 | P2 | SAPI/OS | FreeBSD 13/14 + Apache + mod_php (ports) | **blocked** | no FreeBSD host or VM available |
| G32 | P2 | SAPI/OS | FreeBSD 13/14 + nginx + FPM (ports) | **blocked** | no FreeBSD host or VM available |
| G33 | P2 | SAPI/OS | Windows Server + IIS 10 + FastCGI (8.3/8.4/8.5 NTS) | **blocked** | no Windows host; no FPM on Windows |
| G34 | P3 | SAPI/OS | Windows + Apache + mod_php | **blocked** | no Windows host |
| G35 | P1 | App | WordPress 7.1.3 installed with `mysqli`/DB | **covered** | `R/apps_modphp...` §1: WP dev/prod installed on MariaDB; front controller A1 `SIGABRT`, no chain; `/wp-content/index.php` is the engine-level success |
| G36 | P1 | App | WordPress 7.1.3 nginx+FPM full chain | **covered** | `R/oom109618_wp_20261022T101958Z` + `R/apps_gap...`: stock nginx 1 MiB and FPM `post_max_size=8M` gate B1; A1 is OOM/exit-70 only, no state; app layer adds no primitive |
| G37 | P2 | App | WordPress 7.1.3 mod_php 8.3.35 / 8.5.11 | **assigned T13** | only 8.4.24/8.4.26 tested |
| G38 | P1 | App | Drupal 11.4.11 **stock** DB sessions | **covered** | `R/apps_gap...`: 64M A1 exit-70, B1 no leak; `R/apps_modphp...` same |
| G39 | P1 | App | Joomla 5.4.10 **stock** DB sessions | **assigned T09** | lab file-session only |
| G40 | P2 | App | Joomla 6.2.0 | **covered** | `R/apps_frameworks_20261023T154615Z/report.md`: FPM 8.4.26 OOM/502, no RCE |
| G41 | P2 | App | MediaWiki 1.46.2 mod_php / other FPM | **assigned T10** | FPM OOM only; mod_php untested |
| G42 | P1 | App | Laravel 13 | **covered** | `R/apps_modphp...` mod_php static `/assets/index.php` RCE + front-controller no; `R/apps_frameworks...` FPM negative |
| G43 | P1 | App | Symfony 8.1 | **covered** | same two reports: mod_php static RCE, front-controller/FPM negative |
| G44 | P0 | App | Roundcube 1.7.4 | **assigned T08** | 1.7.5 tested; 1.7.4 not run |
| G45 | P1 | App | Nextcloud 35 | **covered** | `R/apps_roundcube_nextcloud_20261023T153529Z/report.md`: 35.0.2 512M no OOM, 128M exit-70, no leak |
| G46 | P2 | App | phpMyAdmin 5.2.3 | **assigned T11** | none under mod_php |
| G47 | P3 | App | Magento 2.4.9 | **blocked** | optional; heavy stack, no engine discriminator, no artifact path |
| G48 | P3 | App | OpenCart 4.x | **blocked** | optional; version unverified |
| G49 | P3 | App | Laravel 12 / Symfony 7.x/6.4 / Nextcloud 34/33 | **blocked** | secondary versions; same PHP engines, no new engine delta |
| G50 | P1 | SAPI/OS | OpenLiteSpeed 1.9.3 + lsphp `8.5.11` (LSAPI) | **assigned T03** | only 8.4.26/8.4.27 measured; 8.5.11 binary absent |
| G51 | P1 | App | WordPress 7.1.3 + upstream `php:8.4.26-apache` stock multi-worker | **covered** | `R/php8426_multiw_20261023T191822Z/report.md`: 3 blind + 1 extra target-written proof |

### 3.1 Unnumbered `—` rows added to the matrix

| ID | Row | Disposition | Reason |
|---|---|---|---|
| U01 | Roundcube 1.7.5 + 8.4.27 FPM (Applications table `—`) | **assigned T08 (control arm)** | README explicitly says "not rebuilt on 8.4.27"; T08 supplies the control |
| U02 | lighttpd 1.4.79 + FPM 8.4.26 chain | **assigned T07** | `R/alt_sapi_20261023T144614Z` measured body limits only; no A1→B2 chain |
| U03 | Apache 2.4 + `mod_proxy_fcgi` + Debian 13 8.4.24 FPM | **assigned T04 (arm B)** | README G03 only says "FPM not run"; Apache+FPM is a separate transport shape from nginx+FPM |
| U04 | OpenResty 1.31.1.1 + FPM 8.4.26 with raised `client_max_body_size` | **covered** | `R/alt_sapi...` stock 1 MiB returns 413 at 1,048,577 B and the 6.5 MB 109618 body; with the override it is byte-equivalent to nginx+FPM, which is covered by `R/apps_gap...` and `R/nginx_modphp...` |

---

## 4. Task specifications

All tasks use the same conventions:

- **Endpoint (engine tasks):** `/index.php` containing exactly `<?php echo "OK\n"; ?>\n`
  (22 B, sha256 `1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23`).
- **Stage bodies:** A1 `1,060,211 B` sha256 `8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6`;
  B1 `33,128,677 B` sha256 `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2`;
  A2 upstream `279,369 B` sha256 `7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236`;
  A2 Debian `279,432 B` sha256 `7d3e674eed2cad578362a9177c93d67d37b02781a32878be7ea599a3c13ad3c6`;
  B2 `451,384 B` address-dependent, built per run.
- **Stock INI:** `php.ini-production`, `memory_limit=128M`, `post_max_size=8M`,
  `upload_max_filesize=2M`, `session.upload_progress.enabled=On`, `output_buffering=4096`,
  `display_errors=Off`, `zend.assertions=-1`.
- **App tasks:** install only the extensions the installer requires (`intl`, `gd`, `mysqli`,
  `pdo_sqlite`, `zip` as applicable), record `php -m`, and do not raise PHP limits to make an
  installer pass. Before `docker-php-ext-install`, install the matching `-dev` libraries
  (`libicu-dev`, `libpng-dev`, `libjpeg62-turbo-dev`, `libfreetype6-dev`, `libzip-dev`). An app
  that cannot install under the stock limits is recorded as a setup failure, not as a chain
  result.
- **B1 acceptance:** decode the `Set-Cookie` value; a leak requires **> 4,096 decoded bytes**.
  A normal `PHPSESSID` is 26 chars / 34 B (or 32 chars / 40 B on some packages). Never count a
  short cookie as a leak.
- **RCE acceptance:** a target-written proof file containing `uid=33(www-data)` (rootless host
  owner `100032:100032`) plus the run marker. No status code, OOM or crash counts.
- **Artifacts (every task):** `report.md`; `bodies/` with exact body hashes; `conf/` with every
  modified config and a `diff` against stock; `evidence/` with versions, package list, `php -i`,
  `php -v`, module list, binary hashes, `docker inspect`; `logs/` access/error/FPM/Apache/OLS;
  `out/` raw responses; `proof/` only if RCE; `scripts/` generators and drivers.

### T01 — PHP 8.4.9 mod_php source build (G23)

| Field | Value |
|---|---|
| **Priority / batch** | P1 / Batch 1 |
| **Ports / network** | `33100` (8.4.9), `33101` (8.4.8 control); `p2s-gap1` `10.240.1.0/24` |
| **Containers** | `p2sg1-php849`, `p2sg1-php848` |
| **Base image** | `php:8.4.8-apache` `php@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f` (Debian 12 bookworm, Apache 2.4.62, prefork) |
| **Source** | `https://www.php.net/distributions/php-8.4.9.tar.gz` sha256 `1068de4448d77cd44cc15b96984f1f9accf4dbc883b793aea6d02846ef8b1ba1` |
| **Build deps** | `apt-get install -y apache2-dev libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libonig-dev libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev libargon2-dev libsodium-dev libreadline-dev` |
| **Configure** | exact `php:8.4.8-apache` line, reproduced from `php -i`: `./configure --build=x86_64-linux-gnu --with-config-file-path=/usr/local/etc/php --with-config-file-scan-dir=/usr/local/etc/php/conf.d --enable-option-checking=fatal --with-mhash --with-pic --enable-mbstring --enable-mysqlnd --with-password-argon2 --with-sodium=shared --with-pdo-sqlite=/usr --with-sqlite3=/usr --with-curl --with-iconv --with-openssl --with-readline --with-zlib --disable-phpdbg --with-pear --with-libdir=lib/x86_64-linux-gnu --disable-cgi --with-apxs2 build_alias=x86_64-linux-gnu "PHP_UNAME=Linux - Docker" PHP_BUILD_PROVIDER=https://github.com/docker-library/php` |
| **Install** | `make -j"$(nproc)" && make install`; copy `php.ini-production` to `/usr/local/etc/php/php.ini`; `apache2ctl -k graceful`; verify `/usr/lib/apache2/modules/libphp.so` timestamp/hash changed |
| **Control** | same image/endpoint at 8.4.8 with the same stock INI; expected A1 500/200 block, no B1 leak (already in `R/modphp_84_matrix_20261023T074116Z`) |
| **Endpoint** | 22-byte `/index.php` |
| **Expected chain** | 8.4.9 is the only untested patch between 8.4.8 (blocked) and 8.4.10 (RCE). Either it stays on the blocked side — A1 parse-OOM with no stale `PS(id)` (or a clean 200), B1 normal 34/40-B cookie, A2 200/500, no B2 — or the END-cleanup `send_cookie` OOM appears and a >4,096-B B1 becomes possible. Decide empirically; do not extrapolate from 8.4.8 or 8.4.10. If a leak appears, derive this build's `S`, `zif_system`, `zval_ptr_dtor` with `nm`/`readelf` and attempt A2/B2 — do not transplant offsets. |
| **Acceptance (one line)** | `php -v` reports exactly `PHP 8.4.9` and the run ends with either (a) no decoded B1 > 4,096 B and no proof file, or (b) a leak with per-build offsets and a target-written proof, recorded as such. |

**T01 note.** `R/modphp_84_matrix_20261023T074116Z` says "8.4.9 was never released". That
statement is wrong for this artifact: `php-8.4.9.tar.gz` was downloaded from php.net with
sha256 `1068de4448d77cd44cc15b96984f1f9accf4dbc883b793aea6d02846ef8b1ba1`, and its
`main/php_version.h` reports `PHP_VERSION "8.4.9"`. Treat the tarball as the test artifact and
do not repeat the "never released" claim.

### T02 — PHP 8.4.0 mod_php source build (G24)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 3 |
| **Ports / network** | `33140` (`33141` optional 8.4.1 control); `p2s-gap3` `10.240.3.0/24` |
| **Containers** | `p2sg3-php840` |
| **Base / source** | `php:8.4.8-apache` (same digest as T01); `php-8.4.0.tar.gz` sha256 `9597b2054c4698bbfde637389ca1dcba570d5df28d26e3b5674b409c4f857b23` |
| **Build** | identical recipe and configure line as T01, only the tarball/prefix changes |
| **Expected chain** | pre-8.4.1: A1 likely 200 (no OOM) or parse abort; no END-cleanup `send_cookie` OOM; B1 normal cookie; no A2/B2 |
| **Acceptance (one line)** | `php -v` reports `PHP 8.4.0`, A1 is 200-or-parse-abort and B1 decodes to ≤ 4,096 B with no proof; any leak triggers the same per-build offset procedure as T01. |

### T03 — OpenLiteSpeed 1.9.3 + lsphp 8.5.11 (G50)

| Field | Value |
|---|---|
| **Priority / batch** | P1 / Batch 2 |
| **Ports / network** | `33120`; `p2s-gap2` `10.240.2.0/24` |
| **Containers** | `p2sg2-ols8511` |
| **Base** | `debian:13-slim`; LiteSpeed repo package `openlitespeed 1.9.3-1+trixie`; `lsphp` is a source build |
| **Source / build** | `php-8.5.11.tar.gz` from php.net; `./configure --disable-all --enable-litespeed --enable-session --without-pear --disable-cgi --with-config-file-path=/usr/local/lsws/lsphp8511/etc/php/8.5/litespeed --prefix=/usr/local/lsws/lsphp8511`; `make -j"$(nproc)" && make install` |
| **OLS config** | external app `lsphp8511` (`bin/lsphp`, `instances 1`, `maxConns 5`), script handler `lsapi:lsphp8511`, listener `8088`, docroot `/var/www`, `maxReqBodySize 2047M`, `maxReqHeaderSize 65536`, `inMemBufSize 60M` |
| **Endpoint** | 22-byte `/index.php`, plus `/health.php` returning `OK sapi=litespeed php=8.5.11` |
| **Expected chain** | LSAPI skips `php_request_shutdown()` when `php_request_startup()` fails: A1/109618 OOM gives HTTP 500, `wait4` `WIFEXITED` status **255**, no SIGSEGV/SIGABRT/SIGBUS; OLS respawns and health stays 200; B1 no leak; no RCE. Derive the LSAPI heap boundary with an H sweep (header lines 100k–500k) because it differs from mod_php. |
| **Acceptance (one line)** | `lsphp -i` reports `PHP 8.5.11` and `Server API => LiteSpeed V8.3`; a request-time OOM is observed as HTTP 500 + exit 255 with zero signal deaths, no >4,096-B B1 and no proof file. |

### T04 — Debian 13 8.4.24 FPM: nginx stock/raised + Apache mod_proxy_fcgi (G03, U03)

| Field | Value |
|---|---|
| **Priority / batch** | P1 / Batch 1 |
| **Ports / network** | `33102` nginx stock, `33103` nginx raised, `33104` Apache FCGI, `33105` nginx 8.4.27 control; `p2s-gap1` |
| **Containers** | `p2sg1-deb13-ngx-stock`, `p2sg1-deb13-ngx-64m`, `p2sg1-deb13-apache-fcgi`, `p2sg1-deb13-ngx-8427` |
| **Base** | `debian:13-slim` (trixie); `nginx 1.26.3-3+deb13u10`, `apache2 2.4.69-1~deb13u1` |
| **PHP packages** | exact `php8.4-fpm_8.4.24-1~deb13u1`, `php8.4-common_8.4.24-1~deb13u1`, `php8.4-cli_8.4.24-1~deb13u1`, `php8.4-opcache_8.4.24-1~deb13u1` from `deb.debian.org/debian/pool/main/p/php8.4/`; `dpkg -i` + `apt-mark hold`. Control: the same four at `8.4.27-1~deb13u1` |
| **FPM pool** | stock `www.conf`: `listen=/run/php/php8.4-fpm.sock`, `pm=dynamic`, `pm.max_children=5`, `pm.start_servers=2`, `pm.min_spare_servers=1`, `pm.max_spare_servers=3`; stock `php.ini` |
| **nginx** | stock `client_max_body_size` (1 MiB) on 33102; documented 64 MiB delta + `client_body_buffer_size 256k` + `fastcgi_read_timeout 60s` on 33103 |
| **Apache** | `a2enmod proxy_fcgi`; `SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"`; no `LimitRequestBody` change (1 GiB default) |
| **Expected chain** | stock nginx: A1 (1,060,211 B) and B1 (33,128,677 B) 413 before PHP. Raised nginx: A1 reaches FPM, OOM 4,096 B, `exit 70`/502. Apache FCGI: A1 reaches FPM, `exit 70`; B1 with declared CL is refused by `post_max_size=8M` (200/warning, `post=0`); chunked/forwarded variants tested separately. No B1 leak, no A2/B2. 8.4.27: A1/A2 200, no `exit 70`, no leak. |
| **Acceptance (one line)** | exact 8.4.24 package is installed on at least one arm, A1 reaches FPM and produces the documented `exit 70`/502, no B1 > 4,096 B exists on any arm, and the 8.4.27 control returns A1/A2 200 with zero `exit 70`. |

### T05 — Ubuntu 20.04 7.4.3 mod_php + FPM (G04, G05)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 2 |
| **Ports / network** | `33121` mod_php, `33122` nginx+FPM; `p2s-gap2` |
| **Containers** | `p2sg2-u2004-modphp`, `p2sg2-u2004-fpm` |
| **Base** | `ubuntu:20.04` (`sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214`) |
| **Packages** | exact `libapache2-mod-php7.4_7.4.3-4ubuntu2.29_amd64.deb`, `php7.4-fpm_7.4.3-4ubuntu2.29_amd64.deb`, `php7.4-cli_7.4.3-4ubuntu2.29_amd64.deb`, `php7.4-opcache_7.4.3-4ubuntu2.29_amd64.deb` (`apt-cache policy` confirms the version in focal) |
| **Apache** | stock prefork + `php7.4_module`; `mpm_prefork` only |
| **nginx** | Ubuntu `nginx 1.18.0`; stock 1 MiB `client_max_body_size` and a 64 MiB arm |
| **7.4 caveat** | effective 1,020-part multipart cap even with `max_multipart_body_parts=-1`; send the 974-part A1 reference and a 974-part sub-cap body; do not transplant the 8.4 A1 geometry |
| **Expected chain** | mod_php: A1 200 or parse-OOM, B1 0/5 (34-B cookie), A2 200; FPM: A1 OOM/`exit 70`, B1 33 MB declared refused by `post_max_size=8M`; no RCE, no OOB leak |
| **Acceptance (one line)** | both SAPIs report `PHP 7.4.3-4ubuntu2.29`, the 974-part A1/S1 result is recorded with the 1,020-part cap explicitly tested, B1 is ≤ 4,096 B (or transport-gated), and no proof file exists. |

### T06 — Amazon Linux 2023.12 8.4.26 B1 build tuning + A2/B2 (G15, G16)

| Field | Value |
|---|---|
| **Priority / batch** | P1 / Batch 1 |
| **Ports / network** | `33106` mod_php, `33107` FPM, `33108` 8.4.27 control; `p2s-gap1` |
| **Containers** | `p2sg1-amzn-modphp`, `p2sg1-amzn-fpm`, `p2sg1-amzn-8427` |
| **Base** | `amazonlinux:2023.12.20261021.0` |
| **Packages** | pin all three: `php8.4-modphp-8.4.26-1.amzn2023.0.1`, `php8.4-fpm-8.4.26-1.amzn2023.0.1`, `php8.4-common-8.4.26-1.amzn2023.0.1`; `httpd`; install as a matched set or `fpm` pulls `common 8.4.27` and upgrades modphp |
| **MPM fixture** | stock is `event` and stock `conf.d/php.conf` routes `.php` to FPM; for mod_php switch `00-mpm.conf` to `prefork` (declared fixture), keep stock `php.ini` |
| **B1 sweep** | fillers `100–140`, big-value parts `900–1000`, stock 5-child prefork and pinned single-child (`StartServers 1`, `MaxRequestWorkers 1`); decode every `Set-Cookie`; also run the 109618 flood (5,024,984 B, H=427,500) as a producer control |
| **A2/B2** | A2 `279,432 B` on mod_php (not FPM); B2 only if a B1 leak > 4,096 B appears, with Amazon-specific `S`/`zif_system`/`zval_ptr_dtor` derived locally |
| **Optional controls** | G14 onset bisect 860–870 in 1-part steps; G18 8.3.36/8.5.12 fixed A1 controls |
| **Expected chain** | B1 0/N across the sweep (normal 34-B cookie), A2 500/OOM 20,480 B, no B2, no RCE; 8.4.27 `a1_p880` 200 |
| **Acceptance (one line)** | every decoded B1 is ≤ 4,096 B across the full filler/part sweep and both pool shapes, A2 OOM is recorded on mod_php, and no proof file exists; if a leak appears, B2 is attempted with locally derived offsets. |

### T07 — lighttpd 1.4.79 + FPM 8.4.26 chain (U02)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 4 |
| **Ports / network** | `33165` lighttpd, `33166` 8.4.27 FPM control; `p2s-gap4` `10.240.4.0/24` |
| **Containers** | `p2sg4-lighttpd`, `p2sg4-php8426-fpm`, `p2sg4-php8427-fpm` |
| **Base** | `debian:13-slim`; `lighttpd 1.4.79-2`; official `php:8.4.26-fpm` `sha256:f5431b57...`, control `php:8.4.27-fpm` `sha256:e2d8e787...` |
| **lighttpd config** | `server.port=33165`, docroot `/var/www`, `fastcgi.server = ( ".php" => (( "host" => "p2sg4-php8426-fpm", "port" => 9000 )))`; no `server.max-request-size` (stock 0 = unlimited); stock `fastcgi` timeouts |
| **FPM pool** | stock `www.conf` (`pm=dynamic`, max_children=5); stock `post_max_size=8M`; second arm with `post_max_size=64M` (documented delta) |
| **Expected chain** | stock INI: A1 1,060,211 reaches PHP, OOM/`exit 70` → 502; B1 33,128,677 is forwarded with a declared length and refused by `post_max_size` before session code; no leak. Raised INI: B1 reaches the session path; record any leak but no RCE is expected (8.4.26 FPM has no controlled destructor). 8.4.27: A1 200, no exit-70. |
| **Acceptance (one line)** | lighttpd 1.4.79-2 is the front end, stock A1 produces one `exit 70`, stock B1 is `post_max_size`-gated (no >4,096-B cookie), the raised-INI arm records its leak status, and no proof file exists. |

### T08 — Roundcube 1.7.4 mod_php/FPM + 1.7.5/8.4.27 control (G44, U01)

| Field | Value |
|---|---|
| **Priority / batch** | **P0** / Batch 1 |
| **Ports / network** | `33109` 1.7.4 mod_php, `33110` 1.7.4 FPM, `33111` 1.7.5 FPM control; `p2s-gap1` |
| **Containers** | `p2sg1-rc174-modphp`, `p2sg1-rc174-fpm`, `p2sg1-rc175-fpm`, `p2sg1-db` |
| **App source** | `roundcubemail-1.7.4-complete.tar.gz` sha256 `2c6c878f0093f1bf7fb6086781d2dd9269d652c016b86939c157c5f1729139a2`; control 1.7.5 sha256 `93a66c94e3efff7db93187c1c9d7f35546647a3e1e7b9327cc87911564edf9d1` |
| **PHP** | `php:8.4.26-apache` (mod_php) and `php:8.4.26-fpm` + `nginx:alpine`; control `php:8.4.27-fpm`; `docker-php-ext-install intl`; SQLite DB (`db_dsnw=sqlite:////var/roundcube/db/roundcube.db`) |
| **Config arms** | Arm A: stock `session_storage=db` (default), pin `PHPSESSID`; Arm B: explicit `session_storage=php`, `session_name=PHPSESSID`, file sessions in `/tmp`; both with `/static.php` allowlisted |
| **Endpoint** | `/` login page, `/?_task=login`, `/static.php` |
| **Expected chain** | A1 OOM/`SIGABRT` (mod_php) or `exit 70` (FPM); B1 normal 5,400-B page, no pointer leak; A2/B2 normal; no auth bypass. Control 1.7.5 + 8.4.27 FPM: A1/A2/B1/B2 200, no OOM, no exit-70. |
| **Acceptance (one line)** | `RCMAIL_VERSION` reports 1.7.4 in both arms, a valid login works before and after the sequence, no decoded B1 > 4,096 B exists, and the 1.7.5/8.4.27 control returns 200 for all four stages. |

### T09 — Joomla 5.4.10 stock DB sessions + mod_php 8.4.26 (G39)

| Field | Value |
|---|---|
| **Priority / batch** | P1 / Batch 2 |
| **Ports / network** | `33123`; `33124` DB internal; `p2s-gap2` |
| **Containers** | `p2sg2-joomla`, `p2sg2-joomla-db` |
| **App source** | `Joomla_5-4-10-Stable-Full_Package.tar.gz` sha256 `aa72c425105cf775312f9610598b9f1c8866c7f3219a729b59d29a56ff7f76c4` |
| **PHP / DB** | `php:8.4.26-apache` + `docker-php-ext-install intl gd mysqli`; `mariadb:11.4` |
| **Install** | CLI installer `php installation/joomla.php install --db-type=mysqli ...`; set `$session_handler='database'`, stock `configuration.php` otherwise |
| **Endpoint** | `/index.php`, `/administrator/index.php` |
| **Expected chain** | A1 1,060,211 → child `SIGABRT`/500 (pre-app), B1 normal cookie/no leak, A2 OOM; no B2/RCE. The `#__session` table must be present and populated by a login. |
| **Acceptance (one line)** | `/administrator/index.php` shows Joomla 5.4.10, `#__session` exists, a login writes a DB session row, and the A1→B2 pass yields no >4,096-B B1 and no proof file. |

### T10 — MediaWiki 1.46.2 + mod_php 8.4.26 (G41)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 3 |
| **Ports / network** | `33142`; `33143` DB internal; `p2s-gap3` |
| **Containers** | `p2sg3-mw`, `p2sg3-mw-db` |
| **App source** | `mediawiki-1.46.2.tar.gz` sha256 `8f7f937f8bbc1acd4cef1c5362a95f248dcd242020f2588798eb2f73ac2e69ba` |
| **PHP / DB** | `php:8.4.26-apache` + `docker-php-ext-install intl mysqli`; `mariadb:11.4` (or SQLite if the installer supports it; MariaDB preferred for parity) |
| **Install** | `php maintenance/run.php install --dbtype=mysql ...`; stock `LocalSettings.php` |
| **Endpoint** | `/index.php/Main_Page`, `/api.php` |
| **Expected chain** | A1 OOM/500 (mod_php child abort), B1 no leak, A2 200/500; no RCE |
| **Acceptance (one line)** | `Special:Version` reports MediaWiki 1.46.2, the main page is 200, and the A1→B2 pass has no >4,096-B B1 and no proof file. |

### T11 — phpMyAdmin 5.2.3 + mod_php 8.4.26 (G46)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 3 |
| **Ports / network** | `33144`; `33145` DB internal; `33146` optional 8.4.27 control; `p2s-gap3` |
| **Containers** | `p2sg3-pma`, `p2sg3-pma-db`, optional `p2sg3-php8427` |
| **App source** | `phpMyAdmin-5.2.3-all-languages.tar.gz` sha256 `12ba1c425fa4071abbd4e7668c9ebdeac0b0755a467a6d6d5026122bb47c102b` |
| **PHP / DB** | `php:8.4.26-apache` + `docker-php-ext-install intl mysqli zip`; `mariadb:11.4` |
| **Config** | `config.inc.php`: cookie auth, `blowfish_secret` (32 B), host `p2sg3-pma-db`, no `AllowNoPassword`; `/setup/` left disabled as shipped |
| **Endpoint** | `/index.php` login page |
| **Expected chain** | A1 OOM/child abort, B1 no leak, A2 200; no auth bypass; no RCE |
| **Acceptance (one line)** | login page reports phpMyAdmin 5.2.3, a correct login reaches the DB, and the A1→B2 pass yields no >4,096-B B1 and no proof file. |

### T12 — Arch native php-apache 8.5.12 / php-legacy 8.3.36 (G12)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 4 |
| **Ports / network** | `33160` 8.5.12, `33161` 8.3.36; `p2s-gap4` `10.240.4.0/24` |
| **Containers** | `p2sg4-arch8512`, `p2sg4-arch8336` |
| **Base** | `archlinux:latest` (record digest) |
| **Build** | `pacman -Syu --noconfirm apache php-apache=8.5.12-1` (container A) and `apache php-legacy-apache=8.3.36-1` (container B); if the repo has moved, record the new pkgver and mark the task metadata-only rather than silently testing a different version; load each `libphp.so` in its own container |
| **Endpoint** | 22-byte `/index.php` |
| **Expected chain** | both packages are fixed: A1/A2 200, normal cookie, B1 ≤ 4,096 B, no OOM/exit-70, no RCE. This is a package-presence/version confirmation, not a vulnerable-chain test. |
| **Acceptance (one line)** | `php -v` reports 8.5.12 (php-apache) and 8.3.36 (php-legacy-apache), A1 returns 200 with no OOM, and B1 has no >4,096-B cookie. |

### T13 — WordPress 7.1.3 + mod_php 8.3.35 / 8.5.11 (G37)

| Field | Value |
|---|---|
| **Priority / batch** | P2 / Batch 4 |
| **Ports / network** | `33162` 8.3.35, `33163` 8.5.11; `33164` DB internal; `p2s-gap4` |
| **Containers** | `p2sg4-wp8335`, `p2sg4-wp8511`, `p2sg4-db` |
| **PHP** | `php:8.3.35-apache` `sha256:c59c8081...`, `php:8.5.11-apache` `sha256:47e6d884...`; `docker-php-ext-install intl gd mysqli` |
| **App source** | official WordPress 7.1.3 zip sha256 `eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227`; install with `wp-cli` or manual `wp-config.php` against `mariadb:11.4` |
| **Endpoint** | `/index.php` front controller and `/wp-content/index.php` 28-B core silence file |
| **Expected chain** | 8.3.35: A1 parse-OOM (0/8 family), B1 normal 34-B cookie, no leak. 8.5.11: A1 500/OOM, B1 leak-only (53 pointers, no `zval_ptr_dtor`, no 87-bucket), no B2/RCE. |
| **Acceptance (one line)** | both sites report WordPress 7.1.3 with an installed DB, `/index.php` is 200, and neither build yields a proof file; 8.5.11's B1 leak is recorded but not counted as RCE. |

---

## 5. Batch schedule and resource allocation

All batches are independent: different bridge networks, different host port ranges, different
container prefixes. They can run concurrently. Within a batch, start the P0/highest-priority
task first, but no task waits on another.

**If capacity is limited, run in this order:** T08 (P0) → T01 → T04 → T06 → T03 → T09 (P1) →
T02 → T05 → T07 → T10 → T11 → T12 → T13 (P2). This preserves the only P0 cell and the
patch-boundary / distro-FPM / Amazon-B1 questions before app and metadata cells.

### Batch 1 — `p2s-gap1` `10.240.1.0/24`, ports `33100–33119`, prefix `p2sg1-`

| Order | Task | Gap(s) | Ports | Containers |
|---:|---|---|---|---|
| 1 | T08 | G44, U01 | 33109–33111 | `p2sg1-rc174-modphp`, `p2sg1-rc174-fpm`, `p2sg1-rc175-fpm`, `p2sg1-db` |
| 2 | T01 | G23 | 33100–33101 | `p2sg1-php849`, `p2sg1-php848` |
| 3 | T04 | G03, U03 | 33102–33105 | `p2sg1-deb13-ngx-stock`, `p2sg1-deb13-ngx-64m`, `p2sg1-deb13-apache-fcgi`, `p2sg1-deb13-ngx-8427` |
| 4 | T06 | G15, G16 | 33106–33108 | `p2sg1-amzn-modphp`, `p2sg1-amzn-fpm`, `p2sg1-amzn-8427` |

### Batch 2 — `p2s-gap2` `10.240.2.0/24`, ports `33120–33139`, prefix `p2sg2-`

| Order | Task | Gap(s) | Ports | Containers |
|---:|---|---|---|---|
| 1 | T03 | G50 | 33120 | `p2sg2-ols8511` |
| 2 | T09 | G39 | 33123–33124 | `p2sg2-joomla`, `p2sg2-joomla-db` |
| 3 | T05 | G04, G05 | 33121–33122 | `p2sg2-u2004-modphp`, `p2sg2-u2004-fpm` |

### Batch 3 — `p2s-gap3` `10.240.3.0/24`, ports `33140–33159`, prefix `p2sg3-`

| Order | Task | Gap(s) | Ports | Containers |
|---:|---|---|---|---|
| 1 | T02 | G24 | 33140 | `p2sg3-php840` |
| 2 | T10 | G41 | 33142–33143 | `p2sg3-mw`, `p2sg3-mw-db` |
| 3 | T11 | G46 | 33144–33146 | `p2sg3-pma`, `p2sg3-pma-db`, optional `p2sg3-php8427` |

### Batch 4 — `p2s-gap4` `10.240.4.0/24`, ports `33160–33179`, prefix `p2sg4-`

| Order | Task | Gap(s) | Ports | Containers |
|---:|---|---|---|---|
| 1 | T12 | G12 | 33160–33161 | `p2sg4-arch8512`, `p2sg4-arch8336` |
| 2 | T13 | G37 | 33162–33164 | `p2sg4-wp8335`, `p2sg4-wp8511`, `p2sg4-db` |
| 3 | T07 | U02 | 33165–33166 | `p2sg4-lighttpd`, `p2sg4-php8426-fpm`, `p2sg4-php8427-fpm` |

### Preflight (once per batch)

```bash
export DOCKER_HOST=unix:///run/user/1000/docker.sock
ss -ltn | grep -E ':(331[0-9]{2}|33[12][0-9]{2})\b' && exit 1
docker network inspect p2s-gapN >/dev/null 2>&1 || \
  docker network create --subnet=10.240.N.0/24 p2s-gapN
for c in $(docker ps -a --format '{{.Names}}' | grep '^p2sgN-'); do echo "stale: $c"; done
```

No task may restart a host service. Container restarts are allowed only inside a task's own
compose/script and must be recorded as a fresh generation.

---

## 6. Execution protocol

1. **Create the run directory** `R/<task>_<UTC>/` and write `plan.md` (copy of the task block),
   `meta.json` (host, Docker digest, start time, ASLR, `ss` output).
2. **Freeze versions before testing**: package URLs and sha256, image digests, source tarball
   hashes, `php -v`, `php -i`, `dpkg -l`/`rpm -qa`, `httpd -v`, `nginx -v`, `lighttpd -v`,
   `lsphp -i`. Store under `evidence/`.
3. **Diff every config against stock** into `conf/<file>.diff`. Any non-stock delta must be
   named `LAB DELTA` in the report and must not touch `memory_limit`, `post_max_size`,
   `upload_max_filesize`, `session.upload_progress.*`, or the MPM unless the task says so.
4. **Run the stage matrix** in this order: health → A1 → B1 (decode cookie) → A2 → B2
   (only if B1 > 4,096 B). Record status, body length, decoded cookie length, child PID
   (if logged), and exit code/signal for every request.
5. **Negative controls**: one 22-byte request before and after the matrix; one fixed-build
   control if the task specifies one. A run with a broken control is invalid.
6. **Proof handling**: only `B2` may write `/out/p1_<marker>`; read it from the host and verify
   `uid=33(www-data)` and the marker. Never count a 500, OOM, `exit 70`, `exit 255` or SIGSEGV
   as RCE.
7. **Report**: `report.md` must state the exact build, SAPI, endpoint, body hashes, the
   per-stage table, the B1 decode method, the control result, and the verdict. Link every
   claim to a file under `out/`, `logs/`, or `evidence/`.
8. **Cleanup**: stop/remove only the task's containers and network; leave other workers alone.

### Required report skeleton

```markdown
# <task> — <gap IDs>
- Build / package / source (exact version, hash)
- SAPI / web server / MPM / pool
- Endpoint and body hashes
- Stock INI and every lab delta
- Stage table: A1, B1, A2, B2 (status, bytes, cookie bytes, child exit)
- Controls (plain endpoint, fixed build)
- Verdict: RCE / leak-only / crash-only / no primitive
- Artifacts index
```

---

## 7. Acceptance and deduplication rules

- A task is **done** only when its one-line acceptance check is met and `report.md` exists.
- A gap is **closed** only by a report that names the exact build and shows the stage table;
  a source-only inference does not close a runtime gap.
- No task may reuse another task's offsets. Debian-family builds use `S=main+0xF7398` and
  `fillers=116`; upstream builds use `S=main+0xF8398` and `fillers=115`; every new build must
  re-derive with `nm`/`readelf` and validate with a wrong-offset control.
- No task duplicates the active workers listed in §1.2. If an active worker publishes a report
  covering a task's cell before the task starts, the task is cancelled and the gap is marked
  covered by that report.
- Batch collisions are checked before start: no shared host port, no shared container name,
  no shared bridge subnet.

---

## 8. Risks and expected outcomes

| Risk | Mitigation / expected result |
|---|---|
| 8.4.9 source build fails on bookworm `apache2-dev` ABI | The build uses the image's own Apache 2.4.62 and `apxs2`; if the module fails to load, rebuild on `debian:12-slim` with distro `apache2` + `apache2-dev` and record the stack as a declared delta. The patch-boundary question survives either way. |
| 8.4.0 does not compile with the 8.4.8 configure line | Drop only options that `configure` rejects; record the exact delta and keep the engine flags (`--enable-session`, `--with-apxs2`) unchanged. |
| OLS 8.5.11 source build does not reproduce the vendor heap boundary | Expected: the LSAPI heap boundary is build-specific. The acceptance is lifecycle (500/exit 255/no signal), not an exact H value; sweep H and record the boundary. |
| Amazon 8.4.26 packages disappear or upgrade | Pin the exact NEVRA and install `modphp`+`fpm`+`common` as a set; if the repo drops 8.4.26, use the local RPMs already verified in `R/distro_meta...` or mark the task blocked with the package error. |
| Debian 8.4.24 `.deb` removed from the pool | The pool URLs are verified 200 today; archive a local copy under `R/<task>/dl/` before building. |
| Ubuntu 20.04 archive moves to ESM | Use the cached `.deb` set or `old-releases.ubuntu.com`; record the mirror in `evidence/`. |
| App installers require network | Only official package/tarball downloads; no third-party target traffic. Cache all archives under `dl/` and hash them. |
| B1 leak appears on a build expected to be negative | Do not declare RCE. Derive offsets, attempt A2/B2, and record exactly which stage fired; a leak alone is not a chain. |

**Expected overall outcome:** most assigned tasks are expected to be negatives (no RCE) that
close runtime coverage: T01/T02 settle the 8.4.9/8.4.0 boundary; T03 closes LSAPI 8.5.11 as
500/exit-255; T04/T05/T07 close Debian/Ubuntu/lighttpd FPM transport gaps; T06 closes the
Amazon B1 sweep; T08/T09/T10/T11 close app/SAPI cells; T12 confirms fixed Arch packages;
T13 records 8.3.35/8.5.11 WordPress mod_php behavior. A positive result is possible only if a
new B1 leak > 4,096 B appears and a per-build B2 proof is written; nothing in this plan assumes
one.

**Coverage-composition note.** Four covered rows are closed by composition rather than a single
exact-cell rerun, and are flagged here so they are not over-read: G27/G28 (direct warm chain on
8.4.10/8.4.20 plus measured nginx proxy invariance on 8.4.24/26/27), G30 (a config-injection
FastCGI chain, not the A1→B2 body chain), G36 (engine-level FPM negatives plus a WP-specific
nginx+FPM OOM run, not a WP A1→B2 rerun), and G10 (the prior 7.4/8.0 B1 negatives are
invalidated rather than replaced by a new valid negative). If a future audit requires the exact
combined cells, they are cheap follow-ups, but they do not change the engine verdict and are not
scheduled here to avoid duplicating active work.

---

## 9. File manifest

- `plan.md` — this document.
- `plan.json` — machine-readable gap dispositions, task specs, batches, ports and acceptance
  checks. The JSON is authoritative for automation; this Markdown is authoritative for the
  rationale and evidence citations.
