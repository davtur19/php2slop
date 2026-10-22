# How PHP is built in real deployments — measured build inventory and CVE-2026-109618/109619 chain applicability

Date: 2026-10-22
Scratch root: `/tmp/opencode/phpbuild_distro_20261022T013023Z/`
Evidence: package binaries downloaded from vendor repos and measured with `file`, `readelf -h/-lW/-d/-SW`, `nm`/`nm -D`; shipped `php.ini`/FPM pool files inspected. No repo files modified. All extracted binaries are in `extract/`.

## TL;DR

1. **Every distro PHP build measured is PIE**: Debian 11/12/13, Ubuntu 22.04/24.04, Fedora 44, Rocky 9 (8.0/8.2/8.3), Remi el9, Sury Debian 13, Alpine 3.19/3.22 (musl), Arch, openSUSE Tumbleweed, Amazon Linux 2 (5.4.16) and 2023 (8.5.10). ELF type `DYN`, `FLAGS_1: PIE`, first `LOAD` p_vaddr `0x0`. They are also stripped, with NX and canary; most have full RELRO and FORTIFY.
2. **The official Docker `php:8.4-fpm` image is also PIE** (source build with Debian's default PIE toolchain), partial RELRO, canary, no FORTIFY, no `.symtab`, `session.save_path` empty → `/tmp`.
3. **Both commercial panels measured ship non-PIE `ET_EXEC` at `0x400000`**: cPanel EA4 `cpanel-php84` 8.4.26 and 8.4.27 (not stripped; `.symtab` contains `ps_serializers`, `zif_passthru`, `zif_system`) and Plesk `plesk-php84-fpm` 8.4.27 plus `plesk-php83-fpm` 8.3.36 (stripped).
4. Consequently, the current md5-locked G2/G6 profiles (ET_EXEC non-PIE at `0x400000`) **do not apply to any measured distro package or to the official Docker image**. They apply as-is only to panel builds and to custom `-no-pie` source builds. On PIE builds the chain additionally needs a **binary-base leak**, which no receipt demonstrates; current receipts only demonstrate heap/`K_dest` leaks and, in `realchain_20261022`, a gdb calibration for `P`/`B0`.
5. Defaults are otherwise uniform and favourable to the vulnerability: `session.save_handler=files`, `session.serialize_handler=php`, `session.upload_progress.enabled=On`, `session.use_strict_mode=0` on every build inspected. The session directory differs (see §5) and the chain still needs an application that writes native `sess_*` files into a web-served directory (stock WordPress/Drupal/Joomla/MediaWiki do not; Moodle writes outside the web root).

## 1. Method and limits

- Primary evidence is the shipped binary, not build-system flags. Version, ELF type, first `LOAD` vaddr, `GNU_STACK`, `GNU_RELRO`, `BIND_NOW`/`FLAGS_1`, `.symtab` presence, `__stack_chk_fail`, `*_chk` symbols and PT_INTERP were read from each file.
- Package sources: `deb.debian.org`, `archive.ubuntu.com`, `archive.debian.org`, `dl.fedoraproject.org`, `dl.rockylinux.org`, `dl-cdn.alpinelinux.org`, `archive.archlinux.org`, `download.opensuse.org`, `rpms.remirepo.net`, `packages.sury.org`, `httpupdate.cpanel.net`, `autoinstall.plesk.com`, Docker Hub. Details and commands are in `logs/`, matrix in `logs/build_matrix.tsv`.
- Host is Debian 13 (gcc 14.2.0, `--enable-default-pie`; `dpkg-buildflags` adds `-fstack-protector-strong -fstack-clash-protection -fcf-protection` and `-Wl,-z,relro`), so host-side default-PIE is expected; this is stated only as context, the binaries themselves were measured.
- Not measured: DirectAdmin builds, Windows PHP, static-php-cli/static builds, RHEL/CentOS ≤7, PHP builds from PECL-only or bespoke toolchains. These are listed in §8.

## 2. Distro build matrix (measured)

All rows: NX (`GNU_STACK RW`), no `.symtab` (stripped). "Full RELRO" = `GNU_RELRO` + `BIND_NOW`; "partial" = `GNU_RELRO` without `BIND_NOW`.

| Package | PHP | SAPI | ELF | base | RELRO | canary | FORTIFY |
|---|---|---|---|---|---|---|---|
| Debian 13 `php8.4-fpm` / `php8.4-cli` | 8.4.27-1~deb13u1 | fpm-fcgi / cli | DYN PIE | 0x0 | full | yes | yes |
| Debian 12 `php8.2-fpm` / `php8.2-cli` | 8.2.32-1~deb12u1 | fpm-fcgi / cli | DYN PIE | 0x0 | full | yes | yes |
| Debian 11 `php7.4-fpm` | 7.4.33-1+deb11u5 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Ubuntu 22.04 `php8.1-fpm` / `php8.1-cli` | 8.1.2-1ubuntu2.28 | fpm-fcgi / cli | DYN PIE | 0x0 | full | yes | yes |
| Ubuntu 24.04 `php8.3-fpm` / `php8.3-cli` | 8.3.6-0ubuntu0.24.04.13 | fpm-fcgi / cli | DYN PIE | 0x0 | full | yes | yes |
| Fedora 44 `php-fpm` | 8.5.4-1.fc44 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Rocky 9 `php-fpm` base module | 8.0.30-8.el9_8.1 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Rocky 9 `php-fpm` 8.2 module | 8.2.35-1.module+el9.8.0+40395 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Rocky 9 `php-fpm` 8.3 module | 8.3.36-1.module+el9.8.0+40396 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Remi el9 `php-fpm` 8.4 module | 8.4.27-1.module_php.8.4.el9.remi | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Remi el9 `php-fpm` 8.2 module | 8.2.35-1.module_php.8.2.el9.remi | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Sury Debian 13 `php8.4-fpm` | 8.4.27-1+0~20261021.57+debian13 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Alpine 3.19 `php82-fpm` / `php83-fpm` | 8.2.26-r0 / 8.3.14-r0 | fpm-fcgi (musl) | DYN PIE | 0x0 | full | yes | no |
| Alpine 3.22 `php82/83/84-fpm` | 8.2.33-r0 / 8.3.29-r0 / 8.4.16-r0 | fpm-fcgi (musl) | DYN PIE | 0x0 | full | yes | no |
| Arch `php-fpm` | 8.5.11-1 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| openSUSE Tumbleweed `php8-fpm` | 8.5.11-2.1 | fpm-fcgi | DYN PIE | 0x0 | partial | yes | yes |
| Amazon Linux 2023 `php-fpm` | 8.5.10 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| Amazon Linux 2 `php-fpm` (base repo) | 5.4.16-46.amzn2.0.7 | fpm-fcgi | DYN PIE | 0x0 | full | yes | yes |
| official Docker `php:8.4-fpm` | 8.4.27 | fpm-fcgi | DYN PIE | 0x0 | partial | yes | no |

Notes:
- The only partial-RELRO rows are the source-built Docker image, openSUSE Tumbleweed and the two panels. Partial RELRO does not change the exploit's address problem.
- `zif_passthru` is not exported in the dynsym of the Debian 8.4 fpm build (12 other `zif_*` are); symbols are not a usable runtime oracle on stripped distro builds.
- Supported-branch defaults: Debian 13 → 8.4, Debian 12 → 8.2, Ubuntu 24.04 → 8.3, Ubuntu 22.04 → 8.1, Fedora 44 → 8.5, RHEL/Rocky 9 default module → 8.0 (8.2/8.3 module streams available), Alpine 3.22 → 8.2/8.3/8.4 parallel, Arch and openSUSE TW → 8.5, Amazon Linux 2023 → 8.5 (AL2 base is 5.4; 7.4/8.0 via extras).

## 3. Panel builds (the non-PIE population)

| Panel | Package | PHP | ELF | base | RELRO | stripped | symbols of interest |
|---|---|---|---|---|---|---|---|
| cPanel EA4 | `cpanel-php84-8.4.26` | 8.4.26 | **EXEC** | **0x400000** | partial | **no** | `ps_serializers` 0x1cc6040, `zif_passthru` 0x9b4cf0, `zif_system` 0x9b4ce0 |
| cPanel EA4 | `cpanel-php84-8.4.27` | 8.4.27 | **EXEC** | **0x400000** | partial | **no** | same package layout |
| Plesk | `plesk-php84-fpm-8.4.27` | 8.4.27 | **EXEC** | **0x400000** | partial | yes | none |
| Plesk | `plesk-php83-fpm-8.3.36` | 8.3.36 | **EXEC** | **0x400000** | partial | yes | none |
| DirectAdmin | custombuild | unknown | unknown | unknown | unknown | unknown | unknown |

- cPanel installs `/usr/local/cpanel/3rdparty/php/84/sbin/php-fpm` (EA4 root is `/opt/cpanel/ea-php84/root/...`); Plesk installs `/opt/plesk/php/8.4/sbin/php-fpm`.
- Both panels build **without PIE**, despite the el9 toolchain defaulting to PIE. That is a deliberate or spec-level `-no-pie`; the effect is what matters: the binary base is a compile-time constant.
- cPanel's build is **not stripped**, so an attacker who knows the package version can read `ps_serializers` and `zif_passthru` offsets directly. Plesk's is stripped; offsets must be derived per build.
- MD5s of measured panel binaries: cPanel 8.4.26 `f8b9e5bb2d589387e7295a161d243486`; cPanel 8.4.27 `cc4394671da992f2e20191ef0e1e039d`; Plesk 8.4.27 `f86bac1ad5beeb2f7f066883c1b1b198`; Plesk 8.3.36 `f8a39ed620d7f592d693c48ef05432f0`. None match the lab profile md5s, so each still needs its own offset profile.
- DirectAdmin's CustomBuild compiles PHP on the host from source; I could not retrieve its build script or a prebuilt binary in this session (404s on the paths tried). Its ELF type is **unknown**; on el8/el9 with default gcc it would be PIE, but this is inference, not measurement.

## 4. Source builds and the official container image

`docker.io/library/php:8.4-fpm` (digest `sha256:cc7cdfe4da7d46f6e69ac653e3d3396590bf51d6d6731854d01449d0b32b704c`) contains `/usr/local/sbin/php-fpm`, PHP 8.4.27, built by docker-library/php:

- `DYN (Position-Independent Executable file)`, `FLAGS_1: PIE`, first `LOAD` 0x0 → PIE.
- Partial RELRO (no `BIND_NOW`), canary present, no FORTIFY, no `.symtab`, `session.save_path` empty.
- This is the closest measured proxy for "generic `./configure && make`" deployments on Debian/Ubuntu base images: PIE by default, because the toolchain defaults to PIE and PHP's configure does not disable it.

## 5. Session defaults that matter to the chain

Every packaged `php.ini` inspected has `session.save_handler = files`, `session.serialize_handler = php`, `session.upload_progress.enabled` commented (= On), `session.upload_progress.cleanup` commented (= On), and `session.use_strict_mode = 0` (explicit in the RHEL/Fedora/Arch/openSUSE inis). `session.upload_progress` knobs are `PHP_INI_PERDIR`, so per-directory `.user.ini` cannot be used to disable them in a hardened deployment, but they are On by default.

`session.save_path` by target:

| Target | Effective default | Evidence |
|---|---|---|
| Debian 11/12/13, Ubuntu 22.04/24.04 | **empty → `/tmp`** | `php8.x-fpm` postinst installs `/etc/php/8.x/fpm/php.ini` from `php.ini-production` via `ucf`; the only `save_path` line is commented (`;session.save_path = "/var/lib/php/sessions"`). No conf.d override. |
| Fedora 44, Rocky/RHEL 9, Remi el9 | **`/var/lib/php/session`** | `php_value[session.save_path] = /var/lib/php/session` in `/etc/php-fpm.d/www.conf` line 436; directory mode `0750`. |
| Alpine 3.19/3.22 | **empty → `/tmp`** | no `php.ini` shipped in the fpm/base packages inspected; PHP built-in defaults. |
| Arch | **empty → `/tmp`** | shipped `php.ini` has `;session.save_path = "/tmp"` commented. |
| openSUSE Tumbleweed | **empty → `/tmp`** | shipped `php.ini` has `;session.save_path = "/tmp"` commented. |
| Amazon Linux 2/2023 | **empty → `/tmp`** | measured on the installed package: `php -r 'ini_get("session.save_path")'` returned empty. |
| official Docker `php:8.4-fpm` | **empty → `/tmp`** | measured in the image. |
| cPanel EA4 | **`/tmp` per shipped `php.ini`** | `;session.save_path = "/tmp"` only; no `php_value` in the shipped package. Per-vhost cPanel overrides not verified. |
| Plesk | **unknown** | `php.ini` is not shipped in the RPM (generated at install by the panel); not measured. |

Consequence: even the "files" handler writes `sess_*` with mode `0600` in `/tmp` (or a `0750` root-owned directory on RHEL), neither of which is web-servable by default. The chain's file primitive needs the application or a plugin to move `save_path` into a served directory — the same precondition as the `realchain_20261022` receipt, not a property of the PHP build.

## 6. Prevalence

- **PHP the language**: W3Techs, 22 Oct 2026 — PHP is used by **69.3% of all websites**; among PHP sites, Version 8 = 65.3%, Version 7 = 26.9%, Version 5 = 7.7%, Version 4 = 0.1%. The 26.9% PHP 7 share matters because the advisory has backports for 7.4/8.0/8.1 but distro support varies.
- **Official container**: Docker Hub `library/php` reports **1,380,957,297 pulls** and 7,875 stars (API, 22 Oct 2026), 16,064 tags. This is the single most-used non-distro PHP distribution channel and it is PIE.
- **Panels (W3Techs, detection-based, 22 Oct 2026)**: 91.7% of websites show no monitored panel; hPanel 4.5% of all websites (54.2% of panel-using), **Plesk 3.4% (41.4%)**, **cPanel 0.2% (1.8%)**, RunCloud 0.1%, GridPane 0.1%. These are lower bounds and conflict with vendor figures — cPanel's own marketing claims ~900,000 servers / ~85M domains (secondary citation, not directly verified), and Plesk states "more than 380,000 servers, 11M websites" (plesk.com). W3Techs' cPanel detection is evidently weak; do not read 0.2% as cPanel's real server share.
- **Distro package install base**: no public per-package telemetry. Debian/Ubuntu/RHEL-family FPM packages are the default way PHP is installed on VPS/dedicated hosts, but the population is unknown; this is an honest gap.
- Net: the **PIE** population (distro packages, Docker images, Remi/Sury) is the large majority by every measurable channel, while the **non-PIE** population is concentrated in panel-managed shared hosting.

## 7. Exploit-chain applicability

The chain needs three independent things: (a) a vulnerable PHP build, (b) knowledge of the binary address of `ps_serializers[N].decode` (and of `zif_passthru` for G6), (c) a heap-layout leak (`X1`, `P`, `B0`) plus an application that writes a native session file into a served directory and reuses the same worker.

| Build class | PIE | Binary base | Binary-base leak needed | Heap leak still needed | Default handler | Chain status |
|---|---|---|---|---|---|---|
| Debian/Ubuntu FPM/CLI 8.1–8.4 | yes | random | **yes — not demonstrated** | yes | files (`/tmp`) | **not applicable as demonstrated** |
| Fedora / Rocky / Alma / Remi | yes | random | **yes — not demonstrated** | yes | files (`/var/lib/php/session`) | **not applicable as demonstrated** |
| Alpine 3.19/3.22 | yes | random | **yes** | yes | files (`/tmp`) | **not applicable as demonstrated** |
| Arch / openSUSE TW | yes | random | **yes** | yes | files (`/tmp`) | **not applicable as demonstrated** |
| Amazon Linux 2/2023 | yes | random | **yes** | yes | files (`/tmp`) | **not applicable as demonstrated** |
| official Docker `php:8.4-fpm` | yes | random | **yes** | yes | files (`/tmp`) | **not applicable as demonstrated** |
| cPanel EA4 8.4.x | **no** | **0x400000** | no | yes | files (`/tmp`/panel override unknown) | **candidate**: binary half solved; needs per-build offsets (symbols available), heap leak, app session write; no end-to-end test on this exact package |
| Plesk 8.3/8.4 | **no** | **0x400000** | no | yes | files (path unknown) | **candidate**: same, but stripped → offsets must be reverse-engineered |
| DirectAdmin | unknown | unknown | unknown | yes | files (likely `/tmp`) | **unknown** |
| custom `-no-pie` source build (lab) | no | 0x400000 | no | yes | files | **demonstrated** (8.5.10, with gdb-calibrated `P`/`B0`) |

Why PIE blocks the current chain: the G2 write target is `ps_serializers[N].decode` in `.data`. In a PIE binary the load base is randomized per process, so the profile's absolute offset is useless without a leak of a pointer into the binary image. The current leak work does not provide one:

- `receipts/realchain_20261022/` leaks `K_dest` (heap) from a served session file and uses it for `P`/`B0`; `P` and `B0` were still calibrated with gdb before the final request.
- `receipts/mw_aslrleak_1022/` found **no** in-band heap pointer on MediaWiki/Wikibase; negative result.
- `docs/runtime_addresses.md` records that every non-EXEC build is PIE; the `plain`/`realapps` PIE builds exist precisely to test this boundary, and only the `_np` non-PIE builds carry the G2/G6 profiles.
- `USAGE.md` states the G2 precondition explicitly: "ET_EXEC non PIE at image base 0x400000, or a binary base leak."

So the practical statement is: **the current chain is a panel-build/custom-build chain, not a distro-package chain.** A cPanel or Plesk host is the realistic non-PIE target; a stock Debian/Ubuntu/RHEL/Alpine/Docker host needs a new binary-base leak primitive before the same chain can run.

Secondary build properties that matter after a base leak:
- cPanel's partial RELRO keeps the GOT writable; this is not needed for the current `.data` write but widens options.
- cPanel's `.symtab` makes offset discovery trivial for a given package version; Plesk's stripped binary does not.
- None of the measured distro binaries match any profile md5, so even a non-PIE distro binary (none found) would need its own profile.

## 8. Unknowns and what would change the conclusion

1. **DirectAdmin** CustomBuild binaries/flags: not retrieved. Its PHP is compiled locally; on el8/el9 default gcc this should be PIE, but this is inference. Measuring one real DirectAdmin host or its build script would settle it.
2. **Plesk's effective `session.save_path`** (php.ini is generated at install) and **cPanel's per-vhost `save_path` overrides** (possible `/var/cpanel/php/sessions/...`): unverified. If either redirects sessions to a served directory, the app-side precondition weakens.
3. **Panel PHP version distribution**: measured 8.4 and 8.3 builds only. The cPanel 11.130 el9 repository I could list contains only `cpanel-php84` packages (8.4.11–8.4.27); older EA4 branches, if used in the field, were not measured. Plesk ships many branches; the per-version population is unknown.
4. **RHEL/CentOS ≤7 and PHP ≤5.6 distro builds**: not measured; they predate default PIE and could be non-PIE. Amazon Linux 2's 5.4.16 is PIE, which suggests modern rebuilds even of old versions are PIE, but this is one data point.
5. **Static/self-contained PHP builds** (static-php-cli, FrankenPHP, etc.): not measured. Static-PIE would still be PIE; non-PIE static is possible.
6. **Windows PHP**: out of scope; the chain's ELF offsets do not apply.
7. **Remi/Sury per-release differences**: only one release each measured; both PIE. The advisory explicitly warns Remi users, and Remi's el9 builds are PIE, so the warning is about patch availability, not about a non-PIE advantage.
8. **Distro backport contents**: the versions measured are patched (8.4.27, 8.3.36, 8.2.35 are the fixed releases). Whether each distro's build actually contains the fix was not verified beyond the version string; the advisory says vendors received patches in advance.

## 9. Evidence map

- `logs/build_matrix.tsv` — consolidated measured matrix (this report's tables).
- `logs/deb_matrix.tsv` — Debian/Ubuntu measurements.
- `logs/rpm_apk_matrix.tsv` — Fedora/Rocky/openSUSE/Alpine measurements.
- `extract/` — extracted binaries, one directory per package.
- `debs/`, `rpms/`, `apks/` — downloaded packages.
- `logs/w3techs_php.html`, `logs/w3techs_webpanel.html` — prevalence snapshots (22 Oct 2026).
- `/home/davide/ailocal/php/phpshell/USAGE.md`, `docs/runtime_addresses.md`, `receipts/realchain_20261022/`, `receipts/mw_aslrleak_1022/`, `receipts/real_target_preconditions_1022/` — chain preconditions and leak receipts used in §7.

## 10. Reproduce

```bash
# one binary
readelf -hW BIN | grep Type
readelf -lW BIN | awk '$1=="LOAD"{print $3; exit}'
readelf -dW BIN | grep -E 'BIND_NOW|FLAGS'
readelf -SW BIN | grep -c '\.symtab'
nm -D BIN | grep -c __stack_chk_fail

# Debian/Ubuntu session default
dpkg-deb -e php8.4-fpm_*.deb /tmp/ctl && grep -n 'php.ini' /tmp/ctl/postinst
grep -n 'save_path' /usr/lib/php/8.4/php.ini-production

# RHEL family
grep -n 'session.save_path' /etc/php-fpm.d/www.conf

# Docker official image
docker run --rm php:8.4-fpm php -r 'echo ini_get("session.save_path"),"\n";'
```
