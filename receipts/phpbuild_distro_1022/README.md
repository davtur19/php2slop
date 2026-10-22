# How PHP is built in real deployments — measured build inventory

Receipt: `/tmp/opencode/phpbuild_distro_20261022T013023Z/`
Date: 2026-10-22
Scope: package binaries downloaded from vendor repositories and measured with `file`, `readelf -h/-lW/-d/-SW`, `nm`/`nm -D`; shipped `php.ini` and FPM pool files inspected.

## Verdict

1. **Every distro PHP build measured is PIE:** Debian 11/12/13, Ubuntu 22.04/24.04, Fedora 44, Rocky 9 (8.0/8.2/8.3), Remi el9, Sury Debian 13, Alpine 3.19/3.22 (musl), Arch, openSUSE Tumbleweed, Amazon Linux 2 (5.4.16) and 2023 (8.5.10). ELF type `DYN`, `FLAGS_1: PIE`, first `LOAD` `p_vaddr 0x0`; stripped, with NX and canary; most full RELRO and FORTIFY.
2. **The official Docker `php:8.4-fpm` image is also PIE** (source build with Debian's default PIE toolchain): partial RELRO, canary, no FORTIFY, no `.symtab`, `session.save_path` empty.
3. **Both commercial panels measured ship non-PIE `ET_EXEC` at `0x400000`:** cPanel EA4 `cpanel-php84` 8.4.26 and 8.4.27 (not stripped; `.symtab` exposes `ps_serializers`, `zif_passthru`, `zif_system`) and Plesk `plesk-php84-fpm` 8.4.27 plus `plesk-php83-fpm` 8.3.36 (stripped).
4. **Consequence for this project:** the md5-locked G2/G6 profiles (non-PIE `ET_EXEC` at `0x400000`) apply **as-is only to panel builds and custom `-no-pie` source builds**; they do not apply to any measured distro package or to the official Docker image. On PIE builds the chain additionally needs a **binary-base leak**, which no receipt demonstrates.
5. **Defaults are uniform and favourable:** `session.save_handler=files`, `serialize_handler=php`, `upload_progress.enabled=On`, `use_strict_mode=0` on every build inspected. The session directory differs, and the chain still needs an application that writes native `sess_*` files into a web-served directory (stock WordPress/Drupal/Joomla/MediaWiki do not; Moodle writes outside the web root).

## Layout

| path | content |
|---|---|
| `REPORT.md` | full report: method, distro matrix, panel builds, source builds, save-path/defaults per distro, chain applicability, unmeasured targets |
| `build_matrix.tsv` | per-package ELF/RELRO/canary/FORTIFY matrix (the report's §2 table) |
| `deb_matrix.tsv` | Debian/Ubuntu package versions and download provenance |
| `rpm_apk_matrix.tsv` | RPM/Alpine/Arch/openSUSE/Amazon rows |
| `measure.sh` | the `file`/`readelf`/`nm` measurement script used on every extracted binary |

## Limits

Primary evidence is the shipped binary, not build-system flags. Not measured: DirectAdmin, Windows PHP, static-php-cli/static builds, RHEL/CentOS ≤7, PECL-only or bespoke toolchains. DirectAdmin's `CustomBuild` compiles on the host; its ELF type is unknown here (the report labels it inference, not measurement). Extracted package trees are environment and are not included; the matrices and the report are the evidence.
