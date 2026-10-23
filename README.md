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

**Bottom line:** only the mod_php 8.4.10–8.4.26 chain and the Debian 8.4.24
package build have lab-demonstrated RCE, both with `output_buffering=4096` and
exact per-build offsets. Stock nginx, stock FPM, pre-8.4, and "all versions"
claims are **not** met. Lanes marked 🧪 are still running. Nothing here is a
stock or universal exploit.

Legend: ✅ RCE demonstrated in lab · ⚠️ leak/primitive only · ❌ no RCE ·
🚫 fixed · 🧪 running · 🛠 config-induced.

| Target / SAPI | PHP | Status | Conditions / blocker |
|---|---|---|---|
| mod_php | 8.4.10–8.4.26 | ✅ lab RCE | cold chain; `output_buffering=4096`; 22-byte endpoint; exact per-build offsets; not stock-universal |
| mod_php | 8.4.24 Debian 13 | ✅ 4/4 blind RCE | Debian package default; `output_buffering=4096`; warm 25/25 serial |
| mod_php | 8.4.27 | 🚫 fixed | control clean |
| mod_php | 8.4.0–8.4.9 | 🧪 running | early-8.4 stale-`PS(id)` gap |
| mod_php | 8.0–8.3 | ❌ no RCE | 109619 negative; 109618 no controlled destructor |
| mod_php | 8.5.0/5/11 | ⚠️ leak only | sparse 819,208 B; no libphp code pointer; 8.5.12 fixed |
| mod_php | 5.6–7.4 | 🧪 running | pre-8 mod_php matrix |
| FPM | 8.0–8.3 | ❌ no RCE | 109619 negative; 109618 primitive only; 8.2.35/8.3.36 fixed |
| FPM | 8.4.26 | ❌ no RCE | 109618 primitive; no controlled destructor; 8.4.27 fixed |
| FPM | 8.5.11 | ⚠️ leak/reclaim | PIE leak/controlled reclaim; no RCE; 8.5.12 fixed |
| FPM | 7.1.32/7.2.23/7.3.10 | 🛠 config-induced | CVE-2019-11043 only with `PATH_INFO`/no script check; stock Debian/WordPress/MediaWiki blocked; EOL |
| FPM | 5.6–7.4 | ❌ no RCE | B1 leak 114,952/114,954 B; stock A1 blocked by 1 MiB nginx; no B2 |
| nginx + mod_php | 8.4.24/26 | ✅ RCE only non-stock | 64 MB body + `post_max_size=64M` + 4 MB buffers + keepalive; stock nginx 1 MiB → 413 |
| WordPress behind nginx + mod_php | 8.4.24/26 | ✅ only non-stock | `/wp-content/index.php` and `/index.php` 6/6; same non-stock limits |
| Arch mod_php | 8.4.26 | ✅ lab RCE | shipped Arch ini; opcache baseline; lab-conditioned |
| Ubuntu 24.04 | 8.3 | 🚫 patched | CVE patch present; A1 200 |
| Alpine 3.20 | 8.3.15 | ❌ no RCE | 8.3 branch behavior; B1 0/3 |
| Alpine 3.21 | 8.4.27 | 🚫 fixed | control clean |
| Rocky 9 | 8.0.30 | ❌ no mod_php | no `libphp.so`; FPM only |
| nginx + FastCGI | stock FPM | ❌ no RCE | params fixed to `HTTP_*`; framing 400/501; no `PHP_VALUE` |
| SOAP | 8.4.20/8.5.5 | ⚠️ UAF/crash | no RCE; 8.4.21/8.5.6 fixed |
| CVE-2026-115560 | 8.4.26/8.5.11 | 🧪 running | session upload-progress/handler switch |
| Zend structure | 8.4.24/26 | 🧪 running | secondary corruption lane |

No evidence artifacts (receipts, bodies, binaries, dumps or per-run reports)
are shipped in this repository; only the tool, its offset profiles and this
document are.

## Layout

| path | contents |
|---|---|
| `tool/php2shell.py` | chain driver (`recon`, `producer`, `write_stage`, `leak`, `g2`, `chain`) |
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

## Scope and authorization

Use only against systems you own or are explicitly authorized to test. The
tool sends malformed multipart bodies that can crash or exhaust PHP workers by
design.

## License

AGPL-3.0; see `LICENSE`.
