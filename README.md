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

Only the 8.4.10–8.4.26 mod_php chain and Debian 8.4.24 have lab RCE; no
stock/all-version claim.

Legend: ✅ works (RCE) · ❌ does not work (no RCE) · 🚫 patched/fixed.

| Target / SAPI | PHP | RCE? | Conditions / blocker |
|---|---|---|---|
| mod_php | 8.4.10–8.4.26 | ✅ | lab chain; `output_buffering=4096`; 22-byte endpoint; exact offsets; not stock-universal |
| mod_php | 8.4.24 Debian 13 | ✅ | 4/4 blind; Debian package default; warm 25/25 |
| mod_php | 8.4.26 session handlers | ✅ | `php`/`php_binary`/`php_serialize` 3/3 |
| nginx + mod_php | 8.4.24/26, non-stock | ✅ | 64 MB body + `post_max_size=64M` + 4 MB buffers + keepalive; WordPress 6/6 |
| Arch mod_php | 8.4.26 | ✅ | shipped Arch ini; opcache baseline |
| mod_php | 8.4.27 | 🚫 | patched/fixed |
| mod_php | 8.0–8.3 | ❌ | 109619 negative; 109618 no controlled destructor |
| mod_php | 8.5.0/5/11 | ❌ | leak only; no code pointer |
| FPM | 8.0–8.3 | ❌ | 109619 negative; 109618 primitive only |
| FPM | 8.4.26 | ❌ | 109618 primitive; no controlled destructor |
| FPM | 8.5.11 | ❌ | PIE leak/reclaim only |
| FPM | 7.1/7.2/7.3 | ❌ | CVE-2019-11043 only non-stock PATH_INFO/no script check; stock Debian/WordPress/MediaWiki blocked |
| FPM | 5.6–7.4 | ❌ | B1 leak; stock A1 blocked by nginx 1 MiB; no B2 |
| nginx + mod_php | 8.4.24/26 stock | ❌ | nginx 1 MiB → 413; PHP `post_max_size=8M` blocks B1 |
| nginx + FastCGI | stock FPM | ❌ | params pinned to `HTTP_*`; framing 400/501 |
| SOAP | 8.4.20/8.5.5 | ❌ | UAF/crash only |
| Ubuntu 24.04 | 8.3 | 🚫 | patched |
| Alpine 3.20 | 8.3.15 | ❌ | 8.3 branch behavior; B1 0/3 |
| Alpine 3.21 | 8.4.27 | 🚫 | patched/fixed |
| Rocky 9 | 8.0.30 | ❌ | no mod_php; FPM only |

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
