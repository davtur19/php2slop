# php2slop

Research exploit tooling for the PHP `session.upload_progress` use-after-free
(CVE-2026-109618 / CVE-2026-109619).

**Status: WIP research code.** This is not a universal or stock-default
exploit. Chains that were measured under lab conditions required specific
build offsets, pool shapes and, in some lanes, non-default configuration. Treat
every result as lab-conditioned until reproduced on your own target.

This repository contains only the exploitation tool, its per-build offset
profiles, and this documentation.

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
