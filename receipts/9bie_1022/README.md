# 9bie `php2shell-bypass-aslr-exp` — private-lab reproduction

Receipt: `/tmp/opencode/research/9bie_20261022T024258Z`
Date: 2026-10-22 (UTC)
PoC: <https://github.com/9bie/php2shell-bypass-aslr-exp> @ `4586f5cc120c82fd468b17469202bac629810ad9`
Target: official `php:8.4.26-apache` (`php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`, PHP 8.4.26 NTS, Apache 2.4.69, Debian 12, prefork + mod_php)
Isolation: four loopback-only containers (`127.0.0.1:18088–18091`); no existing container or shared service was modified.

## Verdict

| Step | Result |
|---|---|
| Exact public PoC, `display_errors=On`, single worker | **Reproduced**, 3/3 one-shot: both `Set-Cookie` OOB leaks and `uid=33(www-data)` via `zif_system`, with ASLR on and no gdb in the exploit path. |
| `display_errors=Off` (production default), published heap-leak variant | **Chain fails.** The classic chain loses its leak; the published no-display OOM-in-cookie variant produced no OOB cookie on the official image in any published shape. |
| Multi-worker default prefork | **1/5 end-to-end** (0/5 one-shot); the successful run needed retries at all three stages. |
| `MaxConnectionsPerChild=1` worker rotation | **0/3**; A and B cannot share a worker, so the leak and the reclaim never meet. |

Offsets used (derived from the shipped `libphp.so`, matching the PoC README):
`zif_system=0x465370`, `zval_ptr_dtor=0x65eb60`; `HTDATA = chunk + 0x690d8` for the bookworm profile. The first run used the repo's lab defaults (`0x43a870`/`0x613c50`) and stage 2 correctly rejected the leak (`evidence/single_worker/run1_bad_offsets.log`); every reported run uses the official-image values.

## Sequence and artefacts

The instrumented request sequence (12 requests, three rotate/A/B stage groups) is tabulated in `report.md` §1.3 and preserved raw under `evidence/`:

```
evidence/single_worker/     requests.json, 12 responses, proof_sw{1,2,3}.txt, run logs
evidence/multi_worker/      reliability run logs, captured request/response set
evidence/rotation/          MaxConnectionsPerChild=1 runs (0/3)
evidence/display_errors_off/classic + OOM-in-cookie variant captures and sweeps
lab_config/                 the exact php.ini / apache.conf variants and index.php
scripts/                    capture, probe and A/B senders used for the run
metadata.txt                image digest, symbols, offsets, container IDs
```

`report.md` is the authoritative write-up: request shapes, leak decode (98 pointers → 2 MiB chunk base; `nTableSize|pDestructor` → libphp base), fake-HashTable stage and the reliability tables.

## Scope

No application code was involved: the target page is `<?php echo "OK\n"; ?>`. This receipt reproduces a public PoC against the official image and measures where its `display_errors`/worker assumptions break; it does not add a new exploit. The PoC checkout, container layers and 12 MiB request bodies are environment, not evidence, and are not included here.
