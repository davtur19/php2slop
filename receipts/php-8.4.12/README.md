# `php:8.4.12-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.12-apache` |
| image id | `sha256:d04f3fc12f4cd353424f2444c923e2c0b096e878d6b7d6afdd3b5a2a41b4f277` |
| PHP | `PHP 8.4.12 (cli) (built: Sep  8 2025 21:18:08) (NTS)` |
| Apache | `Apache/2.4.65 (Debian)` |
| libphp | 22,390,896 B, sha256 `e6624242a76dc0a44a5507b7d3e0ebf3b2a4d737d542c7924a5e164e021a2ee1` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x63dc20` |
| zif_system | `0x446cf0` |
| S anchor | `main+0xF8398` |
| marker | `M84_8412_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=0) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8412_a` | 65 | `81f832a9ee5995a10a47060783176ebdd8bd2aa64b42c1d678117609f6c6ae65` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8412_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8412_a;echo M84_8412_a>>/out/p1_conc_M84_8412_a;id>&2;echo M84_8412_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
