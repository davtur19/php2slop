# `php:8.4.13-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

This build needed a second whole-chain attempt (marker `M84_8413_b`); the first attempt (marker `M84_8413_a`) missed the leak at B1. The details below describe the successful `chain2` attempt; `final.json` retains both.

| item | value |
|---|---|
| image | `php:8.4.13-apache` |
| image id | `sha256:730d38586b429211d25d2b6b95c062421f66ef9bdf9e8d759507c345f58138ba` |
| PHP | `PHP 8.4.13 (cli) (built: Oct 21 2025 01:27:11) (NTS)` |
| Apache | `Apache/2.4.65 (Debian)` |
| libphp | 20,973,296 B, sha256 `f736a943df7037ed2189d19b5c5215bc404b17422177146fd2e69d37c2650dbc` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x63cbe0` |
| zif_system | `0x445bf0` |
| S anchor | `main+0xF8398` |
| marker | `M84_8413_b` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=2) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8413_b` | 65 | `e89329d80d5cc9fff63e73e1667fdab5c4e196d5142bcde221425da7d3ab56e7` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8413_b\n` |

`final.json` records the same text in `chain2.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8413_b;echo M84_8413_b>>/out/p1_conc_M84_8413_b;id>&2;echo M84_8413_b>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
