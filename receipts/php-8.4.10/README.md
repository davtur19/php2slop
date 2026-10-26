# `php:8.4.10-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.10-apache` |
| image id | `sha256:e7dfce7f85cede10c7a9c334ecb0bee9cff6fe83bbf64f5e1c5a3cf5879f7a8b` |
| PHP | `PHP 8.4.10 (cli) (built: Jul 22 2025 01:17:53) (NTS)` |
| Apache | `Apache/2.4.62 (Debian)` |
| libphp | 22,317,368 B, sha256 `a6b5a2e606b3c06681cc6b13a23aab948c2daf7060c90871c18e4700eb3c655d` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x62cf70` |
| zif_system | `0x43b7d0` |
| S anchor | `main+0xF8398` |
| marker | `M84_8410_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=4) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8410_a` | 65 | `bbbb206d0b5a07a78110238bed3d546b04030bf81679534c6d9c1d7b650dc469` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8410_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8410_a;echo M84_8410_a>>/out/p1_conc_M84_8410_a;id>&2;echo M84_8410_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
