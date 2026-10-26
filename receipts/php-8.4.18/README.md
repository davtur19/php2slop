# `php:8.4.18-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.18-apache` |
| image id | `sha256:c9616ccf090dc051b933a602946e72b2c7fb041df5eced764702836e68c2aff9` |
| PHP | `PHP 8.4.18 (cli) (built: Feb 24 2026 19:09:41) (NTS)` |
| Apache | `Apache/2.4.66 (Debian)` |
| libphp | 20,986,064 B, sha256 `b8b22ade47419643156827f4955408d43f2846487c721a4c8307e7e2b8705aed` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x63eb20` |
| zif_system | `0x446ff0` |
| S anchor | `main+0xF8398` |
| marker | `M84_8418_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=0) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8418_a` | 65 | `7822f196fff39dad03b50e52d5b40b8bc1005983aa82a3aec812cfbe6d294f1e` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8418_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8418_a;echo M84_8418_a>>/out/p1_conc_M84_8418_a;id>&2;echo M84_8418_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
