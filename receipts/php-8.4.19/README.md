# `php:8.4.19-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.19-apache` |
| image id | `sha256:59cce7f8647d32fae782d2ba5e31c339c2cc7747fc9ebeab872033dba3f6fd69` |
| PHP | `PHP 8.4.19 (cli) (built: Apr  7 2026 01:33:04) (NTS)` |
| Apache | `Apache/2.4.66 (Debian)` |
| libphp | 20,986,360 B, sha256 `f56ef68faa09c408f7f7144a07628ed71b7d6f2270cdf7e1f063cdc7e12a1853` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x63efe0` |
| zif_system | `0x4472f0` |
| S anchor | `main+0xF8398` |
| marker | `M84_8419_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=1) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8419_a` | 65 | `66e6176d5280470851c94fdfaf3559365592d7a9e09ad23d8e6fb926a881e7e4` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8419_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8419_a;echo M84_8419_a>>/out/p1_conc_M84_8419_a;id>&2;echo M84_8419_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
