# `php:8.4.15-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.15-apache` |
| image id | `sha256:904364767f74a52921f1c909187e864696ee93b50a33cfea41ac19847ef4cc32` |
| PHP | `PHP 8.4.15 (cli) (built: Dec  8 2025 22:49:51) (NTS)` |
| Apache | `Apache/2.4.65 (Debian)` |
| libphp | 20,973,544 B, sha256 `6a36c3e76d6238fcdc03b75545b039b6a61c49f5665666ad99b6e09e49f9018b` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x63d420` |
| zif_system | `0x445f70` |
| S anchor | `main+0xF8398` |
| marker | `M84_8415_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=4) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8415_a` | 65 | `09b418d369954978702ef1116dbae1a4b55873043926a1211757c9f143331911` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8415_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8415_a;echo M84_8415_a>>/out/p1_conc_M84_8415_a;id>&2;echo M84_8415_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
