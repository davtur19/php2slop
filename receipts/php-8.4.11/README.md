# `php:8.4.11-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.11-apache` |
| image id | `sha256:27a77f7fe2385bd08dc45c88c29e04c283561d73a870cd6d01bf4d0622a8e547` |
| PHP | `PHP 8.4.11 (cli) (built: Aug 12 2025 22:28:48) (NTS)` |
| Apache | `Apache/2.4.65 (Debian)` |
| libphp | 22,386,616 B, sha256 `fe10341d35be5fdd811fac334457df1b23a11d779eaf4d3188c73f73a62ef726` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x63d2e0` |
| zif_system | `0x446cb0` |
| S anchor | `main+0xF8398` |
| marker | `M84_8411_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=0) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8411_a` | 65 | `a44086204e82d9afd5a0451bdbb18725730302ff5b433e8f252b16cf465baaa0` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8411_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8411_a;echo M84_8411_a>>/out/p1_conc_M84_8411_a;id>&2;echo M84_8411_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
