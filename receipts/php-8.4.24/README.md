# `php:8.4.24-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.24-apache` |
| image id | `sha256:8d2818176962263f2ea41c9b20e848eebe0d80417d21aaae89f33bfbceed725a` |
| PHP | `PHP 8.4.24 (cli) (built: Aug 25 2026 00:35:26) (NTS)` |
| Apache | `Apache/2.4.68 (Debian)` |
| libphp | 21,232,880 B, sha256 `322c2d16f4a3f460fec0a1c1df778c214cbdb3e1289e41d07fb3071558727df0` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x65d1e0` |
| zif_system | `0x464530` |
| S anchor | `main+0xF8398` |
| marker | `M84_8424_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=0) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8424_a` | 65 | `cd41b427436850101bec8ec5eee6ba956390ccf7d6f36079789f7bfc0b17f8a0` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8424_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8424_a;echo M84_8424_a>>/out/p1_conc_M84_8424_a;id>&2;echo M84_8424_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
