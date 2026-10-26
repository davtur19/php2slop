# `php:8.4.25-apache` — target-written `uid` proof (copied, not re-executed)

**Status: target-written proof.** Produced on 2026-10-23 in the matrix run; copied byte-for-byte into this tree and hash-verified. It was **not** re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| image | `php:8.4.25-apache` |
| image id | `sha256:c9df646f55dc70fe170515b16aa5d6629e94eb40ca31fdae4294178b6051670f` |
| PHP | `PHP 8.4.25 (cli) (built: Sep 19 2026 00:29:51) (NTS)` |
| Apache | `Apache/2.4.68 (Debian)` |
| libphp | 21,237,136 B, sha256 `a70977eb3ed3aea0569e92da8e3d95d99ff4d96ea8b2fe5ce283525cc01d8a48` |
| php.ini | `php.ini-production`, sha256 `8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a` |
| zval_ptr_dtor | `0x65dc60` |
| zif_system | `0x464c70` |
| S anchor | `main+0xF8398` |
| marker | `M84_8425_a` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 pointer hits (attempt i=0) |
| B2 | 451,384 B body, hit i=4, response 0 B |

## Proof

| file | bytes | sha256 | content |
|---|---|---|---|
| `proofs/p1_conc_M84_8425_a` | 65 | `0cd5318ee3e9bfc1d63e353bef3b9bdd18e68214f0ceea05862d7f5f093b0cbd` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nM84_8425_a\n` |

`final.json` records the same text in `chain.proof`, and the B2 command that wrote it: `id>/out/p1_conc_M84_8425_a;echo M84_8425_a>>/out/p1_conc_M84_8425_a;id>&2;echo M84_8425_a>&2`.

Provenance limit: the original run's per-worker PID attribution is not preserved in `final.json`; this receipt therefore asserts the target-written file (owner `www-data`, marker matching the B2 command) but does not independently re-derive the single-child routing. See `report.md` §3 for the original PID evidence.

## Evidence

- `evidence/final.json` — original per-build record (host port redacted), copied from the matrix run.
- `report.md` — verbatim copy of the matrix report (sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

## Reproduction

See `../../commands.txt` (section `8.4.10–8.4.26`) — the same A1/B1/A2 bodies with this build's two offsets.
