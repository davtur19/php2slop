# `php:8.3.35-apache` — **not reproduced** (stage 1 only)

**Status: `not reproduced`.** The stock A1/B1 pair from this session's 8.4.1–8.4.7 lane was attempted on this build. A1 ends in a *parse-time* OOM; B1 returns a normal 26-character session id with no libphp pointers. No target-written file exists, so this directory has no `proofs/`.

## Target (measured)

| item | value |
|---|---|
| image | `php:8.3.35-apache` |
| image id | `sha256:90620e863c15e608cfebd058554d82d2c7fd816bdd690adc69027409cbb7a369` |
| repo digest | `php@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` |
| PHP | `PHP 8.3.35 (cli) (built: Oct 21 2026 00:33:53) (NTS)` |
| SAPI | `Server version: Apache/2.4.69 (Debian)`, prefork mod_php |
| MPM | `StartServers            5 / MinSpareServers         5 / MaxSpareServers         10 / MaxRequestWorkers       150 / MaxConnectionsPerChild  0` |
| php.ini | unmodified `php.ini-production`, 73,397 B, `2533da00f66b1cf18430b08871262afa12f58cf2ee43b2077740c9c3972bb980` |
| docroot | `/var/www/html` (read-only bind), endpoint `/index.php`, 22-byte stub |
| libphp symbols | `zval_ptr_dtor = 0x49ec50`, `zif_system = 0x3ac080` (`nm -a`, recorded in the search log; no chain stage used them) |

## What was run

| stage | attempt | status | response bytes | worker pid | observation |
|---|---|---|---|---|---|
| A1 | 1 | `HTTP/1.0 500 Internal Server Error` | 211 | 774 | error log: `tried to allocate 8192 bytes` — multipart parse abort, not END cleanup |
| B1 | 0 | `HTTP/1.1 200 OK` | 253 | 774 | no pointers (decoded=34) |
| B1 | 1 | `HTTP/1.1 200 OK` | 253 | 774 | no pointers (decoded=34) |
| B1 | 2 | `HTTP/1.1 200 OK` | 253 | 774 | no pointers (decoded=34) |

B1 responses: `no pointers (decoded=34)`; `no pointers (decoded=34)`; `no pointers (decoded=34)`; the decoded `Set-Cookie` value is 34 bytes and contains no value in the pointer filter range (0x7C0000000000–0x800000000000), so no leak stage can start.

The pin itself was accepted (`parent=1, children=150, established=149`), so the failure is not pool routing.

## Exact blockers

1. **The stock early A1 never reaches END cleanup on this build either.** The same
   `a1_early.bin` produces a parse-time OOM (`tried to allocate 8192 bytes`), B1 returns a
   fresh 26-character session id and no value in the pointer filter range.
2. **No 8.3.35-specific calibration exists.** Unlike 8.2.34 there is no preserved priming
   body, no END-phase OOM record and no B1 geometry for 8.3.35 anywhere in the project
   tree; this session's attempt is the only record.
3. **What would be needed:** an A1 that reaches `php_session_reset_id` cleanup with
   `PS(status)=2` / `PS(send_cookie)=1` on 8.3.35 (a `mk_a1c.py`-style tune of
   `--parts/--big/--tailk/--tailk2` against this build's 128 M limit), then a B1 body that
   reuses the freed chunk. Without the first, no B1 geometry can leak.
4. **A1-only is not a chain.** No target-written file exists; this directory must not be
   read as RCE.

## Evidence files

- `evidence/result.json` — per-stage record (paths, container name, host port redacted).
- `evidence/responses/` — raw A1 and B1 responses.
- `evidence/logs/` — raw Apache access/error logs.
- `evidence/config/`, `evidence/docroot/` — the exact mounted files.
- `evidence/env.json` — image digest, versions, hashes.

## Next concrete command

```bash
# 1) First recover or regenerate an A1 that reaches END cleanup (see blockers).
# 2) Measure this build's S anchor; do not reuse the 8.4.x 0xED398 value.
# 3) Then run the chain with the recovered bodies:
python3 tools/chain_early.py --container <container> --port <PORT> \
  --tag PR8335A --build 8.3.35 --zdtor 0x49ec50 --zif 0x3ac080 --soff <S-offset> \
  --a1 <a1-reaching-END>.bin --b1 <b1-geometry>.bin --fillers 115 \
  --outdir out/8.3.35 --logdir logs
```

Without step 1 there is no runnable chain command for this build; the exact attempt that produced the records here is in `../../commands.txt` (section `8.3.35`).
