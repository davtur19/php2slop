# `php:8.2.34-apache` — **not reproduced** (stage 1 only)

**Status: `not reproduced`.** The stock A1/B1 pair from this session's 8.4.1–8.4.7 lane was attempted on this build. A1 ends in a *parse-time* OOM; B1 returns a normal 26-character session id with no libphp pointers. No target-written file exists, so this directory has no `proofs/`.

## Target (measured)

| item | value |
|---|---|
| image | `php:8.2.34-apache` |
| image id | `sha256:f380b054d6364b80f0952a9198e5dc1e1ab4d809aad24d3f3174f059e863f48a` |
| repo digest | `php@sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` |
| PHP | `PHP 8.2.34 (cli) (built: Oct 21 2026 00:35:21) (NTS)` |
| SAPI | `Server version: Apache/2.4.69 (Debian)`, prefork mod_php |
| MPM | `StartServers            5 / MinSpareServers         5 / MaxSpareServers         10 / MaxRequestWorkers       150 / MaxConnectionsPerChild  0` |
| php.ini | unmodified `php.ini-production`, 73,870 B, `b40aed987458694f7d81b0e469e05d125fff3175d9901fe70a6321ed833af9e1` |
| docroot | `/var/www/html` (read-only bind), endpoint `/index.php`, 22-byte stub |
| libphp symbols | `zval_ptr_dtor = 0x487650`, `zif_system = 0x39b8a0` (`nm -a`, recorded in the search log; no chain stage used them) |

## What was run

| stage | attempt | status | response bytes | worker pid | observation |
|---|---|---|---|---|---|
| A1 | 1 | `HTTP/1.0 500 Internal Server Error` | 211 | 801 | error log: `tried to allocate 8192 bytes` — multipart parse abort, not END cleanup |
| B1 | 0 | `HTTP/1.1 200 OK` | 253 | 801 | no pointers (decoded=34) |
| B1 | 1 | `HTTP/1.1 200 OK` | 253 | 801 | no pointers (decoded=34) |
| B1 | 2 | `HTTP/1.1 200 OK` | 253 | 801 | no pointers (decoded=34) |

B1 responses: `no pointers (decoded=34)`; `no pointers (decoded=34)`; `no pointers (decoded=34)`; the decoded `Set-Cookie` value is 34 bytes and contains no value in the pointer filter range (0x7C0000000000–0x800000000000), so no leak stage can start.

The pin itself was accepted (`parent=1, children=150, established=149`), so the failure is not pool routing.

## Exact blockers

1. **The stock early A1 never reaches END cleanup on this build.** `a1_early.bin`
   (1,123,451 B) aborts inside multipart parsing — `Allowed memory size of 134217728 bytes
   exhausted (tried to allocate 8192 bytes)` — so no stale `PS(id)` survives for B1 to
   refill. B1 then returns a fresh 26-character session id.
2. **The build-specific priming body is not preserved.** Earlier 8.2.34 work used
   `bodies/c1.bin` (2,885,644 B, from a `mk_a1c.py` tune) that did reach the END phase with
   `PS(status)=2`, `PS(send_cookie)=1` and a stale `PS(mod_data)=chunk+0x1ef9d8`. Neither
   `c1.bin` nor `mk_a1c.py` exists in the project tree or the scratch directories any more
   and the tune parameters were never recorded, so the leak stage cannot be reached.
3. **The B1 geometry is unsolved for this build.** The recorded leak recipe
   (5×`G:511` + `G:0x190` + 6×`G:511` + `X:80`, 461,990–521,262 B leak) produced no `libphp`
   pointer cluster and needed gdb / `--kill-others` nudges — not a stock-HTTP result. The
   `map[0x1ef] -> SRUN` placement for 8.2.34 has not been found.
4. **A1-only is not a chain.** The parse-time OOM is reproducible but writes no file; this
   directory must not be read as RCE.

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
  --tag PR8234A --build 8.2.34 --zdtor 0x487650 --zif 0x39b8a0 --soff <S-offset> \
  --a1 <a1-reaching-END>.bin --b1 <b1-geometry>.bin --fillers 115 \
  --outdir out/8.2.34 --logdir logs
```

Without step 1 there is no runnable chain command for this build; the exact attempt that produced the records here is in `../../commands.txt` (section `8.2.34`).
