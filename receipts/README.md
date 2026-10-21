# receipts/: curated named-run receipts

Each directory is a complete named run / evidence set with its own README or
findings file. This is the only curated-evidence location; raw one-off lab
logs are NOT tracked in the public repo (kept locally, archived).

| directory | contents |
|---|---|
| `diag3_10_runs/` | diag1-diag10 series: arm-OOM repeat firing (diag3/4), ASAN built-in-server stale-state repro (diag5), gdb breakpoint ground truth `diag9_gdb.cmd` (FRESH/REUSE/DESTROY at var.c:1352/1359/1367), clean-start replay (diag10), cited by `docs/validation_1021_filmpost.md`. |
| `php5lab_receipts/` | php 5.6.40 parity: macro level-sharing serialize guard, `Z_TRY_ADDREF` absent (record via `ZEND_SET_SYMBOL_WITH_LENGTH`), flock self-deadlock wedge with gdb stack (`b3-wedged-worker-gdb-bt.txt`), `USE_ZEND_ALLOC=0` control; `findings.md`. |
| `php7lab_receipts/` | php 7.4.33 parity: level-guard at var.c:1139-1158, machinery-OOM silent close + dispatcher wedge, bisect (`bisect.py`), captured texts; `findings.md`. |
| `advisory_1400/` | embargo-gated one-shot advisory fetch + fetched artifacts (2026-10-21 14:00 UTC): `fetch_advisory_1400.sh`, `analyze_advisory.py`, `HANDOFF.md`, `status.txt`. |

Committing rule: a receipt directory must carry a README or findings file
naming what was run. Everything without such provenance belongs in the local
archive, not here.
