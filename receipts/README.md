# receipts/ — curated named-run receipts

Each directory is a complete named run / evidence set with its own README or
findings file. This is the only curated-evidence location; raw one-off lab
logs are NOT tracked in the public repo (kept locally, archived).

| directory | contents |
|---|---|
| `diag3_10_runs/` | diag1–diag10 series: arm-OOM repeat firing (diag3/4), ASAN built-in-server stale-state repro (diag5), gdb breakpoint ground truth `diag9_gdb.cmd` (FRESH/REUSE/DESTROY at var.c:1352/1359/1367), clean-start replay (diag10) — cited by `docs/validation_1021_filmpost.md`. |
| `php5lab_receipts/` | php 5.6.40 parity: macro level-sharing serialize guard, `Z_TRY_ADDREF` absent (record via `ZEND_SET_SYMBOL_WITH_LENGTH`), flock self-deadlock wedge with gdb stack (`b3-wedged-worker-gdb-bt.txt`), `USE_ZEND_ALLOC=0` control; `findings.md`. |
| `php7lab_receipts/` | php 7.4.33 parity: level-guard at var.c:1139–1158, machinery-OOM silent close + dispatcher wedge, bisect (`bisect.py`), captured texts; `findings.md`. |
| `advisory_1400/` | embargo-gated one-shot advisory fetch (run 2026-10-21T17:42–17:43Z from this session, post-embargo, foreground; pre-embargo guard runs kept in `status.txt`) + fetched artifacts: `changelog8.html`, commit JSONs, 6 unified diffs (root fix `3584a98bda0f` + merge chain + tag copy `31c0ea7d7ff1`), `compare_8510_8512.json`, `archive_2026.html`, `manifest.sha256` (15/15 verified); 8.5.10→8.5.12 CVE→fix-commit mapping in `attribution_8510_8512.md`. |
| `fpmwiki_produce_consum_1021/` | harvest of worker G's producer→consumer FPM-wiki run `run_fpmwiki_20261021_173406` (MW 1.46.2 @ :28840): producer edit-POST OOM calibration + 5× deterministic machinery-OOM arm (`266240/Unknown line 0`) + upload-progress consumer probes → canonical render, `candidate=false`; verdict + anomalies (empty consumer sid, missing probe driver/worker-pid receipts) in `findings.md`; full run inventory `inventory.sha256.txt`. |
| `modphp_oompair_1021/` | "worker J revival" battery: OOM arm (`F`×262144 fingerprints, 4,983,497 B) vs httpd 2.4.66 + plain mod_php 8.5.10 @ :28850 → pre-app-code machinery fatal `266240/Unknown line 0` (body sha12 `561043a1e978c656` = byte parity with the FPM diag4 receipt; mod_php answers 200+fatal-in-body vs FPM 500); same-worker consumption proven by prefork keep-alive + `%P` pid pairing (one pid per run; battery B across 4 workers); stored `upload_progress_MMM` session record re-decoded/re-encoded pre-app (885 B snapshot + hexdump); decode-OOM unreachable via UPG-name plants (fixed encode cap `2098791`); **109619 stale-decoder-state RCE unproven** on plain build, ASAN stack A unrecoverable (deleted toolbin/sysroots); `modphp_arm.py`, conf, per-battery matrix/summary + console logs, `inventory.sha256.txt`. |

Committing rule: a receipt directory must carry a README or findings file
naming what was run. Everything without such provenance belongs in the local
archive, not here.
