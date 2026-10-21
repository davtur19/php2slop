# run_fpmwiki_20261021_173406 — CHAIN RECEIPT EXPERIMENT (producer→consumer, stock MW 1.46.2 @ :28840)

## Baseline (17:33:50 CEST, 2026-10-21)
- fpm master pid 3920992 (/tmp/opencode/realapps/fpm/fpm_realapps.conf); pool `wiki` worker pid **3920993** (only child, pm=static max_children=1).
- access log tail (format %p|%d|%t|%m|%s):
```
3920993|0.129|21/Oct/2026:17:32:21 +0200|GET|200
3920993|0.184|21/Oct/2026:17:32:30 +0200|GET|200
3920993|0.051|21/Oct/2026:17:32:31 +0200|GET|200
```
  (note: one earlier line at 17:31:02 lacked a leading pid field: `0.140|21/Oct/2026:17:31:02 +0200|GET|200|8388608` — pid field absent/blank on that line, recorded verbatim)
- php-err-wiki.log: 70984 bytes, sha256 ce4c331b05371a39485da5e26496964b9b66ec3fd3ec56d453070f8f38e2ed4c
- Prior fatal receipts mined from log (append-only, not modified):
  - 12:45:17 `Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in Unknown on line 0`
  - 12:45:17 `... (tried to allocate 32768 bytes) in .../includes/Parser/Parser.php on line 5583`
  - 12:47:32 ×3 `... (tried to allocate 266240 bytes) in Unknown on line 0`
  - 15:17:49 `... (tried to allocate 131072 bytes) in .../resources/Resources.php on line 50`
  - 15:23:08 `... (tried to allocate 2101248 bytes) in Unknown on line 0`  ← the 5.7MB anon edit POST
  - 15:31:03 + 15:32:21 `... (tried to allocate 32768 bytes) in .../includes/Parser/Parser.php on line 6447`
- Prior arm-repeat receipts (runs/diag4_result.json, worker surviving): arm → status 200, body 149 B, page marker "Allowed memory" true, alloc_try 266240, identical sha across 3 runs.
- LocalSettings.php: no $wgMaxArticleSize override → default 1024 KB applies.
- Concurrency note: another worker deleted side/php2shell/diag*.py between 17:33 and 17:34; snapshots of core modules copied into this dir (native-output-leak.py, native-output-leak-stock-arm.py, compact-stock-tail.py, php2shell.py, body_mw.bin, mw_anon.txt).

## Receipts (appended below as experiments run)
