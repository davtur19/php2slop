# files/io/ — run receipts

Captured request/response/body artifacts, scanner outputs (`maps_*`), ASAN/
trigger run logs, and OOM-experiment transcripts from the 2026-10-21 lab
sessions. These are protected evidence: they date from before the advisories
published and are the receipts the CVE↔mechanism claims rest on
(see `docs/validation_1021_filmpost.md` and `reports_realapps_validation_1021.md`).

| receipt group | stage captured |
|---|---|
| `asan_S*.out`, `body_S*.bin`, `body_3f.bin` | staged multipart shape runs S1..S5 (arm/probe variants) → php-cgi |
| `p4 Trace*.log` group: `p4_trace_*.log`, `gdb_p4_*.gdb` (in `lab/`) | machinery OOM window gdb/script sessions p4-1..p4-3 |
| `trig_trig-fast-*` | 258-byte writeup trigger shape, stock / mf0 / asan / asanmf0 runs |
| `ov25_*` | 25-file body probe (max_file_uploads boundary) |
| `p619_*` | CVE-2026-109619 shape runs (plain / np / asan, CGI jig) |
| `p618_gdb.out`, `p618_trace.log` | staged 618 gdb + trace captures |
| `maps_*.out` | worker memory map scans (p/r2/reload/w series) |
| `configure_asan.log`, `install_asan.log`, `make_asan.log`, `ctrl_out.txt` | ASAN php-src build pipeline (loopback lab build only) |

New driver receipts default to `files/io/<target>-<step>-<UTC stamp>/`
(`tool/php2shell.py --output` overrides). `files/snapshots/` holds lab binary
images when captured (kept out of the repo history otherwise;
`.gitignore` excludes future lab noise: `runs/`, `receipts/`, `*.log`).
