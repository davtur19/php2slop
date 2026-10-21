# run modphp_redo_1021 — CHAIN RECEIPT EXPERIMENT (mod_php producer→consumer OOM battery, "worker J revival").

# Receipt: curation of the completed worker-J revival run. All artifacts ran against
# stack B = httpd 2.4.66 + plain (non-ASAN) mod_php 8.5.10 at 127.0.0.1:28850 (prefork,
# loopback-only, server STILL RUNNING at curation time, master pid 4041485).

# Scratch dir (volatile tmpfs, full inventory in inventory.sha256.txt):
#   /tmp/opencode/modphp_redo_1021/     — modphp_arm.py, conf, runs/*, sessions/*, logs/*

## Stack

- Binaries `/tmp/opencode/apache/bin/httpd` (prefork static) + `/tmp/opencode/apache/modules/libphp.so`
  (40,492,240 B; NOT ASAN-instrumented, verified `ldd | grep asan` = none).
- Scratch conf `conf/conf_httpd_min.conf` (repo copy): `php_value memory_limit 8M` (FPM-receipt
  parity), `php_value session.upload_progress.cleanup 0` (added mid-session via graceful restart),
  `php_admin_value error_log` + `CustomLog ... "%h %l %u %t \"%r\" %>s %b %D %P"` — the trailing
  **%P** is the pid-pairing format.
- htdocs/ = lab `index.php`, `sess.php`, `mem.php` + `info.php` ini probe (repo copies under htdocs/).
- Boot 19:44: master 4041485 + 5 prefork children 4041487–4041491; after graceful restart
  (to activate `cleanup=0`) children re-forked as 4043228–4043232. MaxConnectionsPerChild default 0
  ⇒ children persist — the mod_php "state lives in the worker" premise.
- **Stack A (ASAN mod_php :38491) was UNRECOVERABLE** — toolbin/sysroots/libphp.so deleted;
  no ASAN receipts were obtainable (documented in findings.md: Stacks preamble + §6 negatives
  + §7 item 4 ASAN-log location).

## What was run (chronology, 19:44–19:56 CET 2026-10-21)

1. Boot + smoke: `httpd -t -f conf_httpd_min.conf` → start; `curl /index.php` →
   `modphp-lab 8.5.10 Linux phpversion=8.5.10`; `info.php` → `memory_limit=8M`,
   `session.use_only_cookies=1`, `max_file_uploads=20`, `post_max_size=8M`.
2. Control battery (no producer): `python3 modphp_arm.py --outdir runs/control_baseline --no-producer
   --repeat 2 --gap 0.5` → consumers deterministic, body sha12 `964e4b4f21cab9d6` everywhere.
3. Paired OOM battery A ×3: `python3 modphp_arm.py --outdir runs/oompair_A --repeat 3 --gap 1.0`
   — per run ONE keep-alive connection: baseline probe → producer OOM arm → consumer probes ×3
   + wedge/children post-check. Every run pinned to a single prefork pid (%P):
   run1 pid=4041488, run2 pid=4041490, run3 pid=4041491. Producer body ×3 = 149 B,
   sha256 prefix `561043a1e978c656` (extends the diag4 receipt's sha12 `561043a1e978` ⇒
   byte-parity with the FPM receipt).
4. `session.upload_progress.cleanup 0` added to conf + graceful restart; stored-record preseed:
   benign upload planted `upload_progress_MMM` machinery record in `sessions/sess_abcdefgh`
   (341 B attacker-named content).
5. Stored-record battery B ×5: `--outdir runs/oompair_B_stored --repeat 5 --gap 1.0` —
   pairing across 4 distinct workers (4043228/229/230/232), same producer/consumer determinism,
   wedge=ok every run.
6. Arbitrary-script criterion C ×2: `--outdir runs/oompair_C_index --repeat 2
   --target /index.php` — identical 149 B OOM producer on a script with NO session API;
   consumers deterministic.
7. Same-worker repeat: 5 consecutive OOM producers on one keep-alive connection → same sha
   `561043a1e978` ×5, then clean consumer + 200 on /index.php; children unchanged
   (`logs/same_worker_repeat_console.log`).
8. INI diagnostics around the OOM (long-sid warning probes, 200-char UPG names, plain consumers)
   before/after the producer: byte-identical bodies both sides
   (`logs/ini_diag_manual.log`, long-sid body sha `4e19cc6deab8f59d` both sides).
9. Oversized-stored-record attempts (sid big3mnbl n=3145728, big24mnbl n=2400000, 4 MB plant):
   all OOM during record **encode** with fixed alloc `2098791` before any flush; store never
   oversized on disk (`logs/record_oom_console.log`, `logs/record_tune_console.log`).

## Key numbers (evidence-pinned in this receipt)

- Producer OOM: `HTTP 200` + body 149 B
  `<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240
  bytes) in <b>Unknown</b> on line <b>0</b>` — body sha256 prefix `561043a1e978c656` across every
  run (diag4 FPM receipt recorded sha12 `561043a1e978` for the same 8.5.10 OOM body ⇒ parity).
- Arm body: 20 file parts (max_file_uploads cap), filename `F`×9 then `F`×262144, terminator;
  4,983,497 B < 8M `post_max_size` (multipart machinery engages, OOM fires pre-RINIT pre-app).
- Consumers: 17 B body `abcdefgh\nfiles=1\n` (sha12 `964e4b4f21cab9d6`, inline
  `probes/oompair_A_r01_consumer_probe_1.body`), byte-identical before/after
  producer on the same worker; every battery post_check `wedge=ok`.
- php_err.log: exact fatal text `PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted
  (tried to allocate 266240 bytes) in Unknown on line 0` present 16× in the curated copy
  (grep-count, append-only log still growing); no child-exit/segfault lines in httpd err.log.

## Verdict (see findings.md for full chains of evidence)

- **Proven**: mod_php producer OOM pre-app-code, byte-parity with validated FPM receipts;
  same-worker consumption via keep-alive + %P pairing; stored-record substrate re-enters the
  machinery pre-app on every request; arbitrary-script (no-app-lever) firing.
- **Not proven**: CVE-2026-109619 stale-decoder-state RCE manifestation on mod_php — no
  divergence/wedge/corruption observed on the plain build; would need a libphp.so offset PROFILE
  for the forged consumer and/or the (deleted) ASAN build.

## Directory index of this receipt

| path | content |
|---|---|
| `findings.md` | full structured write-up adapted from the run's scratch findings.md |
| `inventory.sha256.txt` | sha256 + byte count of EVERY file in the scratch dir (big/not-copied files pinned by hash at their tmpfs source path) |
| `scripts/modphp_arm.py` | the arm script AS RUN (stdlib only: OOM arm + consumer driver + %P pairing compiler) |
| `conf/conf_httpd_min.conf` | the httpd conf AS RUN (php_value memory_limit 8M, upload_progress.cleanup 0, %P CustomLog) |
| `htdocs/` | docroot probes (index.php/info.php/mem.php/sess.php copies) |
| `results/` | matrix_*.jsonl pid pairings + *_summary.json per battery (A, B_stored, C_index, control_baseline) |
| `logs/` | battery consoles, same_worker_repeat, ini_diag_manual, record_oom/record_tune, access_log_pctP.log (%P receipts), php_err.log, httpd_err.log |
| `probes/` | representative transcript bodies: producer OOM body 149 B ×2 (sess.php + index.php), consumer 17 B, stored session record `sess_abcdefgh.bin` + hexdump |

Everything else of the run: path+sha256 only (see `inventory.sha256.txt`).
