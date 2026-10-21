# findings — modphp_oompair_1021 (mod_php producer→consumer OOM battery, CVE-2026-109618 / CVE-2026-109619)

Curation 2026-10-21 of the completed redo session ("worker J revival" — J died mid-run leaving an
empty run dir; this session re-ran the whole battery). Source scratch dir (volatile tmpfs, full
integrity list in `inventory.sha256.txt`): `/tmp/opencode/modphp_redo_1021/`. Everything inlined
here is cited receipt-relative; everything else is pinned by path+sha256 at the source path.

**Stacks.**
- **Stack B (used for everything)** — httpd 2.4.66 + plain mod_php 8.5.10, `127.0.0.1:28850`,
  prefork, loopback-only, **still running at curation time** (master 4041485, `httpd.pid`).
  Binaries `/tmp/opencode/apache/bin/httpd` + `/tmp/opencode/apache/modules/libphp.so`
  (40,492,240 B, NOT ASAN — verified `ldd|grep asan` = none). Conf as run: `conf/conf_httpd_min.conf`
  (lab-conf copy; only paths → scratch + the ini lanes: `php_value memory_limit 8M`,
  `php_value session.upload_progress.cleanup 0`, `php_admin_value error_log`,
  `CustomLog ... %D %P`).
- **Stack A (`/home/davide/ailocal/php/modphp_0910/`, ASAN mod_php 8.5.10, :38491) — UNRECOVERABLE
  (infra finding).** `start_httpd.sh`/`run_httpd.sh` reference `$BASE/toolbin/apache2`,
  `$BASE/php-src/libs/libphp.so`, and sysroots (`$BASE/sysroot`, `stock_iso/sysroot`,
  `apache_iso_0909/sysroot/...`) — **all deleted** from the repo (partially cleaned; only
  `conf/`, `docroot/`, `logs/`, empty `run/`, scripts remain). The only surviving
  `libphp.so` anywhere is a plain non-ASAN build (`zerodays_1020/build_plain`); `build_asan`
  trees contain no built `libphp.so`. Reconstruction = full ASAN php-src + httpd toolchain
  rebuild — out of scope for a redo session. **Therefore no ASAN receipts were obtainable**;
  on the plain build, anomaly evidence would only surface via `mpm_prefork` child-exit lines in
  the httpd error log (none occurred — §4).

## 1. What was run

`scripts/modphp_arm.py` (stdlib only, self-contained; inline AS RUN — deliverable 1). Invocation:

```sh
cd /tmp/opencode/modphp_redo_1021
# control battery (no producer):
python3 modphp_arm.py --outdir runs/control_baseline --no-producer --repeat 2 --gap 0.5
# paired OOM battery R×N: baseline probe → producer(OOM arm) → consumer×3 (keep-alive pinned) + wedge check
python3 modphp_arm.py --outdir runs/oompair_A --repeat 3 --gap 1.0
python3 modphp_arm.py --outdir runs/oompair_B_stored --repeat 5 --gap 1.0   # with stored record on disk
python3 modphp_arm.py --outdir runs/oompair_C_index --repeat 2 --target /index.php
```

How the OOM is achieved (answers the "admin-only memory_limit" question):
- The **server config** supplies the tiny limit; no per-request INI override is attempted
  (`memory_limit` under mod_php via `php_value` is PHP_INI_ALL — verified live: after graceful
  restart `info.php` printed `memory_limit=8M`; the FPM lane had used
  `php_admin_value[memory_limit]=8M` in `fpm_realapps.conf` — validated diag3/diag4).
- The **arm body** is what overshoots the 8M: stock `arm_body(sid, 262144)` — boundary
  `NATIVEOUTPUTEXACT`, field `PHPSESSID=<sid>`, field `PHP_SESSION_UPLOAD_PROGRESS=MMM`,
  then 20 file parts (max_file_uploads cap), filename `F`×9 then `F`×262144 for the rest,
  terminator. Body = **4,983,497 B** (< 8M `post_max_size`, so the *multipart machinery* engages
  and blows inside request-startup instead of aborting pre-machinery).
- Per-request alternatives ruled out by measurement: `PHP_VALUE` header spoofing is not a
  capability of this experiment (plain mod_php honors only config/htaccess), and an oversized
  `PHP_SESSION_UPLOAD_PROGRESS` *name* plant OOMs during record **encode** — the store is never
  flushed (§3.3).

## 2. Producer: mid-init OOM reproduced pre-app-code on mod_php — REPLICA OF THE FPM RECEIPT

Producer response on the plain build (inline `probes/oompair_A_r01_producer_oom_arm.body`):

```
HTTP/1.1 200 ... (mod_php keeps 200; FPM receipt expected 500 — header diff, §5)
<br />
<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted
(tried to allocate 266240 bytes) in <b>Unknown</b> on line <b>0</b><br />
```

Identical bullet for bullet with the FPM receipts:
- `logs/php_err.log`: `PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to
  allocate 266240 bytes) in Unknown on line 0` — 16 grep-countable occurrences in the curated
  copy (append-only; the scratch findings noted 19 by session end at 19:56, server kept serving).
- Response body sha256 prefix `561043a1e978c656` — the diag4 FPM receipt recorded sha12
  `561043a1e978` for the same 8.5.10 OOM body on stock FPM. **Byte-level parity achieved.**
- "in Unknown on line 0" ⇒ fatal inside the multipart/session machinery during request startup,
  **pre-RINIT, pre-app-code** — the mod_php producer shape claimed upstream (no app lever needed):
  it fired identically with target `/sess.php` AND `/index.php` (arbitrary-script criterion, §4).

## 3. Same-worker consumption + pairing (deliverables 2 & 3 evidence)

Each battery run opened ONE keep-alive connection: baseline → producer → consumer×3. `%P` in the
access log pins the serving prefork child per request; full per-step lines with
`pid_from_accesslog` per battery are inline:

- `results/matrix_oompair_A.jsonl` (battery A ×3): run1 all steps pid=**4041488**, run2 all
  pid=**4041490**, run3 all pid=**4041491** (`logs/oompair_A_console.log` — one full battery).
- Battery B (after `upload_progress.cleanup=0` + preseeded stored record) hit **4 distinct prefork
  workers** 4043230/4043232/4043229/4043228 — each consumed the OOM producer and then served its
  consumers from the **same process** (`results/matrix_oompair_B_stored.jsonl`,
  `logs/oompair_B_console.log`), proving "state lives in the worker itself".
- Same-worker consumption is also proven structurally: one keep-alive TCP connection per run;
  httpd prefork serve-all-steps-of-one-connection semantics + identical %P on producer/consumer
  lines of `logs/access_log_pctP.log` (raw %P access-log receipts, last field = child pid).
- Worker-survival parity (diag4 repeats): same keep-alive connection, **5 consecutive producers →
  same sha 561043a1e978 every time**, then clean consumer and a 200 on `/index.php`
  (`logs/same_worker_repeat_console.log`); all children still alive, `logs/httpd_err.log` has no
  child-exit, segfault or corruption lines. **On 8.5.10 the OOM tears down the REQUEST, not the
  worker process.**

## 4. Stored-record substrate (CVE-2026-109619 consumption shape)

- Enabled `php_value session.upload_progress.cleanup 0` + graceful restart; preseeded a real
  machinery record via a completed benign upload: `sessions/sess_abcdefgh` grew to 341 B of
  attacker-named content `upload_progress_MMM|a:5:{s:10:"start_time";...;s:5:"files";a:7:{...}}`
  (inline snapshot: `probes/sess_abcdefgh.bin` + `probes/sess_abcdefgh.hexdump`).
- Subsequent consumer exchanges re-decode and re-encode this record pre-app: the redo session
  recorded the file md5 changing across battery C (`ab0f5416…` → `883e75f9…`, size stable 341 B
  at that time); the pinned snapshot shows the file has kept mutating since — **885 B, sha256
  `ef259aa1…`** (see inventory) vs **891 B** right after the record-oom plant
  (`logs/record_oom_console.log`: "sess_abcdefgh size after plant: 891"), battery C ran in
  between. The machinery DOES re-enter and consume the stored record on this lane.
- Oversized-record attempts at decode-OOM (name plants) did **NOT** reach disk: 4 MB / 3 MB
  (`big3mnbl`, n=3145728) / 2.4 MB (`big24mnbl`, n=2400000) UPG names all OOM during record
  **encode** with the **fixed** `tried to allocate 2098791 bytes` before the flush
  (`logs/record_oom_console.log`, `logs/record_tune_console.log`). The encode phase caps what can
  be stored ⇒ a stored record large enough to OOM the *decoder* is not reachable via the
  UPG-name vector on this build.

## 5. Arbitrary-script criterion

Battery C (`results/matrix_oompair_C_index.jsonl`, inline `probes/oompair_C_r01_producer_oom_arm.body`):
producer fired on `/index.php` (no session API) — same 149-byte OOM body
`561043a1e978c656`, consumers deterministic (42 B page, sha12 `385b0361b92629e6`, one pinned
worker per run: 4043229 / 4043230). The producer needs **no application support** on mod_php.

## 6. What was NOT observed (negative results, important)

On the plain 8.5.10 mod_php build, after the mid-init OOM producer:
- consumers (plain multipart probes, giant 300-char sid + INI-diagnostics probes, 200-char UPG
  names) returned **byte-identical** bodies before and after the OOM on the same worker
  (`logs/ini_diag_manual.log` — long-sid warning body sha `4e19cc6deab8f59d` both sides);
- no wedge (`post_check wedge=ok` every battery), no child death, no flock self-deadlock visible,
  no poisoned response, no error-log anomaly beyond the expected request-local fatals;
- RCE-class behavior: **not achieved / not attempted beyond receipts** — the forged-bookkeeping
  consumer (149×`t[]` reclaim + forged call target) requires per-binary offsets (`zif_passthru`,
  leak/target/stage offsets, dso deltas); the FPM profiles in
  `/tmp/opencode/realapps/side/php2shell/php2shell.py` explicitly do not transfer to
  `libphp.so` (per-binary offsets; a libphp.so PROFILE entry must be measured), and stack A's
  ASAN build — where anomaly would manifest in the ASAN log — is unrecoverable (§ Stack A).

## 7. mod_php-vs-FPM differences hit

1. **Session id delivery**: FPM stock arm (diag3/4) sent `PHPSESSID` **form field only**, no
   Cookie. mod_php honored `session.use_only_cookies=1` (default) ⇒ sid had to travel via
   `Cookie: PHPSESSID=<sid>` (worker-H lesson reconfirmed; both field and cookie are now sent —
   field kept for byte parity). Verified live via `info.php`.
2. **Response status**: FPM receipts frame the arm answer as HTTP 500 (articles "expect 500");
   this mod_php laminate answered `200` with the fatal in the body (status set before the
   machinery fatal is not promoted the same way in the handler SAPI). Body/limit/alloc numbers
   identical.
3. **State location & recycling**: prefork children persist (MaxConnectionsPerChild 0) and each
   keep-alive connection pins one child — same-worker provenance is *stronger* than on the pooled
   FPM receipts (which needed `%p` in fpm access.format to pair). A graceful restart is what
   wipes worker state (used once, to activate `upload_progress.cleanup=0`: master 4041485
   unchanged, children re-forked as 4043228–4043232).
4. **ASAN log location**: for stack A it would have been `$BASE/logs/error_log` (Apache error log
   catches the ASAN report — libphp preloads into httpd via the stack's LD_PRELOAD launcher);
   unavailable, stack unrecoverable. On the plain stack the equivalent worker-anomaly channel is
   the httpd `logs/err.log` child-exit lines + the **separate** PHP error_log
   (`php_admin_value error_log` → `logs/php_err.log`).
5. **`memory_limit` control**: `php_value` (NOT admin-only under mod_php) suffices; verified
   observable via `ini_get` from `info.php`. The "admin-only" caution proved to be an
   FPM-pool-lane property.

## 8. Exact commands / environments

```sh
# boot (scratch conf; config test first)
/tmp/opencode/apache/bin/httpd -t -f /tmp/opencode/modphp_redo_1021/conf_httpd_min.conf
/tmp/opencode/apache/bin/httpd -f /tmp/opencode/modphp_redo_1021/conf_httpd_min.conf -k start
# graceful restart after conf tweak (cleanup=0)
/tmp/opencode/apache/bin/httpd -f ... -k restart
# smoke
curl -s http://127.0.0.1:28850/index.php      # "modphp-lab 8.5.10 Linux phpversion=8.5.10"
curl -s http://127.0.0.1:28850/info.php       # memory_limit=8M, use_only_cookies=1, max_files=20, post_max_size=8M
# batteries (§1) + one-off drivers logged into runs/*_console.log (inline under logs/)
```

## 9. Verdict & explicit statement of what remains unproven

**CVE-2026-109618 OOM-corruption producer shape on mod_php: REPRODUCED** — pre-app-code
machinery OOM, byte-parity with the validated FPM receipts (sha12 `561043a1e978`), worker-pinned
(%P pairing), app-independent (fires on /index.php), deterministic across repeats on the same and
across workers.

**CVE-2026-109619 stale-decoder-state RCE manifestation on mod_php: NOT PROVEN.**
1. No divergence/wedge/corruption observed on the plain build (§6); every consumer
   byte-deterministic. Absence of ASAN instrumentation limits sensitivity — a silent
   (non-tripping) conservative-decode recovery may still have occurred.
2. The forged-consumer step needs a libphp.so byte-offset PROFILE — not measured here (FPM
   profiles don't transfer), and/or the ASAN build whose `AddressSanitizer SEGV` reports marked
   the FPM-side proof — stack A's binaries were deleted (documented infra finding).
3. Post-OOM worker wedging / flock leak (php-5.6 receipt shape): not reproduced — 8.5.10 mod_php
   workers survived 5 back-to-back OOM producers on one connection.
4. Stored-record decode machinery demonstrably re-enters pre-init on the same process (§4), but
   decode-OOM via UG-name plants is unreachable (encode caps the stored size).
