# phpshell — php 8.5.x session.upload_progress / OOM RCE lab toolkit

Independent research toolkit for the **PHP October 2026 security release**:
**CVE-2026-109618 / CVE-2026-109619** — pre-auth cross-request machinery
use-after-free family (php-src `ext/session` upload-progress machinery +
ZendMM OOM interruption; `ext/session/session.c:3129–3338` window).

All experiments run on operator-owned stacks against loopback targets
(nginx → MediaWiki 1.46.2 / WordPress on stock-build php 8.5.10 fpm/cgi).

**Upstream write-up:** <https://calif.io/php2shell/> (alias: <http://php2shell.com>) —
*A tale of two PHP remote vulnerabilities*, Calif / OpenAI / Wiz.

**Official advisories (published 2026-10-21 14:00 UTC):**

- CVE-2026-109618 — [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — RCE via OOM corruption
- CVE-2026-109619 — [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — RCE via stale global state

**Patched in:** PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (release announcement:
<https://www.php.net/archive/2026.php#2026-10-21-5>).

## Status — both CVE classes found and reproduced independently

The receipts below were produced on our own trees/binaries/victim apps
**before** the advisories published; the GHSA technical pages then confirmed
the same mechanisms line-by-line.

| CVE | Mechanism | Our independent receipt |
|---|---|---|
| **CVE-2026-109618** OOM corruption | OOM `longjmp()` exits a mid-initialization context; teardown then consumes partially-initialized request state (count-before-key-alloc pattern in hash registration; machinery record torn down early) | `diag3`: arm reaches `Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in Unknown on line 0` **during Request Startup** (pre-RINIT) on *stock* php-fpm 8.5.10 behind nginx, unauthenticated; offline fuzzing: deterministic ASAN heap-UAF at `php_session_rfc1867_update` (`session.c:3155` → `zend_hash.c:872` pDestructor) reproduced 5/5 + 2 reduced repros with planted state (`fuzzing/crashes/`); multipart empty-file-control shape (six `$_FILES` entries per record, not counted by `max_file_uploads`) |
| **CVE-2026-109619** stale global state | Request-owned state published in worker globals survives the heap free; the next request consumes it *before* normal initialization resets it. Confirmed consumers: pre-init INI diagnostics and **session upload-progress** | `diag5`: ASAN built-in server — R1 OOM fatal → R2 divergent body → R3 process death with SEGV at `tmp_var` (`var_unserializer.c:168`) ← `var_tmp_var` ← `ps_srlzr_decode_php` (`session.c:1123`) ← auto-globals → `php_hash_environment` → `php_request_startup` — the stale-state consumer firing pre-RINIT; `diag9/10` gdb ground truth (macro-free FRESH/REUSE/DESTROY breakpoints); php 5.6.40 flock self-deadlock wedge (stale fd/machinery state) |

**SAPI note (matches the official matrix):** on *stock* fpm a pre-RINIT
startup fatal exits the child — `diag4` repeats come back *identical* because
the pool respawns a fresh worker each time. The FPM-exploitable sequence
requires the fatal **after successful startup** (application level), then the
upload-progress consumer on the surviving worker — exactly the validated FPM
path in GHSA-6wmf-4rv5-p3rp ("session upload progress … consumer … does not
require a diagnostic", "no application call to session_start() is required").
Victim-app surface is unchanged and stock: the decode entry points are
application-reachable ops (`session_start()` in MediaWiki,
`maybe_unserialize()` in WordPress).

## Cross-version parity (our own builds)

- **php 8.5.10** — primary lab target (nginx → fpm stock + separate ASAN build for receipts).
- **php 7.4.33** — `php_var_serialize_init` level-guard parity (`var.c:1139–1158`), `Z_TRY_ADDREF` at `session.c:3151`; machinery-OOM = silent close + dispatcher wedge on the built-in server (see `php7lab_receipts/`).
- **php 5.6.40** — guard via macro level-sharing (`PHP_VAR_SERIALIZE_INIT`, `php_var.h:55/73`); no `Z_TRY_ADDREF` (record via `ZEND_SET_SYMBOL_WITH_LENGTH`, refcount hand-set); deterministic **flock self-deadlock wedge** with a full disk session record + arm (gdb-resolved stack, `php5lab_receipts/`); `USE_ZEND_ALLOC=0` disables `memory_limit` in 5.6 (control-tested).
- The upstream "PHP >= 5.4.0" affected range is consistent with these parity findings.

## Layout

- `php2shell/` — exploit driver (`php2shell.py`) + helper modules:
  `native-output-leak.py` (LEAK probe/raw framing), `native-output-leak-stock-arm.py`
  (STOCK arm), `compact-stock-tail.py` (COMPACT rearm/final forged multipart);
  diag harnesses `diag_arm_probe.py`, `diag2_arm_probe_rearm_final.py`.
- `harnesses/runs/` — diag3…diag10 scripts: `diag3_arm_oom.py`, `diag4_repeat_arm.py`,
  `diag5_asan.py`/`diag5run.sh`, gdb breakpoint cmd files (`diag9_gdb.cmd`, macro-free
  FRESH/REUSE/DESTROY at `var.c:1352/1359/1367`), clean-start replay (`diag10_run.sh`),
  filtered gdb event traces.
- `fuzzing/` — offline CGI-SAPI fuzzing + deterministic UAF crashes
  (`crashes/reduce_min_progress_file/`, `crashes/reduce_min_progress_only/`, …),
  plus `fuzz_findings.md`.
- `universal/` — freeze battery + per-binary PROFILE builder and run captures.
- `addresses/` — per-binary symbol/offset profiles (incl. `generated/`).
- `php5lab_receipts/`, `php7lab_receipts/` — cross-version lab results.
- `docs/validation_1021_filmpost.md` — dated validation log (diag3–diag10,
  gdb ground truth, advisory analysis).
- `advisory_1400/` — embargo-gated one-shot fetcher + fetched advisory artifacts summary.
- `reports_realapps_validation_1021.md` — master validation report.
- Root — staged PoC shape builders, build scripts, gdb scripts, trigger-experiment
  logs, per-ASAN-flavor run logs.

## Reproduce (receipt commands)

Built-in server ASAN receipt (diag5 family):

```sh
USE_ZEND_ALLOC=1 ASAN_OPTIONS=abort_on_error=0:exitcode=21:malloc_context_size=10 \
  build_asan/sapi/cli/php -S 127.0.0.1:28842 -d memory_limit=8M \
  -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0 \
  -t <docroot>
# then send the STOCK arm multipart 3× (runs/diag5run.sh) and watch
# R1 OOM fatal → R2 divergent body → R3 death w/ SEGV in the decode path
```

gdb ground truth (state lifecycle):

```sh
gdb -q -batch -x harnesses/runs/diag9_gdb.cmd --args build_asan/sapi/cli/php -S 127.0.0.1:28846 ...
# [FRESH]/[REUSE]/[DESTROY] events per request; clean repeats stay balanced
```

## Mitigations (official, from the GHSAs)

- **Patch** to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 — the only complete fix
  (soft-OOM at VM safe points + immediate hard-OOM `_exit()`, full global
  state reset at request shutdown).
- Until then, partial: administratively enforce `memory_limit=-1`;
  `session.upload_progress.enabled=0` (worker restart required, admin scope);
  low `post_max_size`; PHP 8.5 `fatal_error_backtraces=0`; frontend size
  enforcement (incl. requests without usable `Content-Length`); cgroup
  `memory.max` for availability. Do **not** use `RLIMIT_AS`/`RLIMIT_DATA`
  (they trigger the vulnerable `mmap()`-failure path).

## Safety

Lab security research. Targets are operator-owned; tests are loopback-only.
Excludes third-party bundles (`zer061`, `jpack`) by design.

---

## Historical log

### 2026-10-21 — independent verification of community corrected-findings (jackalsyn page)
Treated as lead, not truth. Fact-check on our 8.5.10 tree: var.c:756 / basic_functions.c:391-393 / var.c:1346 level-guard / session.c:3154 addref — all verbatim. Reproduced ourselves (diag3-5, see docs/validation_1021_filmpost.md): arm OOM pre-RINIT on stock fpm, and on ASAN built-in server: R1 OOM → R2 diverged body → R3 death with SEGV in var_unserializer via session decode at php_hash_environment → php_request_startup.

### 2026-10-21 — gdb ground truth (diag9/10)
No BG(serialize) reuse on clean repeats; diag5 divergence/SEGV = disk session-record leftover between run modes; decoded via ps_srlzr_decode_php. Family requires attacker-controlled session record on disk (later superseded by the advisory's producer/consumer model).

### 2026-10-21 — official advisory analysis
Advisories (14:00Z) + upstream write-up mapped 1:1 onto our receipts: 109618 = OOM corruption (diag3/fuzz UAF/empty-file shapes); 109619 = stale global state with session upload-progress as confirmed producer *and* consumer pre-init (diag5 decode-path SEGV; php5.6 flock wedge). Full details: `docs/validation_1021_filmpost.md`.
