# PHP 5.6.40 — upload_progress machinery / serializer-state UAF family: independent replication

Date: 2026-10-21 · Lab: /tmp/opencode/php5lab · Rules honored: user-space only, no sudo, no system
services, loopback 127.0.0.1:28844 only, no git commits, no credentials involved.

## 1) Build

- Source: https://museum.php.net/php5/php-5.6.40.tar.gz → /tmp/opencode/php5lab/php-5.6.40
- Status: **ASAN build OK** (`sapi/cli/php` reports `PHP 5.6.40 (cli) (built: Oct 21 2026 15:25:19)`, ASAN linked).
- Configure: `CFLAGS="-g -O1 -fsanitize=address -fcommon" LDFLAGS="-fsanitize=address" ./configure
  --disable-all --enable-cli --enable-session --disable-cgi --without-pear`
- gcc 14.2 compile-only patches (ALL compile-only; no runtime semantics changed):
  1. `ext/session/session.c:867` — `php_var_unserialize(&session_vars, &val, endptr, …)`: added
     `(const unsigned char **)` casts (gcc14 hard-error on incompatible pointer; char* vs uchar* is a no-op reinterpret).
  2. `main/php_config.h:1276` — undef'd `HAVE_OLD_READDIR_R` (bogus autoconf detection of 2-arg readdir_r
     on modern glibc; POSIX branch selected, identical normal-distro behavior).
  3. `main/streams/cast.c:124-128` — `stream_cookie_seeker(void *cookie, off_t *position, int whence)`:
     glibc's modern cookie-io seek prototype passes a pointer; kept intended value semantics by a single
     `*position` deref (`php_stream_seek(cookie, *position, whence)`). Not on the exercised paths.
- Both alloc batteries ran on this one ASAN binary with `USE_ZEND_ALLOC=0/1`.

## 2) Serializer-state guard inventory (line numbers) + verdict

Greps on 5.6.40 sources:

- `php_var_serialize_init` in `ext/standard/var.c`: **0 matches — absent.** The state guard lives in the
  macro `PHP_VAR_SERIALIZE_INIT`, `ext/standard/php_var.h:55` (and its DESTROY pair :73):
  ```c
  if (BG(serialize_lock) || !BG(serialize).level) { /* ALLOCATE new HashTable var_hash … */
      if (!BG(serialize_lock)) { BG(serialize).var_hash = …; BG(serialize).level = 1; }
  } else { /* SHARE the BG(serialize).var_hash … */ ++BG(serialize).level; }
  ```
- Level/lock fields: `ext/standard/basic_functions.h:207-215` — `BG(serialize_lock)`,
  `BG(serialize){var_hash, level}`, `BG(unserialize){var_hash, level}`.
- `BG(serialize_lock)` usage: `ext/standard/var.c:799,801` (only around the `__sleep` user callback) and
  `ext/standard/var_unserializer.c:207,212,717,719,727,747,749,763,775,783` (only around unserialize-side user
  handlers `__wakeup`/`__destruct` etc.). NO lock anywhere else.
- Re-entry check: `php_var_serialize` wrapper, `ext/standard/var.c:903` — **no lock/level test at all**;
  array recursion is fenced only by `nApplyCount` (var.c:848-872), object recursion only by `__sleep` call sites.
- Session write path: default "php" serializer `PS_SERIALIZER_ENCODE_FUNC(php_serialize)`,
  `ext/session/session.c:844-858`: `php_var_serialize(&buf, &PS(http_session_vars), …)` at **session.c:848**.
- Session rfc1867 machinery: callback at **session.c:2664** (`php_session_rfc1867_callback`);
  record insertion `ZEND_SET_SYMBOL_WITH_LENGTH(Z_ARRVAL_P(PS(http_session_vars)), progress->key.c, …,
  progress->data, 2, 0)` at **session.c:2649** (refcount hand-adjusted by macro, `Zend/zend_API.h:717`);
  per-event flush via `php_session_rfc1867_update` (session.c:2624, called at 2645 by stack) →
  `php_session_flush`/encode on EVERY multipart event (session.c:2651, 2661, and file events :2782).
- `Z_TRY_ADDREF` in `ext/session/session.c`: **0 matches** (5.6 uses the zval** occurrence model — `Z_ADDREF`,
  refcount by hand at insertion). `zend_hash_update` in `ext/session/session.c`: **0 matches**
  (insertion goes through the ZEND_SET_SYMBOL macro; look-up path uses `zend_symtable_find`, session.c:2612).

**Verdict (guard parity): NOT de-fenced, but differently fenced.** PHP 5.6.40 *does* have a level-based
reuse guard — but only inside the INIT/DESTROY macro pair (php_var.h:55/:86): a nested `PHP_VAR_SERIALIZE_INIT`
while `level>0` and unlocked **shares** the previous call's var_hash (and its `level` counter is request-global,
not bound to a frame). 5.6 lacks (a) any re-entry lock inside `php_var_serialize` itself (7.x/8.x added a hard
`BG(serialize_lock)` in the serializer frame), (b) any refcount-shield on the session-vars path (no Z_TRY_ADDREF;
insertion via ZEND_SET_SYMBOL_WITH_LENGTH with hand-set refcount 2 at session.c:2649). So on 5 the machinery is
**weaker-fenced than 8.5**, with the rfc1867 callback driving repeated full-session serializations in one request.

## 3) Server + arm receipt batteries (same arm ×3, sid "abcdefgh", port 28844)

Server per battery: `php-5.6.40/sapi/cli/php -S 127.0.0.1:28844 -d memory_limit=8M
-d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0
-d session.save_path=/tmp/opencode/php5lab/sess -t /tmp/opencode/php5lab/root`.
Arm = stock arm (20 file parts, filename F*262144 rest, F*9 first; PHPSESSID form field; USP field "MMM"),
framing identical to the 8.5 reference diag (Basic user len 23, keep-alive, no Cookie), body 4,983,575 B.
Raw-read only, status+len printed per run. ASAN_OPTIONS=…:log_path=/tmp/opencode/php5lab/logs/asanf.

| Battery | alloc | sess baseline | run1 | run2 | run3 | divergence | server end-state |
|---|---|---|---|---|---|---|---|
| A | USE_ZEND_ALLOC=0 | empty | 200 OK, 136B, EOF | identical | identical | **no** | healthy; worker S/do_select |
| B | USE_ZEND_ALLOC=1 | full frozen 4,984,736B (from A) | 0B, EOF=true, OOM receipt | 0B, **EOF=false, 75s no close** | never served (worker wedged) | **YES** | **permanently wedged** (flock) |
| C | USE_ZEND_ALLOC=1 | empty | 0B, EOF=true, OOM | identical | identical | no (deterministic death ×3) | healthy; sess 327B partial record |
| D | USE_ZEND_ALLOC=0 | empty | 200 OK, 136B | identical | identical | no | healthy; sess full frozen 4,984,736B |
| B2 | USE_ZEND_ALLOC=1 | full frozen 4,984,736B | 0B, EOF=true, OOM | 0B, **EOF=false, wedge** | never served | **YES** | **permanently wedged** (flock) |
| B3 | USE_ZEND_ALLOC=1 | full frozen 4,984,736B | 0B, EOF=true, OOM | 0B, wedge (repro) | not needed | **YES (repro of B2)** | wedged capture + gdb bt |

- Sess file end-states: A/D = 4,984,736 B (`upload_progress_MMM|a:5:{…}` full record incl. all 20 F-names,
  `done` flags, cleanup=0 → record survives request end **and is reloaded by every repeat**).
- C freezes a 327 B partial record (F*9 file only) — every repeat then OOMs at the same point.
- OOM receipt (mm batteries, one per arm request): `Allowed memory size of 8388608 bytes exhausted
  (tried to allocate 262145 bytes)` — 262145 = one F*262144 name + NUL, i.e. the allocation belongs to the
  upload_progress record content being serialized/written. On battery C the wording is deterministic ×3.
- Log-attribution quirk (receipted in B, C, B2, B3 logs): an arm request that died in `php_request_startup`
  gets **no per-request log line**; its OOM text is appended to the *next* request's line (the z-probe GET).
- Control test (receipted): `USE_ZEND_ALLOC=0` **disables memory_limit enforcement** on 5.6 (16 MB succeeds
  under `-d memory_limit=1M`); mm mode enforces → this is exactly why malloc batteries are OOM-free.

## 4) Divergence/death receipts (the family's frozen-profile behavior on 5.6)

**Battery B/B2/B3 = the serialize-context reuse receipt, reproduced ×3 (B: once, B2: once, B3: gdb-resolved):**

- run1 (identical arm, frozen 4,984,736B record loaded): memory-limit fatal inside the machinery while the
  request is still in `php_request_startup` (POST body parse / rfc1867). Worker SURVIVES, connection closes
  clean (0 bytes, EOF=true), **but the request-state teardown never reached `ps_files_close`
  (ext/session/mod_files.c:110-118: `flock(LOCK_UN); close(); data->fd = -1`)** — the locked session-file fd leaks.
- run2 (byte-identical arm): new `ps_files_open` does `flock(data->fd, LOCK_EX)` (mod_files.c:171, blocking,
  NOT LOCK_NB) on the same inode. flock is not owner-affine across fds → **the worker blocks itself forever**:
  the single-request cli-server does not even finish `php_request_startup` ($_POST auto-global materialization),
  so EVERY later connection (incl. all probes) hangs. Receipts: `State: S (sleeping)`,
  `wchan: locks_lock_inode_wait`, `syscall: 73 0x6 0x2 …` (flock, fd=6, LOCK_EX blocking), client sees
  0 bytes with EOF=false. gdb backtrace captured (crashes/b3-wedged-worker-gdb-bt.txt):
  `flock ← ps_files_open:171 ← ps_read_files:369 ← php_session_initialize:507 ← php_session_rfc1867_update:2645
  ← php_session_rfc1867_callback:2782 ← rfc1867_post_handler:981 ← sapi_handle_post:185 ← … ← php_request_startup:1685`.
- run3: never served.
- sess file untouched throughout the wedge (4,984,736 B, mtime frozen): the machinery's record survives request
  end on disk, and — the 5.6 twist of this family — the machinery's **lock state** survives the bailed-out request
  and freezes the next identical request.

**Hypothesis (explicitly tagged):** the exact frame that skipped `ps_files_close` in run1 is the request-startup
bailout longjmping U past module RSHUTDOWNs (the wedge stack proves run2 is still in php_request_startup, and the
wedged flock proves no clean close ran); the precise skipped frame was not separately captured (no RSHUTDOWN trace).
The measured alternative explanation — battery C's fatal lands *after* the first small successful record write and
unwinds cleanly each time (sess 327B, fd released, no wedge) — confirms that it is the **full-profile fatal timing
(pre-write, startup phase)** that poisons the state, not the OOM per se.

**ASAN: zero reports in all six batteries (both alloc modes).** In malloc mode the arm engages the machinery with
no memory-limit and completes deterministically clean (3× identical 136B 200s, worker healthy, full frozen record
written); no UAF reported by ASAN on these paths.

## 5) Family-level characterization on 5.6.40

1. The stock arm (20 × F*262144 names) fully engages the machinery on 5.6: per-event session flush serializes the
   whole record; with mm + 8M cap this reaches the deterministic OOM point at ~file#5 (C: identical ×3, 0-byte
   death per request but worker survives) — request-level death receipts, no divergence.
2. With a **preloaded full frozen profile** (exactly the A/D outcome of the same stock arm), the SAME arm request
   instead diverges on repeats: run1 = OOM-leaves-poisoned-session-lock; run2 = permanent worker wedge in
   `flock(LOCK_EX)`; run3 = never served. Three repeats ⇒ two different outcomes ⇒ serialize-context-reuse receipt.
3. malloc mode (ASAN-visible allocations, no memory_limit): the same arm is fully deterministic 3× identical 200s,
   no ASAN fault — the 5.6 machinery does not UAF-fault under this arm with unlimited accounting.
4. Guard parity: 5.6 *has* the level/lock fields of the 8.5 world but *not* the 8.x fencing shape: no re-entry lock
   in `php_var_serialize` (var.c:903), macro-level-only var_hash sharing, no refcount shield on the
   session-insert path (Z_TRY_ADDREF absent), record inserted by hand at refcount 2 (session.c:2649).
   In short: **the family is not de-fenced on 5, but its fences are macro-level and weaker than 8.x's.**

## 6) Artifacts

- /tmp/opencode/php5lab/crashes/b3-wedged-worker-gdb-bt.txt — wedge stack + /proc receipts (primary crash artifact)
- /tmp/opencode/php5lab/crashes/asan-phps56*.log — server logs per battery (A, B, B2, B3, C, D)
- /tmp/opencode/php5lab/crashes/result.json — battery result snippets; /tmp/opencode/php5lab/logs/asan-phps56*.log mirrored
- /tmp/opencode/php5lab/runs/diag56_asan.py, diag56v2_asan.py — runners (arm ×3, raw-read receipts)
- /tmp/opencode/php5lab/runs/diag5656run.sh, diag5656v2run.sh, diag5656cd.sh, diag5656b2.sh, diag5656b3.sh — batteries
- /tmp/opencode/php5lab/runs/diag56/, /tmp/opencode/php5lab/runs/diag56v2/ — raw request + per-run artifacts/result.json
- /tmp/opencode/php5lab/php-5.6.40/ — ASAN build with 3 compile-only patches
- /tmp/opencode/php5lab/logs/*.log — configure/make logs (config.log, make*.log), ASAN log prefix asanf (never written — zero ASAN reports)
