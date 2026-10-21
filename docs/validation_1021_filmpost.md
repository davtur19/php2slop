# Validation 2026-10-21 — corrected-article, independent receipts (no article trust)

## Stock fpm 8.5.10 (realapps lab)
- diag3: arm with memory_limit=8M -> `Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in Unknown on line 0` during *Request Startup* (pre-RINIT). Mechanism class reproduced.
- diag4: arm x3 IDENTICAL response (sha12 561043a1e978, alloc 266240, zero corruption markers). Worker survived all 3 -> article's SAPI-matrix row "fpm exits at R1" is FALSE on our 8.5.10 fpm.

## ASAN php -S 8.5.10 (same-stack, built-in server)
Run alloc_malloc (USE_ZEND_ALLOC=0): no OOM (memory_limit inert), machinery benign x3.
Run alloc_mm (USE_ZEND_ALLOC=1):
    R1: 200 OK len=459 oom=True (facility fatal workload)
    R2: 200 OK len=313 oom=True  <-- body DIVERGED: serialize context polluted between requests
    R3: process death + AddressSanitizer SEGV 0x14a at
        tmp_var ext/standard/var_unserializer.c:168 <- var_tmp_var <- ps_srlzr_decode_php ext/session/session.c:1123
        <- php_hash_environment main/php_variables.c:794 -> zend_activate_auto_globals -> php_request_startup main/main.c:1942
Cross-request serializer-state corruption family: CONFIRMED on our build, earned, not trusted.

## Source fact-check vs page (our tree, 8.5.10)
- var.c:756 `data->n += 1` — exact
- basic_functions.c:391-393 RINIT(basic) memsets BG(serialize)/BG(unserialize) — exact
- var.c:1346 php_var_serialize_init reuses BG(serialize).data when level!=0 — exact
- session.c:3154 Z_TRY_ADDREF(progress->data) (page said 3213 @8.5.4, 59-line drift) — cached-chain classification consistent
- php_request_startup order: zend_activate -> sapi_activate (machinery/POST read HERE) -> ... -> hash_environment -> zend_activate_modules(RINIT) — machinery runs pre-RINIT; fatal in machinery leaves BG(serialize) dirty+arena-freed context for the next heavy request.

Artifacts: harnesses/runs/{diag3_arm_oom.py,diag4_repeat_arm.py,diag5_asan.py,diag5run.sh}

## PHP 7.4.33 parity (php7lab, ASAN build, built-in server :28843)
- Source guard parity: php_var_serialize_init reuse guard var.c:1139-1158 (same shape as 8.5.10:1346); Z_TRY_ADDREF progress->data at session.c:3151 (8.5.10:3154).
- Behavior: arm + memory_limit=8M → silent close ×3 (no fatal body, no ASAN crash), dispatcher wedged (post-check EMPTY). Same arm at 64M → 200 OK ×3 clean. OOM trigger = arm body machinery traffic, not filename length.
- Contrast 8.5.10: R1 fatal body → R2 diverged body → R3 process death (SEGV var_unserializer decode).

## gdb ground truth (diag9/diag10, 8.5.10 ASAN php -S, breakpoints var.c:1352/1359/1367)
- Clean save_path, arm x3: ALWAYS exactly one FRESH + one DESTROY per request, same d address, zero REUSE, bodies identical (313B fatal), no crash even when the on-disk session file exists after R1.
- diag5's divergence (459→313) + SEGV replay: caused by the on-disk state LEFTOVER — the alloc_malloc run (memory_limit inert) had completed a full machinery record flush to /tmp; the alloc_mm run re-READ that file (ps_srlzr_decode_php) → different serialization trajectory → SEGV. It is disk-session-state poisoning, NOT a pure-OOM BG-context UAF.
- Realapps/stock fpm worker: survives all repeats (diag4), no reuse.
⇒ corrected-article mechanism needs an ATTACKER-CONTROLLED session record on disk, not only the OOM arm. The poisoned-record family (fuzz seed receipt at session.c:3155) is the operative substrate.

## PHP 5.6.40 parity (php5lab ASAN, builtin :28844)
- Guard parity via MACRO level-sharing: PHP_VAR_SERIALIZE_INIT (php_var.h:55/73) shares var_hash while level>0 & unlocked; no php_var_serialize_init fn; php_var_serialize itself has NO re-entry lock; Z_TRY_ADDREF absent (record via ZEND_SET_SYMBOL_WITH_LENGTH refcount=2, session.c:2649).
- USE_ZEND_ALLOC=0 disables memory_limit in 5.6 (control-tested) — ASAN/malloc batteries inert to the arm.
- Deterministic wedge battery (record 4,984,736B on disk, same arm x3): run1 OOM inside machinery in php_request_startup, leaked flock-locked session fd; run2 self-deadlocks flock(LOCK_EX) ps_files_open:171 <- ps_read_files:369 <- php_session_initialize:507 <- rfc1867_update:2645 <- ... php_request_startup:1685; run3 unserviced. Worker permanently wedged, sess file byte-identical. Reproduced ×3 (gdb-resolved receipt).
- Empty-baseline battery C: deterministic per-request OOM death 327B cap, no poison.
⇒ cross-version: family fences differ by SAPI/allocator but disk-session-record state + arm machinery OOM/bail leak produces deterministic cross-request wedging on 5.6; on 8.5 the analogous window is the decode-path state (diag5/6)... the planted-record substrate is the card to play for RCE.
