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
