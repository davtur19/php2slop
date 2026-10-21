# attribution_8510_8512.md — CVE-2026-109618 / CVE-2026-109619 fix attribution, PHP 8.5.10 → 8.5.12

Written 2026-10-21 (~19:45–19:55 UTC) from artifacts fetched in this directory
(see `status.txt`; script lines + `[MANUAL-curation]` lines). Confidence levels:
**CONFIRMED** = stated verbatim in a fetched official artifact (commit message,
NEWS, php.net changelog/announcement); **INFERRED** = our reasoning, marked as such.

## Official release record (fetched here)

- `archive_2026.html` (php.net news archive, fetched 19:52Z): "PHP 8.5.12,
  8.4.27, 8.3.36 and 8.2.35 fix two critical vulnerabilities that can allow
  unauthenticated remote code execution." — the official announcement; 9
  mentions of `CVE-2026-1096*` in the page.
- `changelog8.html` (php.net ChangeLog-8, fetched 17:42:56Z, wget-preserved
  remote Last-Modified 15:33Z): 8.5.12 section → "Core: Fixed
  GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via
  bailout)."
- `diff_c7273b9ba89c.patch` NEWS hunk (8.4→8.5 merge, i.e. the 8.5.12 release
  batch): "22 Oct 2026, PHP 8.5.12 — Core: Fixed GHSA-w8hw-w9fx-j79w,
  GHSA-6wmf-4rv5-p3rp (Avoid state corruption via bailout).
  (CVE-2026-109618, CVE-2026-109619) (Arnaud, ilutov, Jakub Zelenka, ndossche,
  Nicolas Grekas)"

→ **One fix commit covers BOTH CVEs**, filed under *Core* (not ext/session) in
NEWS/ChangeLog. CONFIRMED.

## The fix commit

Title: **"Avoid state corruption via bailout"**
Message body (verbatim, from `commit_3584a98bda0f.json` /
`commit_31c0ea7d7ff1.json`):

```
- Replace bailout on OOM with UnwindExit
- Properly reset various globals that may be accessed during startup

Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)

Co-authored-by: Ilija Tovilo <ilija.tovilo@me.com>
Co-authored-by: Jakub Zelenka <bukka@php.net>
Co-authored-by: Nora Dossche <...>
```

| branch / context | SHA | date (committer, UTC) | evidence |
|---|---|---|---|
| php-8.5.12 **tag** (shipped 8.5.12) | `31c0ea7d7ff1` | 2026-10-18T17:23:46Z | `compare_8510_8512.json` (php-8.5.10...php-8.5.12, ahead_by 480) lists it; parent `dd830558ffb1`; diff fetched as `diff_31c0ea7d7ff1.patch` (715852 B) |
| PHP-8.2 root of release-day merge chain | `3584a98bda0f` | 2026-10-21T14:06:22Z | `commits_session_c_85.json` + `commit_3584a98bda0f.json`; diff `diff_3584a98bda0f.patch` (661854 B, ~389 files) |
| merge 8.2→8.3 | `c1a5f468d09f` | 2026-10-21T14:12:35Z | `diff_c1a5f468d09f.patch` |
| merge 8.3→8.4 | `8a94bb3822b9` | 2026-10-21T14:27:03Z | `diff_8a94bb3822b9.patch` |
| merge 8.4→8.5 | `c7273b9ba89c` | 2026-10-21T14:30:04Z | `diff_c7273b9ba89c.patch` (contains the 8.5.12 NEWS hunk) |
| merge 8.5→8.6 | `d6373dfe150a` | 2026-10-21T14:33:23Z | `diff_d6373dfe150a.patch` |
| merge 8.6→master | `9705fda1bbb4` | 2026-10-21T14:34:56Z | `diff_9705fda1bbb4.patch` |
| NEWS entry (in tag) | `3d37ab3b8ee6` | 2026-10-18T17:23:47Z | compare list |
| version bump (in tag) | `136e049ac10b` "Update versions for PHP 8.5.12" | 2026-10-19T17:02:46Z | compare list |

Reading: the embargoed fix was committed to the release branches on 2026-10-18
(pre-staged; tags cut ~Oct 19 with the version bump), announced 2026-10-21
14:00Z; the Oct 21 14:06–14:35 merge chain (`3584a98bda0f` on PHP-8.2 and its
forward merges) is post-tag propagation to 8.3/8.4/8.5/8.6/master. The
Oct-21-merge copies and the tag copy carry the identical message.

## CVE → area/mechanism mapping

| CVE | GHSA | fix area | confidence |
|---|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | `Zend/zend_alloc.c` OOM handling: replace bailout with UnwindExit | commit-level **CONFIRMED** (message bullet 1 + NEWS order); hunk-level INFERRED |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | "Properly reset various globals that may be accessed during startup" — incl. `ext/session` rfc1867 progress guard + GINIT resets, `ext/standard/var_unserializer.re` + `php_incomplete_class.h` | commit-level **CONFIRMED** (message bullet 2 + NEWS); hunk-level INFERRED |

Commit-level confidence is CONFIRMED because the commit message names both
GHSAs→CVEs and NEWS/ChangeLog repeat the same pairing. The per-CVE split into
the two message bullets follows the message's own bullet order
(w8hw→109618 first, 6wmf→109619 second) — INFERRED at hunk granularity.

### CVE-2026-109618 mechanics (from `diff_3584a98bda0f.patch`, Zend/zend_alloc.c)

Old code (removed):

```c
static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(...)
	heap->overflow = 1;
	zend_try {
		zend_error_noreturn(E_ERROR, ...);   /* E_ERROR => bailout longjmp */
	} zend_catch {
	} zend_end_try();
	heap->overflow = 0;
	zend_bailout();
	exit(1);
```

New code (added):

- `zend_mm_delayed_verror()` — soft-limit OOM no longer unwinds inline: it
  stores `EG(delayed_oom).{message,filename,lineno}` with
  `ZEND_OOM_STATE_PENDING` and sets `EG(vm_interrupt)` (**delayed soft OOM**),
  so the VM aborts at a safe point instead of longjmp-ing mid-initialization.
- `zend_mm_hard_limit_error()` — hard limit prints to stderr and calls
  **`_exit(137)`** (no unwinding at all). Matches the pre-advisory prediction
  "delayed soft OOM + hard OOM _exit()".
- `zend_mm_check_limit()` with `heap->fallible` / `hard_limit` /
  `zend_mm_max_allocs_reached`; `zend_throw_unwind_exit()` used as the
  non-bailout unwind path (`Zend/zend_exceptions.c`: "An exception may already
  be in flight, and zend_throw_unwind_exit()..."; unwind-exit now also honored
  when comparing/add-ing previous exceptions); `ext/standard/assert.c` and
  `ext/zend_test/test.c` adapted.
- New tests: `tests/basic/oom_rfc1867_*.phpt` (13 files incl.
  `oom_rfc1867_upload_progress.phpt`, `oom_rfc1867_session_skipif.inc`),
  `ext/date/tests/oom_*.phpt`, `ext/standard` oom tests — multipart
  upload-progress under OOM is exactly the regression surface.

### CVE-2026-109619 mechanics (from the same patch, ext/session + decoder)

- `ext/session/php_session.h`: new `bool in_rfc1867_update; /* php_session_rfc1867_update() is running */` in `ps_globals`.
- `ext/session/session.c`: GINIT resets it (`ps_globals->in_rfc1867_update = false;` next to `ps_globals->serializer = NULL;`), re-entrancy guards `if (PS(in_rfc1867_update))` in the rfc1867 update/callback paths, set/clear around the update body.
- Decoder-adjacent: `ext/standard/var_unserializer.re` + `ext/standard/php_incomplete_class.h` changed, with tests `ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt`, `rfc1867_no_user_code.phpt`, `rfc1867_sid_invalid.phpt` — the "stale machinery state consumed via decode" surface.
- The 300+ file breadth of the commit is the "reset various globals ... during startup" bullet: GINIT/`-D`-style resets across many extensions' globals (246 files under `ext/`, 96 under `Zend/`, 7 under `main/` incl. `main/rfc1867.c` and `main/streams/memory.c`).

## Negative / partial findings (do not over-claim)

- `https://www.php.net/releases/8.5.11.php` and `/releases/8.5.12.php` do not
  exist as pages: both **302 → `search.php?show=404quickref&...`** (probed
  19:52Z, `[MANUAL-curation]` lines in `status.txt`). The fetch script's
  `release_8.5.11.html` target was stale → its FETCH_FAIL is a wrong-target
  404, not a network outage. php.net's official record for this security
  release here = `changelog8.html` + `archive_2026.html`.
- 8.5.11 (released 24 Sep 2026 per changelog) does **not** contain this fix:
  compare base is `php-8.5.10...php-8.5.12` and the fix commits are dated
  Oct 18/19; the 8.5.11 changelog section holds unrelated fixes (incl.
  CVE-2026-91768 FPM ACL bypass).
- `751190d8e042` "ext/session: do not reuse session state a save handler tore
  down" (2026-10-13) is on the current PHP-8.5 branch tip
  (`commits_session_c_85.json`) but **not** in php-8.5.12 (absent from the
  compare) → post-release work, unrelated to this advisory.
- 8.5.12's `Session:` changelog section lists only "session_start()
  continuing after a failed create_sid() when session.use_strict_mode rejects
  the supplied ID" (Sep 23 commits `4868dd4e0205`/`eacd1576adb5`) — the CVE
  fix is filed under Core.
- `tags.json` (per_page=10) captured only old tags; php-8.5.12 tag evidence
  comes from the compare endpoint instead.
- `compare_8510_8512.json` reports `behind_by=1` (one php-8.5.10 commit not in
  8.5.12) — not investigated further.
