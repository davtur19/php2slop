# PHP session-deserialization memory corruption under PIE + ASLR — public technique survey

Receipt: `/tmp/opencode/onlineresearch_1792633763`
Date: 2026-10-22
Scope: public sources only; no lab work, no repo writes, no PHPGGC/POP testing.

## Verdict

1. The bug class is public and current: **CVE-2026-109618 / CVE-2026-109619**, fixed 2026-10-21 in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. The session/decoder-specific bug is **619** (stale global state incl. `BG(unserialize)`, with `PS(id)` and `PS(http_session_vars)` as sibling stale pointers); **618** is the OOM/longjmp corruption that supplies the interruption.
2. **A served session file is not needed.** The public chains work in memory and in-band over HTTP.
3. Two dominant public patterns: **OOB read through a stale `zend_string`/`PS(id)` → `Set-Cookie` leak of heap + libphp/PIE base → `zif_system` fake HashTable/`execute_data`** (3em0), or **arbitrary read → ELF scan → `.gnu_hash` → GOT dump → fake `stdClass` handlers → `system`** (calif.io). Wiz reports the same leak+UAF combination on stock WordPress/Drupal/Joomla.
4. **PHP-FPM:** the vendor says the session-lifecycle RCE was validated on FPM, but there is **no public end-to-end FPM + PIE chain with offsets**. Leak and terminal primitives transfer; the producer differs because FPM kills the child on startup failure, so the fatal/OOM must occur during application execution.
5. **Defaults are favourable but not sufficient:** `upload_progress.enabled=1`, `serialize_handler=php`, `use_strict_mode=0`, `save_path=""` (not served). The cleanest libphp leak was calibrated with `display_errors=On` and `memory_limit=8M`; an OOM-in-cookie variant covers `display_errors=Off`, but the libphp stage needs recalibration.

## Contents

`REPORT.md` is organised as a primitive model (W = attacker session write, D = stale decode slot, F = served/leaked file), a 10-row leak matrix (L1–L10), a 9-row hijack matrix (H1–H9), session-logic/dead-end rows, notes on the highest-value rows, an explicit dead-end list, public-writeup survey, query coverage, 33 citations with HTTP status, and limitations.

`raw/` preserves every fetched artefact cited by the report: the 3em0 PoC/docs (`3em0_*`), calif.io write-up, Wiz/ikow/Sansec pages, vendor advisories, the UCR PDF used for the async/fiber discussion, and saved search result pages. `check.sh` re-verifies the presence/size of the raw set; `s.py` is the fetch/search driver used for the run.

## Caveats

* Raw search-engine pages are retained because search coverage is part of the method; they are not evidence of exploitability.
* Offsets quoted in the report are 3em0's build (`0x43a870`, `0x613c50`, `0x1504d0`, `0x21ef23`) and are **not portable**; every other build needs its own derivation.
* Partial code-pointer overwrite (H7) is explicitly inference, not a public PHP PoC; `zif_passthru` is not separately documented and is not claimed as verified here.
