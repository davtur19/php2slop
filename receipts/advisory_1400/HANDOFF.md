# HANDOFF: advisory_1400 fetcher (one-shot, embargo-gated, idempotent)

Context: CVE-2026-109618 / CVE-2026-109619 (php-src 8.5.x session
upload-progress UAF family) publish 14:00:00 UTC today, 2026-10-21.
Two previous sleeping fetcher instances died at session teardown ("Killed by
SIGTERM"; children of a subagent session die when that session closes), so a
sleeping process must NOT be spawned from a subagent. The fetcher is therefore
a ONE-SHOT script: the operator session launches it at/after 14:00Z.

## Script used
`/tmp/opencode/realapps/side/fetch_advisory_1400.sh` (rewritten in place;
the old sleep-based version is gone). Executable, `bash -n` clean.

## Exact one-shot command (run from the OPERATOR session, any time >= 14:00:00Z)
```
bash /tmp/opencode/realapps/side/fetch_advisory_1400.sh
```
- Optionally pass an outdir: `bash .../fetch_advisory_1400.sh /some/dir`
- Safe to run repeatedly: existing non-empty artifacts are skipped and logged
  as `skipped`; successful fetches append sha256 to `manifest.sha256`
  (verify later with `cd advisory_1400 && sha256sum -c manifest.sha256`).
- Every action goes to `advisory_1400/status.txt` with UTC timestamps.
- Network failures are logged (`FETCH_FAIL ...`) and never fatal; no `set -e`.
- PARTIAL artifacts are removed on failure so a rerun retries cleanly.
- Final exit code 0 even with partial failures (fail count is in the log).

## Embargo guard (tested live, twice: both runs stamped 2026-10-21T11:22:58Z)
If `date -u` is before 2026-10-21T14:00:00Z the script logs
`BEFORE_EMBARGO now=... < 2026-10-21T14:00:00Z; nothing fetched, exiting 0`
and exits 0 WITHOUT any network activity. Verified pre-14:00 ("access test"):
two consecutive runs, exit 0 both times, only `status.txt` written,
zero fetches. `status.txt` currently holds exactly these two `BEFORE_EMBARGO`
lines; before the real run you can truncate it if you want a clean log.

## Optional detached awake-at-14:00 launcher
Only from the operator session (NOT a subagent; its children get SIGTERMed
when the session closes). The sleep is computed at invocation time:
```
d=$(( $(date -u -d '2026-10-21 14:00:00' +%s) - $(date -u +%s) )); \
  [ "$d" -lt 0 ] && d=0; \
  setsid nohup bash -c "sleep $d; bash /tmp/opencode/realapps/side/fetch_advisory_1400.sh" \
  >/dev/null 2>&1 & echo "detached launcher pid=$!"
```
`setsid` detaches it from the caller's process group; it sleeps `$d` seconds,
then the one-shot runs (which is a no-op if its gate is hit early, and is
idempotent if run twice).

## What it fetches post-gate (all into /tmp/opencode/realapps/side/advisory_1400/)
1. `https://www.php.net/releases/8.5.11.php` -> `release_8.5.11.html`
2. `https://www.php.net/ChangeLog-8.php` -> `changelog8.html`
3. GitHub API: `commits_session_c.json` (main branch),
   `commits_session_c_85.json` (PHP-8.5 branch), `tags.json`
4. `diff_<sha12>.patch` for up to 8 session.c commits with committer date
   >= 2026-10-21T11:45:00Z (the monitoring cutoff), fetched from
   `https://github.com/php/php-src/commit/<sha>.diff`
5. `tarball_urls.txt`: location record for the 8.5.11 source tarball
   (`php-8.5.11.tar.gz` / `.tar.xz` distributions URLs); ONE HEAD probe confirms
   availability; the tarball itself is NOT downloaded
6. `commits_summary.txt`: local parse of the commit JSONs, no network

## analyze_advisory.py state (offline dry-runs done)
- `py_compile` OK (`python3 -m py_compile`).
- Fixture dir: `/tmp/opencode/realapps/side/tmp/analyze_dryrun/`
  - `base_pre/` (rate-limit-dict file + pre-cutoff entries + empty list)
    -> run: `run_pre.log`, "not a list (maybe rate-limited or empty)" and
    "NO post-cutoff session.c commits found", rc=0.
  - `base_post/` (a post-cutoff entry with EMPTY message, a real post-cutoff
    entry, a pre-cutoff entry) -> driver `driver_post.py` monkeypatches
    `gh()` with a fake diff (NO network) -> run: `run_post_after.log`, rc=0:
    2 post-cutoff commits listed, fake diffs saved as `diff_<sha>.patch`,
    keyword highlight filter surfaced SEPARATE_ARRAY / zval_ptr_dtor /
    add_next_index_zval / bytes_processed lines, and the "3151" message
    marker `<touches SEPARATE_ARRAY(sess_var)>` fired.
  - `run_post_before.log` documents the UNFIXED analyzer crashing with
    `IndexError at line 65` on an empty commit message (reference evidence).
- Fixes applied to `/tmp/opencode/realapps/side/analyze_advisory.py`:
  1. empty `commit.message` no longer crashes (`.splitlines()[0]` -> guard);
  2. malformed `Accept: application/vnd.github/vnd.github+json` ->
     `application/vnd.github.v3+json`;
  3. `gh()` per-commit diff fetch wrapped in try/except: FETCH_FAIL logged,
     loop continues (no single-commit network error kills the run).
  Python here is 3.13.5: `fromisoformat` already parses GitHub's `Z` dates,
  so no extra date normalization was added.

## php.net reachability probe (single, generic, pre-embargo; permitted)
```
curl -s -o /dev/null -m 15 -A '<fetcher UA>' -w 'HTTP=%{http_code} ip=%{remote_ip} dns=%{time_namelookup}s tls=%{time_appconnect}s total=%{time_total}s size=%{size_download}\n' https://www.php.net/
```
Result: **HTTP=200 ip=84.17.59.117 dns=0.008s tls=0.025s total=0.037s**
(body discarded; homepage only; network path + curl mechanics verified).

## Embargo confirmation
NO embargo-related artifact was fetched before 14:00:00Z on 2026-10-21 during
this prep: zero requests to CVE listings, the 8.5.11 release page, session.c
commit/diff URLs or the tarball. The only network contacts made were (a) the
single generic homepage probe above and (b) nothing else; the real script
refused to fetch in both pre-embargo test runs. Everything in this directory
right now (besides this file and `status.txt`) was written by this prep.

## Quick usage recipe for the operator at 14:00Z
```
bash /tmp/opencode/realapps/side/fetch_advisory_1400.sh        # one-shot fetch
python3 /tmp/opencode/realapps/side/analyze_advisory.py        # post-cutoff commits + diffs
tail -40 /tmp/opencode/realapps/side/advisory_1400/status.txt  # what happened
ls -la /tmp/opencode/realapps/side/advisory_1400/
```
