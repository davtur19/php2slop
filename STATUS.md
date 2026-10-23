# Research status

Updated: 2026-10-23 20:27 UTC
Protocol: the source agent edits only the "Source agent" section; the target agent edits only the "Target agent" section. Always `git pull --rebase` before editing. Keep it short; no secrets, no large logs, no binary artifacts. Link branches/paths instead of pasting evidence. Statuses: ✅ RCE / ❌ no RCE / 🚫 patched / — untested.

## Source agent
Updated: 2026-10-23 20:27 UTC
Host: source (davide)
Repo: master 6bf1d18
Active:
- PHP 8.4.27 stock Apache mod_php + WordPress (worker)
- PHP 8.5.11 stock Apache mod_php + WordPress (worker)
- audit of PHP 8.4.26 multi-worker RCE (worker)
- gap matrix planner (worker)
- publish WP 8.4.24 setup branch (worker)
Recent:
- PHP 8.4.26 stock upstream Apache mod_php multi-worker: ✅ RCE, 3/60 blind = 5.0%, first attempt 3/3, post-first 0/57; heap freshness precondition; audit pending.
- WP 8.4.24 setup kit validated: setup-only, no exploit traffic, no RCE claimed.
Branches:
- research/wp8424-setup — setup-only positive control (publishing)
- research/8426-kit — 8.4.26 replication kit (in preparation)
- research/gap-plan — gap matrix plan (in preparation)
- research/8426-result — target output (optional)
Next:
- publish 8426 kit and gap plan
- update README only after audit confirms
- hand off parallel batches to target

## Target agent
Updated: 2026-10-23 20:32 UTC
Host: netsec (96 CPU, 251 GiB RAM, rootless Docker)
Phase: fase 1+2 done; parallel per-build lanes running (8.4.x mod_php, FPM, image matrix)
Done:
- preflight: name=rootless, no /var/run/docker.sock; repo clean; branch scan shows only research/wp8424-setup
- FASE 1 metadata matrix: 12 pulled php images characterized (version, SAPI, Apache/MPM, ini, FPM pool) -> research/meta_20261023T203029Z/matrix.tsv. Note: stock images load no php.ini; CLI reports display_errors=1, so effective values must be sampled through Apache/FPM. Tags moved: php:8.4-fpm=8.4.27, php:8.5-fpm=8.5.12.
- FASE 2 positive control: research/wp8424-setup @ e210e07 in worktree repro8424_20261023T203049Z, RUN_DIR=research/wp8424_run PORT=28081 -> 28/28 OK, RESULT: setup ready, setup-only, no exploit traffic, no RCE claim. Container wp8424-repro frozen as the reference environment.
Next:
- per-build mod_php primitive lanes (A1/B1) on upstream 8.4.10-8.4.26 + 8.4.27 control, harness validated against the documented 8.4.26 numbers
- stock nginx+FPM lane: exact-version 8.4.26/8.4.27/8.5.11 (note php:8.4-fpm resolves to 8.4.27)
- branch poll for research/8426-kit and research/gap-plan; FASE 3/4 stay blocked until those branches exist
Blockers:
- research/8426-kit missing (FASE 3 blocked)
- research/gap-plan missing (FASE 4 blocked)
