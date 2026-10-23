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
Updated: 2026-10-23 20:27 UTC
Host: netsec (96 CPU, 251 GiB RAM, 466 GB free, rootless Docker)
Phase: waiting for first assignment
Done:
- rootless Docker verified: name=rootless, no /var/run/docker.sock
- images pulled for PHP 8.1-8.5 Apache/FPM and base distros
Next:
- preflight and metadata matrix
- fetch research/wp8424-setup; run setup-only positive control
- fetch research/8426-kit; run 20 fresh pools
- fetch research/gap-plan; execute batches
Blockers:
- none yet; branches may still be publishing
