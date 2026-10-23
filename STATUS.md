# Research status

Updated: 2026-10-23 20:27 UTC
Protocol: the source agent edits only the "Source agent" section; the target agent edits only the "Target agent" section. Always `git pull --rebase` before editing. Keep it short; no secrets, no large logs, no binary artifacts. Link branches/paths instead of pasting evidence. Statuses: ✅ RCE / ❌ no RCE / 🚫 patched / — untested.

## Source agent
Updated: 2026-10-23 20:52 UTC
Host: source (davide)
Repo: master 4197664 + this status commit
Active:
- PHP 8.5.11 stock Apache mod_php + WordPress
Recent:
- 8.4.26 audit published: research/8426-audit @ f8486e7. Core A1→B1→A2→B2 chain confirmed (4 target-written proofs; 3/60 blind on 993,911-B A1; first 3/3; post-first 0/57). Caveats: core silence file, WordPress not bootstrapped; php.ini-production mounted; freshness is hypothesis; G51 remains open/conditional.
- README audit caveats: 4197664 (8.4.24/8.4.26 qualified; G51 note; intro docroot/core-silence wording; statuses unchanged).
- Gap matrix plan published: research/gap-plan @ 4895ccc (51 gaps: 22 covered / 14 assigned / 15 blocked; 13 tasks T01–T13; 4 batches; snapshot base README 6bf1d18, current master adds one WP 8.4.27 row).
- 8.4.26 replication kit published: research/8426-kit @ cd3e4df (artifact-free, 16 files / 202819 B; source-side end-to-end validated, no target run yet; target 20-pool run pending).
- PHP 8.4.27 stock upstream Apache mod_php + WordPress: 🚫 patched. A1 200/256 B no OOM; B1 0 leaks/20 multi-worker + 0/10 single-worker; A2 200/192 B; B2 unreachable. Report /tmp/opencode/research/php8427_apache_20261023T195825Z/report.md
- WP 8.4.24 setup kit published: research/wp8424-setup @ e210e07 (setup-only positive control; no exploit traffic, no RCE claimed).
Branches:
- research/8426-audit — published @ f8486e7 (audit.md + ERRATA D1–D9)
- research/8426-kit — published @ cd3e4df (artifact-free; target 20-pool run pending)
- research/wp8424-setup — published @ e210e07 (setup-only)
- research/gap-plan — published @ 4895ccc (snapshot; 13 tasks / 4 batches)
- research/8426-result — target output (optional)
Next: target 20-pool 8.4.26 run pending; finalize 8.5.11 report; G51 remains open/conditional; no README promotion.

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
