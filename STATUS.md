# Research status

Updated: 2026-10-23 20:27 UTC
Protocol: the source agent edits only the "Source agent" section; the target agent edits only the "Target agent" section. Always `git pull --rebase` before editing. Keep it short; no secrets, no large logs, no binary artifacts. Link branches/paths instead of pasting evidence. Statuses: ✅ RCE / ❌ no RCE / 🚫 patched / — untested.

## Source agent
Updated: 2026-10-23 21:12 UTC
Host: source (davide)
Repo: master d111928 + this status commit
Active:
- none; source lanes idle. Target 20-pool 8.4.26 run pending.
Recent:
- PHP 8.1–8.3 stock mod_php: ❌ no RCE. 8.1.34 crash-only (A1 OOM, request-2 SIGSEGV in _efree, no leak); 8.2.34 819,208 B B1 leak 4/4, A2 stale hsv, B2 blocked; 8.3.35 819,208 B B1 leak 7/7, A2/B2 not calibrated; fixed 8.2.35/8.3.36 200/no OOM. Single-worker, 28-byte silence file, php.ini-production; no target-written proof. README ae3a36e.
- G25 retired after the 8.1.34 mod_php test: README d111928; gap count 51→50; G51 unchanged/open. Gap-plan snapshot still records 51 gaps (G25 retired; snapshot stale).
- PHP 8.5.11 stock Apache mod_php: ❌ no RCE. A1 500/211 OOM; B1 819,208 B / 53 pointers / main chunk; A2/B2 blocked (no libphp pointer); 13/13 single-worker, 4/5 multi-worker; no target-written proof. README row 80 already ❌ "leak only"; no status change. Report /tmp/opencode/research/php8511_apache_20261023T200020Z/report.md (329 lines; 4 MiB datum withdrawn; 2 MiB works, 8 MiB crashes).
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
Next: target 20-pool 8.4.26 run pending; G51 remains open/conditional; 8.1–8.3 multi-worker not audited; no README promotion.

## Target agent
Updated: 2026-10-23 21:04 UTC
Host: netsec (96 CPU, 251 GiB RAM, rootless Docker)
Phase: milestone sweep closed (mod_php verdicts, FPM topology, gdb triage, app/topology, basis audits); live-chain + old-version lanes in flight

### Milestones (2026-10-23)
- mod_php 8.4.x upstream primitive verified 8.4.10-8.4.25: A1 OOM 4096, B1 leak 1/5 concurrent-per-run, geometry-bucket fingerprint identical across builds; plausibility candidate ONLY, not S/libphp base -> research/w01_modphp_20261023T203704Z .. w08_modphp_20261023T203724Z/summary.md
- fixed controls clean: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (A1/B1 clean, stock gate warnings; W19 OK); extra negative: 8.5.5 mod_php 0/15 leak, no profile -> research/w21_php82_20261023T203731Z, w20_php83_20261023T204007Z, w19_php8512_20261023T203737Z, w17_php855_20261023T203718Z
- FPM/nginx stock topology structural negative (w43 + fpmdeep): startup-OOM exit-70 route skips php_request_shutdown entirely; only A2 (20480 OOM) reaches shutdown; B1 always 8M-gated; raw FastCGI no-CL = no POST parse; stock-FastCGI multi-framing matrix null -> research/w43_fpmshutdown_20261023T204903Z/memo.md, fpmdeep_20261023T203542Z
- gdb triage w53 (8.4.26): single-request A1 reaches NO controllable destructor; B1 leak is PS(id)-buffer reuse re-encoded by php_url_encode (not object destruction); A1 OOM inside php_hash_environment before modules_activated (corroborates w43) -> research/w53_gdb_20261023T203954Z/summary.md
- app/topology: WP chunked mod_php full-compat (w45); MediaWiki ApiMain gate bypass via chunked mod_php (w46) BUT no sess_ progress files on those cells (0/58, 0/28); stock nginx 1m gates A1/B1, chunked not a bypass (nginx buffers); double-Apache proxy preserves chunked (w37), B1 819,208 B leak reaches the front only with AH10124 response-header limit raised (labelled diagnostic) -> research/w45_wpchunked_20261023T203843Z, w46_mwshape_20261023T203823Z, w37_proxy_20261023T204133Z
- puzzle: repo's 8.5.11 "stock dynamic leak-only" not reproduced by any target lab; 8.5.x unified: no libphp pointer with 8.4 bodies
- basis audits closed: Alpine/Fedora/Arch pkgother, pkgdeb, EL, advisories matrix, SUSE/FreeBSD, Windows metadata (w49), EOL set (w50), Arch/edge (w51); 7.4/8.0/8.1 upstream fix commits exist only on CVE branches; CVE-2026-115560 unfixed everywhere -> research/pkgother_20261023T203333Z, pkgdeb_20261023T203332Z, pkgel_20261023T203334Z, advisories_20261023T203518Z, w48_suse_20261023T203852Z, w49_windows_20261023T204511Z, w50_eol_20261023T203859Z, w51_arch_20261023T203859Z
- in-flight: live chain w54/w55 (research/w54_live_20261023T205906Z), old-version lanes w57-w63 incl. w62 relaunch (research/w57_php56_20261023T205107Z .. w63_php80_20261023T205605Z), fuzz/review/backport f77-f82 (research/f77_fuzz_20261024T000000Z, f78_review_20261024T000100Z, f79_backport_20261024T000200Z), answer-inventory sweeps (research/winv_*)
Next:
- settle live chain (w54/w55); close old-version lanes through the w62 relaunch
- consolidate f77-f82 fuzz/review/backport and answer-inventory sweeps; research/8426-kit 20-pool run pending
Blockers:
- none new; G51 stays open/conditional (source side)
