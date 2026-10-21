# php2slop

php 8.5 session.upload_progress machinery tooling.
CVE-2026-109618 / CVE-2026-109619 — pre-auth cross-request UAF family
(`ext/session/session.c` machinery + ZendMM OOM interruption, window 3129–3338 on 8.5.10).
Fixed 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21). Upstream affected range ≥ 5.4.0.
SAPIs: mod_php — no app cooperation needed. FPM — needs an app-reachable fatal after
successful startup, then the upload-progress consumer on the surviving worker (GHSA-6wmf-4rv5-p3rp).

## Chain

```
producer → stale decoder state → upload_progress consumer → negative used_slots → controlled copy
```

1. producer: unauthenticated request OOMs `longjmp` mid-init / leaves stale worker state
2. consumer: machinery re-entry consumes the stale record pre-RINIT; no `session_start()` needed
3. negative `used_slots` passes `used_slots + num > VAR_DTOR_ENTRIES_MAX`; `var_push_dtor_value` copies a chosen pointer/type
4. copy places `zif_passthru` / `zif_system` over a controlled callee; `passthru-<cmd>` runs the payload

Stage sources: `receipts/diag3_10_runs/`, `docs/validation_1021_filmpost.md`.

## Layout

| path | contents |
|---|---|
| `tool/php2shell.py` | driver CLI (`--step recon\|chain`) |
| `tool/run`, `tool/__main__.py` | `./tool/run`, `python -m tool` |
| `tool/modules/arm.py` | multipart `PHP_SESSION_UPLOAD_PROGRESS` builders, HTTP framing, 14-byte disclosure analyzer |
| `tool/modules/native-output-leak-stock-arm.py` | STOCK arm body (author-provided reconstruction) |
| `tool/modules/compact-stock-tail.py` | COMPACT rearm + final forged multipart (author-provided reconstruction) |
| `tool/modules/producer_618.py` / `producer_619.py` | CVE-109618 / CVE-109619 staged producer shapes (inert forge default) |
| `tool/modules/producer.py` | producers facade — not wired into driver steps; mod_php producer TODO |
| `tool/modules/write_stage.py` | stub; live path = `php2shell.py:attempt()` → `COMPACT.probe_body(...)` |
| `tool/modules/profiles.py` | `BINARY_PROFILES` + `TARGETS` registry |
| `tool/stages/probe.py` | pre-flight fingerprint (GET, status/headers) |
| `addresses/` | per-binary offsets (`realapps_fpm.json`, `realapps_np_fpm.json`, CGI flavors, `generated/`) |
| `universal/` | `profile_builder.py` (read-only `nm`/`readelf`), freeze battery, wiki/wp run captures |
| `fuzzing/` | CGI fuzz harness, deterministic ASAN heap-UAF crashes, `fuzz_findings.md` |
| `receipts/` | curated named runs: `diag3_10_runs/`, `php5lab/`, `php7lab/`, `advisory_1400/` (index + rule: `receipts/README.md`) |
| `docs/` | `validation_1021_filmpost.md`, `reports_realapps_validation_1021.md`, `runtime_addresses.md`, `README_2026-10-21_research_version.md` |
| `LICENSE` | MIT |

## Requirements

python3 ≥ 3.10, stdlib only. Loopback target you own. `gdb`/`nm`/`readelf` optional
(`universal/profile_builder.py`, gdb runs in `receipts/diag3_10_runs/`).

## Run

```sh
./tool/php2shell.py --target wiki --step recon      # fingerprint + stock arm + leak probe + addresses
python3 -m tool --target wiki --step recon          # same via package entry
./tool/php2shell.py --target wp --step chain        # blocker hold + rearm + forged staged multipart
./tool/php2shell.py --target wiki --step chain --command id
./tool/php2shell.py --url http://127.0.0.1:28840/index.php --profile realapps-pie --step recon
```

Not implemented:

| stage | path |
|---|---|
| producer wiring (CLI step) | `tool/modules/producer.py` |
| modphp target (addresses + producer) | `tool/modules/profiles.py:TARGETS["modphp"]` |
| write_stage extraction | `tool/modules/write_stage.py` |

Parameterized producer/step plan: `/tmp/opencode/realapps/side/php2shell/runs/UNIVERSAL_PLAN.md`.

## Targets

| attribute | wiki | wp | modphp |
|---|---|---|---|
| binary profile | `realapps-pie` | `realapps-pie` | — |
| endpoint | 127.0.0.1:28840 `/index.php` | 127.0.0.1:28841 `/index.php` | — |
| `memory_limit` | 8M (`php_admin_value`) | 8M | — |
| pm / max_children | static / 1 | static / 1 | — |
| `session.save_path` | `/tmp/opencode/realapps/sessions/wiki` | `/tmp/opencode/realapps/sessions/wp` | — |
| `session.upload_progress.enabled` | 1 (compiled default) | 1 | — |
| `session.upload_progress.cleanup` | 1 at runtime (diag labs override 0) | 1 | — |
| producers | `producer_618`, `producer_619` | same | — |
| status | run | run | TODO |

Values as-found on the lab stack (verify per run). Add a target: new dict in
`tool/modules/profiles.py:TARGETS` + constants in `BINARY_PROFILES` (generate via
`universal/profile_builder.py`, offsets per `addresses/*.json`).

Ini knobs that matter: `memory_limit` (produces the OOM fatal), `post_max_size`
(>8M aborts pre-machinery on this stack), `max_file_uploads` (arm file-part cap),
`pm=static` (pinned child mapping), `session.save_path` (attacker-writable `sess_*`
records), `session.upload_progress.*` (gates the consumer; `cleanup` timing).

## Receipts

`--step` writes `files/io/<target>-<step>-<UTC stamp>/` (or `--output DIR`):
`<label>-request/-response/-body.bin` + `result.json` (status, headers, sha256 per artifact).

| step | extra |
|---|---|
| recon | derived addresses (`main`, `target`, `stage`, `dso_candidates`) |
| chain | blockers count, per-candidate result, `uid=` line on success |

Runtime output dir is git-ignored. Curated evidence: `receipts/<name>/` with a README
(`receipts/README.md`). Raw logs/binaries not tracked.

## References

- CVE-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- CVE-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- Fix release 2026-10-21: https://www.php.net/archive/2026.php#2026-10-21-5
- Writeup (upstream, alias `php2shell`): https://calif.io/php2shell/ — http://php2shell.com
- Internal: `docs/` (validation log, master report), `receipts/` (named runs)

Loopback-only, operator-owned targets. Use against third-party systems is out of scope and
out of license. MIT; no warranty.
