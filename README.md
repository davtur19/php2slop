# php2slop — php 8.5 session.upload_progress machinery chain (CVE-2026-109618 / CVE-2026-109619)

## Overview

Research toolkit for the php-src 8.5.x pre-auth cross-request use-after-free
family in the session.upload_progress machinery and ZendMM OOM interruption
(`ext/session/session.c`, entry window 3129–3338 on the analyzed 8.5.10 tree).
Fixes shipped 2026-10-21 as php 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; the upstream
affected range starts at php 5.4.0. The kit contains the driver, request/producer
builders, per-binary offset profiles and the curated run receipts that document
both CVE classes on operator-owned stacks.

Two distinct SAPI situations apply. On mod_php, the stale-state machinery lives
inside the web server process, so the exploit does not depend on the
application. On php-fpm the exploitable sequence needs a fatal after a
successful request startup (application level), followed by the
upload-progress consumer on the surviving worker — the validated FPM path in
GHSA-6wmf-4rv5-p3rp.

## Mechanism

Chain, as reproduced and documented in the writeup (<https://calif.io/php2shell/>):

1. **Producer** — an unauthenticated request turns into a forced OOM
   interruption (`longjmp` out of a mid-initialization context) or leaves
   stale decoder state behind (CVE-2026-109618 OOM corruption,
   CVE-2026-109619 stale global state respectively).
2. **Stale decoder state** — request-owned state survives the heap free in
   worker globals; the next request consumes it before normal initialization
   resets it (confirmed consumers: pre-init INI diagnostics, session
   upload-progress decode paths).
3. **Upload_progress consumer** — the machinery record re-entry with stale
   bookkeeping; no `session_start()` call in the application is required
   (per GHSA-6wmf-4rv5-p3rp).
4. **Negative `used_slots`** — the forged machinery state passes the signed
   `used_slots + num > VAR_DTOR_ENTRIES_MAX` check because `used_slots` is
   negative; `var_push_dtor_value` then copies an attacker-chosen pointer/type.
5. **Controlled copy** — the copied zval chain into the stage address places
   `zif_passthru` / `zif_system` over a controlled callee; a forged
   `passthru-<cmd>` reference string executes the payload. Persist = the
   surviving daemon keeps executing per forged request.

Line-level provenance for each step is in
`receipts/diag3_10_runs/` and `docs/validation_1021_filmpost.md`.

## Layout

| path | contents |
|---|---|
| `tool/` | take-and-run driver: `php2shell.py` (CLI, `--step recon|chain`), `run` (sh wrapper), `__main__.py` (`python -m tool`) |
| `tool/modules/` | `arm.py` (multipart `PHP_SESSION_UPLOAD_PROGRESS` builders + HTTP framing + 14-byte disclosure analyzer), author-provided reconstructed `native-output-leak-stock-arm.py` (STOCK arm) and `compact-stock-tail.py` (COMPACT rearm/final forged multipart), `producer*.py` (618/619 shape builders + facade), `write_stage.py` (stub), `profiles.py` (registry), one-line index in `modules/README.md` |
| `tool/stages/` | `probe.py` — pre-flight worker-alive + header/status fingerprint |
| `addresses/` | per-binary symbol/offset profiles (`realapps_fpm.json`, `realapps_np_fpm.json`, CGI flavors, `generated/`) + `runtime_addresses.md` notes |
| `universal/` | profile builder (`profile_builder.py`: read-only `nm`/`readelf` → per-binary constants), freeze battery + run captures (wiki/wp fullflow, leakprobe, probeonly) |
| `fuzzing/` | offline CGI-SAPI fuzz harness, deterministic ASAN heap-UAF crashes and minimizations, `fuzz_findings.md` |
| `receipts/` | curated named runs with own READMEs: `diag3_10_runs/` (diag1–diag10 drivers, gdb cmd/filtered traces), `php5lab_receipts/`, `php7lab_receipts/`, `advisory_1400/` (one-shot fetch + fetched artifacts) |
| `docs/` | validation log (`validation_1021_filmpost.md`), master validation report (`reports_realapps_validation_1021.md`), previous README version (`README_2026-10-21_research_version.md`) |
| `LICENSE` | MIT |

## Requirements

- python3 ≥ 3.10 (stdlib only: `socket`, `struct`, `hashlib`, `argparse`, `json`).
- A loopback target you own, reachable HTTP, satisfying the target attributes
  in the table below.
- Optional: `gdb`, `nm`, `readelf` for `universal/profile_builder.py` and the
  gdb ground-truth runs in `receipts/diag3_10_runs/`.

## Quickstart

Commands below correspond to implemented code. The default target endpoints
and per-build constants are those measured on the lab stack (nginx → php-fpm
8.5.10); recon and chain against a different build require updating
`addresses/` and `tool/modules/profiles.py`.

```sh
# 1. recon: pre-flight fingerprint + stock arm + leak probe + address derivation
./tool/php2shell.py --target wiki --step recon

# same, package entry point
python3 -m tool --target wiki --step recon

# 2. chain: blocker-hold + per-DSO-candidate attempt (rearm + forged staged multipart)
./tool/php2shell.py --target wiki --step chain
# non-interactive proof command (default: id); listener needed for revshell
./tool/php2shell.py --target wp --step chain --command id

# one-off URL target (no registered profile; per-build constants mandatory)
./tool/php2shell.py --url http://127.0.0.1:28840/index.php --profile realapps-pie --step recon
```

Not implemented (chain stage producer): producer orchestration is not wired
into `--step recon/chain` — stub/facade at `tool/modules/producer.py`; the
proven shape builders already live at `tool/modules/producer_618.py` /
`tool/modules/producer_619.py`, and the parameterized producer plan (ranked
MW producers, step recipes) is
`/tmp/opencode/realapps/side/php2shell/runs/UNIVERSAL_PLAN.md`.

Not implemented (chain stage targets): `--target modphp` — no measured
addresses, no producer (`tool/modules/profiles.py`: `TARGETS["modphp"]`).

Not implemented (chain stage write_stage): negative-`used_slots` extraction
into profiles and stage-write receipt checks — stub at
`tool/modules/write_stage.py`; the live call path is
`tool/php2shell.py:attempt()` → `tool/modules/compact-stock-tail.py:COMPACT.probe_body(...)`.

## Targets

Target attributes, per `tool/modules/profiles.py:TARGETS` (values as-found on
the lab stack; verify per run — these are preconditions, not driver settings):

| attribute | wiki | wp | modphp |
|---|---|---|---|
| binary profile | `realapps-pie` | `realapps-pie` | — (TODO) |
| host:port/path | 127.0.0.1:28840 `/index.php` | 127.0.0.1:28841 `/index.php` | — |
| `memory_limit` | 8M (`php_admin_value`) | 8M | — |
| pm / max_children | static / 1 | static / 1 | — |
| `session.save_path` | `/tmp/opencode/realapps/sessions/wiki` | `/tmp/opencode/realapps/sessions/wp` | — |
| `session.upload_progress.enabled` | 1 (compiled default) | 1 | — |
| `session.upload_progress.cleanup` | 1 at runtime (diag labs override 0) | 1 | — |
| producers | `producer_618`, `producer_619` | `producer_618`, `producer_619` | — |
| status | probe + chain | probe + chain | TODO (missing module) |

To register a new target: append a dict to `TARGETS` in
`tool/modules/profiles.py` with `binary_profile`, `host`/`port`/`path`,
`session_save_path`, and the `ini` keys above. Generate the matching per-build
constants with `universal/profile_builder.py` (read-only on the binary) and
set the `dso_deltas`/gadget offsets in `tool/modules/profiles.py:BINARY_PROFILES`
per the `addresses/` JSON files.

Ini knobs that matter at the target: `memory_limit` (low → producer OOM fatal
inside the machinery window), `post_max_size` (body budget; >8M aborts
pre-machinery on the lab stack), `max_file_uploads` (arm file-part cap),
`pm = static` with predictable child mapping (worker-pinned chains),
`session.save_path` (attacker-writable `sess_*` records are the persistence
surface), and the `session.upload_progress.*` group (`enabled` gates the
consumer; `cleanup=1` empties the record at request end — the machinery
arm/freeze receipts rely on timing, not on a disabled cleanup).

## Receipt scheme

Each `--step` run writes a receipt directory: per-exchange
`<label>-request.bin` / `-response.bin` / `-body.bin`, a `result.json` with
status/headers/sha256 per artifact, and (recon/chain) derived addresses
(`main`, `target`, `stage`, `dso_candidates`) plus the `uid=` id-line match for
chain success. Default output directory:
`files/io/<target>-<step>-<UTC stamp>/` (override with `--output`; the
directory is local and git-ignored). Published, curated evidence lives under
`receipts/<name>/` with a describing README — see `receipts/README.md` for the
index and the commitment rule. Raw uncurated lab logs (`.out/.err/.bin/.log`)
are intentionally not tracked.

## References

- CVE-2026-109618 — RCE via OOM corruption:
  <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619 — RCE via stale global state:
  <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- php 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 release announcement (2026-10-21):
  <https://www.php.net/archive/2026.php#2026-10-21-5>
- Upstream writeup, *A tale of two PHP remote vulnerabilities*:
  <https://calif.io/php2shell/> (alias <http://php2shell.com>)
- Internal: `docs/validation_1021_filmpost.md` (diag3–diag10 ground truth),
  `docs/reports_realapps_validation_1021.md` (master validation report),
  `docs/runtime_addresses.md`, `docs/README_2026-10-21_research_version.md`
  (full historical README version).
- Partial mitigations (from advisories): patch (complete fix only);
  `memory_limit=-1` and `session.upload_progress.enabled=0` (admin scope,
  worker restart); low `post_max_size`; php 8.5 `fatal_error_backtraces=0`;
  cgroup `memory.max`. Do not use `RLIMIT_AS`/`RLIMIT_DATA` (they trigger the
  vulnerable `mmap()`-failure path).

## Legal / Lab notice

Runs exclusively against operator-owned, loopback-only lab targets
(127.0.0.1) for controlled security research on published, patched bugs;
use against third-party systems is outside the scope of this repository and
its license. Targets must satisfy the attribute table above; nothing here
requires modifying victim applications. Code is provided as-is under MIT.
