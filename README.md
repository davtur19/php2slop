# phpshell — php 8.5.x session.upload_progress machinery UAF lab toolkit

Research toolkit around **CVE-2026-109618 / CVE-2026-109619** (php-src 8.5.x,
`ext/session` upload-progress machinery use-after-free window,
`ext/session/session.c:3129–3338`). All experiments run on operator-owned
stacks against loopback targets (nginx → MediaWiki 1.46.2 / WordPress on
stock-build php 8.5.10 fpm/cgi).

## Layout

- `php2shell/` — exploit driver (`php2shell.py`) + helper modules:
  `native-output-leak.py` (LEAK probe/framing), `native-output-leak-stock-arm.py`
  (STOCK arm — reconstructed from the zer061 shape docs, provenance per semantic),
  `compact-stock-tail.py` (COMPACT rearm/final forged multipart); diag harnesses
  `diag_arm_probe.py`, `diag2_arm_probe_rearm_final.py`.
- `universal/` — freeze battery (`freeze_battery.py`), per-binary PROFILE
  builder (`profile_builder.py`), per-runtime run captures.
- `addresses/` — per-binary symbol/offset profiles (incl. `generated/`).
- `advisory_1400/` — embargo-gated one-shot fetcher for the fix window +
  `analyze_advisory.py` consumer.
- Root — staged PoC shape builders (`staged_618.py`, `build_p1.py`, `gen_shape.py`,
  `sender_fpm.py`, `slowfeed.py`, `feeder_f618.py`), build scripts, gdb scripts,
  trigger-experiment logs, runtime maps dumps, per-asan flavor run logs.
- `reports_realapps_validation_1021.md` — master validation report.

## Status highlights

- 21 binaries / 7 flavors × 3 SAPIs profiled (nm-deterministic + PIE deltas).
- Machinery record persistence **reproduced in the lab** with
  `session.upload_progress.cleanup=0` instrumentation: the serialized
  `upload_progress_*` record survives request end (observable in `sess_*`).
- ASAN-confirmed reentrancy UAF at `php_session_rfc1867_update`
  (`session.c:3155` → `zend_hash.c:872` pDestructor double-release), triggered
  with planted-state conditions in the offline harness — family mechanism of
  the advisored window.
- Open: stock-ini freeze semantics at request teardown + the 14-byte
  native-output disclosure — resolution expected from the 8.5.11 fix diff.

## Safety

Lab security research. Targets are operator-owned, tests are loopback-only.
Excludes third-party bundles (`zer061`, `jpack`) by design.

## 2026-10-21 — independent verification of community corrected-findings (jackalsyn page)
Treated as lead, not truth. Fact-check on our 8.5.10 tree: var.c:756 / basic_functions.c:391-393 / var.c:1346 level-guard / session.c:3154 addref — all verbatim. Reproduced ourselves (diag3-5, see docs/validation_1021_filmpost.md): arm OOM pre-RINIT on stock fpm (remains alive, contradicting page matrix), and on ASAN built-in server: R1 OOM -> R2 diverged body -> R3 death with SEGV in var_unserializer via session decode at php_hash_environment → php_request_startup. No RCE claim yet — primitive family only.
