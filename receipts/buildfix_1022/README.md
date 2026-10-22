# php2slop builder fixes — `--step g2` patch receipt

Receipt: `/tmp/opencode/buildfix_20261022T023939Z`
Date: 2026-10-22
Scope: four offline builder fixes for `tool/modules/g2_chain.py` (`--step g2`), documentation and self-checks. No transport, no live target, no service restart.

## Verdict

The four fixes were generated as a patch series against the public tree and **applied and pushed** by the main session:

| # | commit | message | files |
|---|---|---|---|
| 1 | `53ab5b9` | `fix: derive zif arg1 from Q, map serializer slots, per-profile zif delta` | 4 files, +236/−47 |
| 2 | `dcdf16b` | `feat: plan realapps php_binary decode in --step g2` | 5 files, +31/−26 |
| 3 | `9131cfe` | `chore: reference committed receipts repo-relative in g2_chain` | 1 file, +4/−2 |

Base `d16b0b2`; `HEAD == origin/master` at `9131cfe`; working tree clean; README 42 lines; no force push. The fixes are therefore already in this repository — this receipt preserves the patch, the self-check harness and the byte-parity evidence behind them.

## What the patch changes

1. **`zif` arg1 derivation from `Q`** — the fake `execute_data` argument slot is derived from the record geometry instead of a hard-coded profile constant; `--g2-target` must be 16-byte aligned (the previously accepted `0x22c54c8` now exits 2).
2. **Serializer-slot mapping** — `[0]=php_serialize, [1]=php, [2]=php_binary, [3]=sentinel` is mapped per binary, so `--g2-decode` selects the correct active slot.
3. **Per-profile `zif` delta** — `zif_passthru`/`zif_system` deltas are per profile instead of a single global delta.
4. **Realapps `php_binary` planning** — the committed realapps 8.5.10 profile now plans the entry-2 (`php_binary`) target instead of rejecting it.
5. **Documentation** — module docstring and `USAGE.md` cite `receipts/realchain_20261022/` (entry-1 `php` slot) and `receipts/realzif_entry2_1022/` (entry-2 `php_binary` slot) instead of stale "pending" wording; the old "19-byte symbols" claim was verified with `nm -S` (`zif_system` and `zif_passthru` both `0x13`).

## Evidence

| path | content |
|---|---|
| `REPORT.md` | full report: work location, patch choice, files changed, verification matrix, push result, deviations |
| `buildfix.patch` | original patch against clone base `760662c` (`git apply --check` fails on `USAGE.md` only) |
| `buildfix_rebased.patch` | **recommended** patch; applies cleanly to `d16b0b2` |
| `check_builder_fixes.py` | 52-check self-check driver |
| `check_rebased.py`, `check_realrepo.py` | rebased-tree and real-repo variants |
| `selfcheck_*.log` | 52/52 on the isolated tree; **55/55** on the pushed real repo (`selfcheck_realrepo_c3.log`) |

The decisive check is output parity, not only exit codes: after the patch, the 8.5.10 G2 and G6 records are **byte-identical** to the pre-patch baseline (`aeb2021a…5792d`, `02bc043f…c6e770`), and the lab regression matrix (8.5.10 / 8.4.25 / 8.1.34 / 7.4.33, G2 + G6) keeps every record hash unchanged. On the pushed tree, the realapps receipt geometry reproduces: target `0x22c54e0`, entry `php_binary`, `Q=0x78`, `L=130892`, `F=0x7ffff46ae190`, `K=-8796078587571`, delta `+0x13`, record 131,014 B.
