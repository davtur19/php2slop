# php2slop builder fixes — worker report

> **Status: applied and pushed.** Sections 1–6 describe the pre-push work and
> remain accurate as history; section 7 records the commits, the re-verification
> on the pushed tree, and the deviations from the requested procedure.

Date: 2026-10-22
Scope: four offline builder fixes for `tool/modules/g2_chain.py`
(`--step g2`), docs, self-checks. No transport, no live target, no service
restart, no push.

## 1. Where the work is

| item | path |
|---|---|
| isolated clone (uncommitted changes) | `/tmp/opencode/buildfix_20261022T023939Z/phpshell` |
| patch against clone base `760662c` | `/tmp/opencode/buildfix_20261022T023939Z/buildfix.patch` (30,216 B, sha256 `a4e44c9a…f4a4497`) |
| **patch rebased onto current HEAD `d16b0b2`** | `/tmp/opencode/buildfix_20261022T023939Z/buildfix_rebased.patch` (29,790 B, sha256 `ae683d40…b5c70a68`) |
| rebased working tree (for inspection) | `/tmp/opencode/buildfix_20261022T023939Z/applycheck` |
| self-check driver | `/tmp/opencode/buildfix_20261022T023939Z/check_builder_fixes.py` (52 checks) |
| self-check logs | `selfcheck_final.log` (52/52), `selfcheck_rebased.log` (52/52) |
| baseline / after record hashes | `baseline/`, `after/`, `regression/` |

Original repo `/home/davide/ailocal/php/phpshell` was **not modified**:
`git status --porcelain` is empty and HEAD is still `d16b0b2`. All editing,
committing-adjacent work and patch generation happened in the clones only. No
commit was made in any tree.

## 2. Which patch to use

The clone was cut from `760662c`; HEAD has since moved to `d16b0b2` and
`USAGE.md` changed in between (F14 reclassified, realchain/realzif receipts
added). Therefore:

- `buildfix.patch` — original, applies to `760662c`. `git apply --check`
  **fails on USAGE.md only** (hunk at the F12b section).
- `buildfix_rebased.patch` — **recommended**. Verified on a fresh clone of
  `d16b0b2`: `git apply --check` passes, `py_compile` passes, `--step g2` G2 and
  G6 both rc=0, and the emitted records are byte-identical to the originals
  (`aeb2021a…5792d` G2, `02bc043f…c6e770` G6 zif_passthru).

The builder logic is identical in both patches; the only differences are
documentation strings — `g2_chain.py`'s module docstring and its
`real-target status` caveat (rebased to cite `receipts/realchain_20261022/` and
`receipts/realzif_entry2_1022/` instead of the stale "pending" wording), and the
matching `USAGE.md` sentences. `tool/php2shell.py` and
`tool/modules/README.md` are byte-identical between the two patches.

## 3. Files changed (rebased)

```
 USAGE.md                 |  55 ++++++++++--
 tool/modules/README.md   |   2 +-
 tool/modules/g2_chain.py | 213 +++++++++++++++++++++++++++++++++++++++--------
 tool/php2shell.py        |  15 ++--
 4 files changed, 238 insertions(+), 47 deletions(-)
```

## 4. The four fixes

### Fix 1 — Q-derived fake `execute_data` arg1 pointer

`plan_zif` already computed `Q = payload_start` at HEAD, but `F` was assembled
from `Q` inline with no invariant. Now:

- `_fake_zend_string_addr(x2, payload_start)` is the single definition of
  `F = X2 + 0x18 + Q + 0x100`.
- Two new plan checks: `arg1_pointer_from_Q` and a re-derivation guard after
  record assembly (`len(rec1) + len(prefix) == Q`).
- The assembled key1 is asserted to contain exactly `struct.pack("<Q", F)` at
  `0x50`.
- `fake_execute_data.arg1_value_source` now reports
  `X2 + 0x18 + Q(0x78) + 0x100`, so the derivation is auditable in `result.json`.

Why it matters: `Q` moves with the decimal width of the written zif address
(lab `0x88f6b7` = 7 digits → `Q=0x77`; realapps `0xa3c074` = 8 digits →
`Q=0x78`). A hardcoded `0x77` points one byte before `F`.

### Fix 2 — serializer entry name → real table slot

New `_serializer_entry(profile, "php_binary")` resolves the write target by
entry **name**, validates `index` is a non-negative int, and checks
`table + index * ps_serializer_size + 0x10 == entry.decode`. `plan` and
`plan_zif` now take the default target from that entry, never from
`ps_serializers.default_target`.

`_decode_entry` was rewritten to: reject duplicate decode slots, validate the
matched entry by name/arithmetic, reject non-16-byte-aligned slots, and return
`None` for targets outside the table (the `PS(serializer)` fake-struct route
still works).

Why it matters: on all four lab profiles `default_target` **is** the
`php_binary` slot, but on realapps `default_target` is `0x22c54c8` (entry 1,
`php`, 8 mod 16) while `php_binary` is `0x22c54e0` (entry 2). The old code was
silently wrong on realapps. Plans now emit `serializer` and `serializer_entry`
blocks.

### Fix 3 — per-profile `zif_passthru`

`zif_passthru` was already read from the profile; the patch makes "never
synthesize `zif_system + 0x10`" explicit and checked:

- `_zif_delta(profile)` returns `zif_passthru - zif_system`, requires `> 0`, and
  cross-checks a declared `zif_route.zif_passthru.delta_from_zif_system` token
  (realapps stores `"+0x13 on this build, not the +0x10 seen…"`; the first token
  is parsed).
- `_zif_symbol` always validates the delta, so a missing `zif_passthru` is a
  hard error rather than a `+0x10` fallback.
- Plan emits `addresses.zif_delta_from_system` and a
  `zif_passthru_profile_delta` check.

### Fix 4 — poison / recycle documentation

No behaviour change. Added `USAGE.md` §"Poison and worker recycling" and a
`plan_zif` caveat: the overwrite is worker-local `.data`, survives every
non-crashing decode, persists for the worker lifetime under
`pm.max_requests=0`, and is cleared only by recycle; a crafted crash respawn
gives a pristine worker but is **not** remediation.

## 5. Tests run (all green)

| test | result |
|---|---|
| `py_compile` tool/php2shell.py + tool/modules + tool/stages | OK (both trees) |
| self-check `check_builder_fixes.py` | **52 PASS / 0 FAIL** (`ALL CHECKS PASSED`) |
| rebased self-check (`check_rebased.py`) | **52 PASS / 0 FAIL** |
| lab G2/G6 record bytes vs pre-patch baseline | identical: G2 `373b4bb1…`, G6 passthru `311e602b…`, G6 system `4366c161…` |
| CLI regression 8.5.10 / 8.4.25 / 8.1.34 / 7.4.33 | G2 and G6 rc=0 for all four, correct targets, G6 `Q=0x77`, delta `+0x10` |
| realapps php_binary plan (in-memory profile copy) | target `0x22c54e0`, `Q=0x78`, `F=0x7ffff46ae190`, `K=-8796078587571`, delta `+0x13`, cmd len 67, record 131,014 B |
| rebased patch on fresh `d16b0b2` clone | applies cleanly, rc=0, identical record hashes |

Negative checks that pass: unmodified realapps profile rejected (still
`php_session_zif`), missing `--g2-x2` rejected, explicit `0x22c54c8` rejected
(not 16-byte aligned), profile without `zif_passthru` rejected, declared-delta
mismatch rejected, profile with zero/duplicate `php_binary` entries rejected.

Not tested (deliberately): no live/transport path, no realapps run, no F12b
record emission.

## 6. Open questions for the main worker

1. **Enable realapps `php_binary` planning?** The committed realapps profile
   still has `record_builder: php_session_zif` and `--step g2` still rejects it
   with a pointer to the F12b `mkrec.py`. Fix 2 makes the builder *correct* for
   that profile, but the patch does **not** flip the gate. If you want
   `--step g2 --g2-profile realapps-8.5.10 --g2-decode zif_passthru` to plan
   the `0x22c54e0` write, that is a one-line profile change (set
   `record_builder: php_binary_zif`) and should be a separate decision, because
   the profile is documented as the F12b `php`-slot route.
2. **USAGE status reconciliation.** HEAD now records the entry-1 `php`-slot
   clean `zif_passthru` run (`receipts/realchain_20261022/`) and the entry-2
   `php_binary` run (`receipts/realzif_entry2_1022/`). My first patch predates
   that and still said "pending"; the rebased patch follows HEAD instead and
   cites both receipts. Please confirm the split wording reads correctly to you.
3. **Receipt constant path.** `REALZIF_RECEIPT` points at the research dir
   `/tmp/opencode/research/realzif_20261022T013000Z` to match the other
   `*_RECEIPT` constants. The same receipt is now in-repo at
   `receipts/realzif_entry2_1022/`. Say the word if you prefer repo-relative
   receipt paths and I will switch all constants together.
4. **`_decode_entry` return of `None`.** Targets that match no table entry are
   still accepted, because the documented `PS(serializer)` fake-struct route
   points into `ps_globals` (`ps_globals + 0x160` / `+0x130`), not into the
   serializer table. A tighter check — "target inside the table's
   `[table, table + n*stride)` range but not on any `+0x10` decode slot" — would
   be safe for that route (it sits outside the range) and would catch typos that
   happen to be 16-byte aligned. Left out to keep the patch minimal; say if you
   want it.

## 7. Push result (final state)

Repo: `/home/davide/ailocal/php/phpshell`, branch `master`, remote `origin`.
Base `d16b0b2`, all three commits pushed with no force push; `HEAD` and
`origin/master` both `9131cfe`; working tree clean; no `index.lock`; README 42
lines; no credentials printed or committed.

| # | hash | message | files |
|---|---|---|---|
| 1 | `53ab5b9` | `fix: derive zif arg1 from Q, map serializer slots, per-profile zif delta` | 4 files, +236/−47 |
| 2 | `dcdf16b` | `feat: plan realapps php_binary decode in --step g2` | 5 files, +31/−26 |
| 3 | `9131cfe` | `chore: reference committed receipts repo-relative in g2_chain` | 1 file, +4/−2 |

Each commit was pushed and `HEAD == origin/master` verified before the next
started.

### Re-verification on pushed `9131cfe`

- `py_compile` (tool/php2shell.py, tool/modules, tool/stages): OK.
- Self-checks: **55/55 PASS** (`selfcheck_realrepo_c3.log`). The harness grew
  from 52 to 55 because commit 2 replaces the old "realapps profile is rejected"
  assertion with "committed realapps plans php_binary" (3 checks) plus
  "php_session_zif profile is rejected" (1 synthetic-profile check).
- Realapps receipt reproduction (`--g2-profile realapps-8.5.10 --g2-decode
  zif_passthru --g2-total 131014`, geometry X1/X2/P/B0 from
  `receipts/realzif_entry2_1022/phase/mkrec_final.json`): target `0x22c54e0`,
  entry `php_binary`, `Q=0x78`, `L=130892`, `F=0x7ffff46ae190`,
  `K=-8796078587571`, delta `+0x13`, record 131,014 B, all checks ok — agrees
  with `mkrec_final.json` on target/L/Q/K/F.
- Profile-default total (`36101091`) also plans: `Q=0x7a`,
  `F=0x7ffff46ae192`, same target/K/delta, 36,101,091 B.
- Explicit `--g2-target 0x22c54c8`: exit 2, `target 0x22c54c8 is not 16 byte
  aligned`.
- Lab regression 8.5.10 / 8.4.25 / 8.1.34 / 7.4.33: G2 and G6 rc=0, record
  hashes unchanged (`aeb2021a…`, `02bc043f…`, `ed0629c4…`, `c7656340…`,
  `763495ca…`, `bf711e69…`, `15c23aff…`, `6ecfc8c4…`).
- 8.5.10 G2/G6 records remain byte-identical to the pre-patch baseline.

### Decisions applied

- **Q2 (USAGE vs HEAD).** Every USAGE hunk was diffed against `d16b0b2` and the
  committed receipts before applying. Adjustments made: the rebased wording
  cites `receipts/realchain_20261022/` (entry-1 `php` slot) and
  `receipts/realzif_entry2_1022/` (entry-2 `php_binary` slot) instead of the
  stale "pending" claim; the "19-byte symbols" claim was verified with
  `nm -S` on the installed realapps binary (`zif_system` and `zif_passthru`
  both size `0x13`); the poison section cites `receipts/realzif_entry2_1022/`
  (worker 143459, slot back to `0x9e6dd5`), both confirmed in that README.
- **Q3 (receipt constants).** `ZIF_RECEIPT` → `receipts/g6zif_1021`,
  `REALZIF_RECEIPT` → `receipts/realzif_entry2_1022`. Both replacement READMEs
  are byte-identical to the `/tmp` research dirs (sha256 `52b6d30c…`,
  `4d6a34b9…`). `F12B_RECEIPT` stays absolute: no F12b receipt is in the repo.
  `producer_unser.SOURCE_RECEIPTS` also stays absolute: `producerexp_20261021T184832Z`
  is not committed.
- **Q4 (tightening).** Skipped as instructed; `_decode_entry` still returns
  `None` for targets outside the serializer table.

### Deviations (all deliberate, flag if unwanted)

1. **Commit 1 is +236/−47, not +238/−47.** One sentence ("Because the generic
   builder resolves the target by entry name, on this profile it targets
   `0x22c54e0`…") was moved from commit 1 to commit 2, because while the
   `php_session_zif` gate was still in place that sentence was false. Final tree
   is unchanged; only the commit split differs.
2. **Commit 2 touches 5 files, not 2.** Beyond `record_builder` and the docs, it
   also had to remove stale "clean `zif_passthru` run pending" claims inside
   `addresses/g2_fpm_realapps_8510.json` (`status`,
   `zif_route.zif_passthru.behavior`, `zif_route.clean_run`, `caveats[7]`,
   `prerequisites[8]`). Leaving them would have contradicted
   `receipts/realchain_20261022/` and `receipts/realzif_entry2_1022/` in the
   same repo.
3. **Commit 3 is typed `chore:`, not `docs:`.** It changes module constants
   whose values appear in `result.json` metadata, not documentation text. The
   subject is easy to reword if you prefer `docs:`.
4. **Not swept (needs your call).** `addresses/*.json` `receipts` dicts and
   `USAGE.md` prose still carry `/tmp/opencode/research/...` paths — 37
   references across 8 files. Several point at receipts that are committed under
   different directory names (`g6zif_20261021T222434Z` → `receipts/g6zif_1021`
   is unambiguous, but `fpmgadget`, `fpmzend`, `fpmsurvive`, `veroff` and the
   F14 chain need per-receipt verification), so they were left untouched rather
   than guessed. This is a mechanical follow-up if you want it.

### Environment note

`tool/__pycache__` artefacts are produced by `py_compile` but are not tracked
(`git ls-files | grep -c pycache` = 0), so nothing leaked into the commits.
