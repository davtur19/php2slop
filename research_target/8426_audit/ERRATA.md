# ERRATA — required corrections to the 8.4.26 multi-worker report

These corrections apply to the audited report
(`57ddf8596bdbe0eecdae00a0aace3dc990f9b0c9879b4ec869311fda9213ada2`).
The archived report is preserved unchanged; apply these before any promotion.
Item IDs refer to the audit's §4.

| # | Defect | Required correction |
|---|---|---|
| D1 | "WordPress RCE" scope overclaim | The endpoint is the 28-byte `/wp-content/index.php` silence file; no WordPress bootstrap, `wp-config.php`, plugin, or theme is loaded. Do not call it an application-level WordPress RCE. |
| D2 | Hidden `php.ini-production` mount | State that the image's `php.ini-production` is mounted unmodified and that the default no-INI startup was not tested (different heap geometry). Remove unqualified "stock upstream/default". |
| D3 | Heap freshness asserted as fact | Downgrade to a hypothesis: success correlates with prior B1 exposure and is consistent with a fresh-child requirement; freshness itself was not measured. |
| D4 | Two sentences contradicted by the report's own data | (a) A/B/D span five PIDs but C spans six (A2 hit 47; A1 child 18 was not A2-hit). (b) "The GETs are the only non-chain requests" is false for series A, which has a pre-chain declared-length control at 19:19:56 (PID 19, 200/192). |
| D5 | `out/b1_declared_control.json` self-contradiction | `body_bytes` is `33128677`; the response body is 0 (192 B total, `Content-Length: 0`, no `Set-Cookie`). Fix the field to 0 or rename it to a request-size field, and keep the correct meta as authoritative. |
| D6 | Wilson independence assumption | Intervals assume i.i.d. trials, but the 20 attempts per pool are serially dependent. Label them descriptive Wilson intervals for a serial/clustered protocol; effective independent units are 3 pools, not 60 attempts. |
| D7 | Wrong D exclusion rationale | D is excluded as an extra, non-protocol, full-A1 run outside the fixed 20-attempt blind denominator — not because its pool freshness was unknown (A/B/C pools were also known fresh). "Blind" means blind routing. |
| D8 | 3/60 A1 variant not stated up front | The blind 3/60 is for the 993,911-B A1 shrink (`build_a1(big_len=7150)`), not the full 1,060,211-B A1. The full A1 has 1/1 (series D) and no measured rate. |
| D9 | G51 closure stated unconditionally | G51 is closed only for the production-INI deployment. The no-INI default remains a variant/gap, and no stock multi-worker WordPress-bootstrap cell was demonstrated. |

## Also recommended (minor)

- Distinguish the 9x B1 `200/192` session-startup no-ops from the
  `post_max_size` control.
- Time-scope "the A1/leak child survives" to the success sequence; later reuse
  can abort.
- Replace "briefly six after a crash" with the actual causality: spares 46/47
  existed before the proof crash; final pools were 5/6/6/5.
- Cite the pre/post docroot manifest, not `docker diff`, as the integrity
  evidence for the read-only bind mount.
- Say "no evidence this run touched pre-existing containers/services", not
  "no host changes".
- Remove or cite the no-INI `S = main + 0xF5398` sentence; it has no artifact
  in this run.
- Label proof-write provenance and leak size/decoded count as
  ownership/timing/parser inference, not syscall-verified measurements.
