# PHP 8.4.26 multi-worker audit (G51)

Independent audit of the PHP 8.4.26 mod_php multi-worker report
(SHA-256 `57ddf8596bdbe0eecdae00a0aace3dc990f9b0c9879b4ec869311fda9213ada2`,
516 lines). This directory contains the audit only, not the run artifacts.

## Verdict

**Promote with caveats — not verbatim.** The core A1 -> B1 -> A2 -> B2 chain was
independently confirmed on stock `php:8.4.26-apache` (prefork 5/150). Four
target-written proofs exist (3 blind first attempts plus 1 extra full-A1 pool),
and in every success the proof child SIGSEGVs after writing the proof.

## Scope and configuration

- **Not a WordPress-bootstrapped RCE.** The tested endpoint is the 28-byte
  `/wp-content/index.php` silence file (`<?php // Silence is golden.`); no
  `wp-config.php`, plugin, theme, or front controller is loaded. "WordPress
  7.1.3" denotes the official docroot only.
- **`php.ini-production` was mounted** (the image's own file, unmodified). The
  default no-INI startup was **not tested** and uses different heap geometry.
  Scope the result to the production-INI deployment.

## Rates

Blind series: **3/60** on the **993,911-B A1 shrink** — descriptive Wilson
1.7-13.7%, a serial/clustered protocol with effective independent units of
about 3 pools, not a per-request probability. First attempts were 3/3;
post-first attempts were 0/57. The full 1,060,211-B A1 has one proof (extra,
non-protocol series D) and no measured rate.

## Open issues

- **Heap freshness is a hypothesis, not measured.** The data show a
  correlation with prior B1 exposure; they do not distinguish freshness from
  persistent corruption or an A1-on-polluted-child effect.
- **G51 is not unconditionally closed.** It is closed only for the
  production-INI deployment. The no-INI default remains untested, and no stock
  multi-worker WordPress-bootstrap cell was demonstrated.

See `ERRATA.md` for the required corrections and `audit.md` for the full
claim-by-claim audit.
