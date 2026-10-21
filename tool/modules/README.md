# tool/modules: one line per module

| module | what it does |
|---|---|
| `arm.py` | multipart `PHP_SESSION_UPLOAD_PROGRESS` request builder: arm/probe bodies, HTTP/1.1 framing helpers, 14-byte frozen-profile disclosure analyzer (consolidated from the pre-restructure `native-output-leak.py`; same functions and standalone CLI). |
| `native-output-leak-stock-arm.py` | author-provided reconstructed "STOCK" arm body (frozen-profile arm machinery record); consumed by the driver, keep as separate provenance module. |
| `compact-stock-tail.py` | author-provided reconstructed "COMPACT" rearm body + final forged multipart (the negative-`used_slots` controlled copy stage); consumed by `--step chain`. |
| `g2_chain.py` | G2 FPM chain profile (`addresses/g2_fpm_8510.json`) plus the offline `--step g2` php_binary record plan: negative `used_slots` arithmetic, fake `php_unserialize_data` / `var_dtor_entries` placement, record bytes and self-checks; no transport and no address guessing. |
| `leak_stage.py` | mod_php leak stage, dry-only (`--step leak`): Set-Cookie PS(id) channel request shapes and the section C calibration plan; `leak_offset` is surfaced with its build binding (`addresses/apache_libphp.json`) and never guessed. |
| `producer.py` | facade over the CVE-109618 / CVE-109619 producer shape builders; mod_php producer TODO (missing module). |
| `producer_fpmwiki.py` | fpmwiki producer stage (`--step producer`): MediaWiki 1.46.2 anon-edit OOM, int N (5.7M receipt); offline byte-build default, `--live` gates the send, post_max_size ceiling guard. Promoted from the run_fpmwiki_20261021_173406 receipt. |
| `producer_modphp.py` | modphp producer stage (`--target modphp --step producer`): STOCK-arm body delegation (byte parity with the run_20261021T155303Z_armoom receipts, sha256-gated), int N = filename length ladder (262144/330000/400000 → alloc 266240/331776/401408), Cookie-transport sid (use_only_cookies=1), memory_limit knob pre-flight gate (absent/128M → refusal), dry default / `--live` gated. |
| `producer_unser.py` | offline unserialize OOM producer (master shape a, receipted 2M / 8M / 128M classes, sha256 receipt parity via `--verify-receipts`); dry default with zero sockets, `--live` needs an explicit endpoint URL, 128M class refused at the 8M post_max_size ceiling. |
| `producer_618.py` | CVE-2026-109618 staged multipart producer (heavy POST, OOM/stale machinery shape; inert forge default). Moved from `staged_618.py`. |
| `producer_619.py` | CVE-2026-109619 producer shape (149 x `t[]` reclaim records first → stale decoder state). Moved from `build_p1.py`. |
| `write_stage.py` | write stage, wired, dry-only (`--step write_stage`): builds the exact `attempt()`-shaped final multipart bytes via the documented `COMPACT.probe_body(...)` call and records them; no transport; the negative-`used_slots` math extraction (`stage_body()`) stays a NotImplementedError placeholder. |
| `profiles.py` | target + binary-profile registry: `BINARY_PROFILES` (per-build offsets) and `TARGETS` (wiki / wp live, modphp TODO missing module). |
