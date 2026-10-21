# tool/modules — one line per module

| module | what it does |
|---|---|
| `arm.py` | multipart `PHP_SESSION_UPLOAD_PROGRESS` request builder: arm/probe bodies, HTTP/1.1 framing helpers, 14-byte frozen-profile disclosure analyzer (consolidated from the pre-restructure `native-output-leak.py`; same functions and standalone CLI). |
| `native-output-leak-stock-arm.py` | author-provided reconstructed "STOCK" arm body (frozen-profile arm machinery record); consumed by the driver, keep as separate provenance module. |
| `compact-stock-tail.py` | author-provided reconstructed "COMPACT" rearm body + final forged multipart (the negative-`used_slots` controlled copy stage); consumed by `--step chain`. |
| `producer.py` | facade over the CVE-109618 / CVE-109619 producer shape builders; mod_php producer TODO (missing module). |
| `producer_618.py` | CVE-2026-109618 staged multipart producer (heavy POST, OOM/stale machinery shape; inert forge default). Moved from `staged_618.py`. |
| `producer_619.py` | CVE-2026-109619 producer shape (149 x `t[]` reclaim records first → stale decoder state). Moved from `build_p1.py`. |
| `write_stage.py` | documented stub — not implemented (chain stage write_stage); the live call path is `COMPACT.probe_body(...)` inside `tool/php2shell.py:attempt()`. |
| `profiles.py` | target + binary-profile registry: `BINARY_PROFILES` (per-build offsets) and `TARGETS` (wiki / wp live, modphp TODO missing module). |
