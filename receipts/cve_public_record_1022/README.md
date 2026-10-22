# CVE-2026-109618 / CVE-2026-109619 — public-record research report

Receipt: `/tmp/opencode/cve_1792633871`
Prepared: 2026-10-22
Scope: desk research (NVD/MITRE, PHP advisories and source, distros, hosting panels, researcher writeups, public PoCs). No exploit was executed in this pass; internal lab results cited in the report are labelled as separate receipts.

## Verdict

* **Both IDs are public**, published 2026-10-21 by the PHP CNA (`security@php.net`), state `PUBLISHED`; MITRE timestamps `13:48:34Z` (618) and `13:54:43Z` (619), NVD `14:17:09Z` for both.
* **They are not classic PHP "session deserialization" bugs.** The CNA assigns CWE-416/755/824/1325/1419; **CWE-502 is not assigned**. 618 is "RCE via OOM corruption"; 619 is "RCE via stale global state".
* **The session upload-progress path is a confirmed 619 vector.** PHP's GHSA-619 lists "Session upload progress lifecycle: confirmed"; `session.upload_progress` is enabled by default, needs no `session_start()`, and can supply the producer, the consumer, or both. The official mitigation is `session.upload_progress.enabled=0` plus a worker restart.
* **Attribution conflict, flagged not hidden:** Wiz and Sansec classify the upload-progress unserializer UAF under 618, while PHP's GHSA puts the session/decoder lifecycle under 619. One patch fixes both; the session chain exercises both halves.
* **Affected/fixed:** PHP 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12; fixed 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 on 2026-10-21. 8.1 and older are EOL upstream; minimal source backports exist for 7.4/8.0/8.1; distros and researchers describe branches back to 5.4 as affected.
* **Severity:** CNA CVSS 4.0 **9.2 Critical** (`AC:H/AT:P`), NVD CVSS 3.1 **9.8 Critical** (`AC:L`); Red Hat 8.1, SUSE 8.1 v3 / 9.2 v4, Ubuntu Critical. The CNA/NVD complexity mismatch is real and is quoted with its source.
* **Exploitation status is contested:** not in CISA KEV as of 2026-10-21; NCSC NZ says it is aware of reports of active exploitation; Sansec's timeline records watchTowr pre-release RCE confirmation and Cloudflare early attacks. Treated as reports, not CISA confirmation.
* **Public PoCs exist but none was independently verified here.** The most concrete is 9bie's PHP 8.4.26 + Apache prefork + mod_php chain; its `display_errors=1`/`memory_limit=8M` are lab constraints, not CVE requirements. Internal reproduction is in `9bie_1022/`.

## Artifacts

| group | files |
|---|---|
| advisories | `CVE-2026-109618.json`, `CVE-2026-109619.json`, `GHSA-6wmf-4rv5-p3rp.{json,txt}`, `GHSA-w8hw-w9fx-j79w.{json,txt}`, `nvd_sess.json`, `nvd_sp.json`, `mitre618.json`, `mitre619.json`, `meta.json`, `k1.json`, `g.json` |
| distro/vendor | `DLA-4848-1.html`, `DSA-6574-1.html`, `rel8427.json`, `rel8512.json`, `x.json` |
| fixes | `fix.patch`, `alt.patch`, `session.diff` |
| source snapshots | `session-8.4.26.c`, `session-8.5.11.c`, `session-8.5.12.c`, `var.c` |
| researcher material | `9bie.md`, `9b_NOTES.md`, `9b_ASLR_PURE_HTTP.md`, `ub619.md`, `commit.json`, `cmp.json`, `c2.json`, `ub.json`, `ubj.json` |
| report | `report.md` — full narrative with section-by-section evidence and 60+ citations |

### `fix.patch` vs `alt.patch`

Both are the same **389-file** unified diff with the same subject ("Avoid state corruption via bailout") and the same code; they differ only in the `From` line: `fix.patch` is the released commit **`3584a98bda0f`**, `alt.patch` is the security-branch commit **`01a40e89fbfc`**. They are kept side by side because the report cites both provenance paths; `sha256` values are in `SHA256SUMS`.

## Notes

The report deliberately separates **Official / Vendor / Third-party / Author claim / Project-internal** labels. Values that are commonly misquoted (CVSS complexity, affected lower bound, KEV status) are given with their source. No credentials or personal data are included; the researcher pages are public.
