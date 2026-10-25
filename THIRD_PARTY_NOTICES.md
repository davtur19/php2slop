# Third-Party Notices

## Scope

php2slop is distributed under AGPL-3.0 (see `LICENSE`). This file records the
third-party code, proof-of-concept (PoC) material, and published shape notes
that informed the local files listed below. It does not change the license of
any third-party material and grants no rights that the upstream authors did
not grant. Where a local file adapts upstream code, the upstream project, the
exact file, the reviewed commit, and the license are recorded here. This file
is informational, not legal advice.

| Local file | Upstream source | Relationship | Upstream license |
| --- | --- | --- | --- |
| `tool/modules/producer_flood.py` | WoYinDao/CVE-2026-109618-CVSS-9.2-Critical, `tools/exploit_128m.py` @ `a127f77009ca` | Adapted (`_multipart`, `arm_body`, flood/spray arm layout) | MIT |
| `tool/modules/producer_618.py` | PHP-UP-2026 bundle, `poc0_109618.py` @ `c63f1455` | Adapted (staged phase1/tail builders) | None stated; defensive-research / scoped-engagement terms only |
| `tool/modules/producer_619.py` | PHP-UP-2026 bundle, `poc1_109619.py` @ `c63f1455` | Adapted (staged phase1/tail builders) | None stated; defensive-research / scoped-engagement terms only |
| `tool/modules/native-output-leak-stock-arm.py` | Zer061 / PHP-UP-2026 shape notes (repository removed) | Reconstructed from shape notes; no verbatim upstream code | None asserted (repository unavailable) |
| `tool/modules/compact-stock-tail.py` | Zer061 / PHP-UP-2026 shape notes (repository removed) | Reconstructed from shape notes; no verbatim upstream code | None asserted (repository unavailable) |
| `tool/debian8424.py` | `9bie/php2shell-bypass-aslr-exp` | Stage-layout reference ("follows / inspired by"); code-level reuse unresolved | None asserted |

## 1. WoYinDao — CVE-2026-109618-CVSS-9.2-Critical (MIT)

- Upstream: <https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical>
- File: `tools/exploit_128m.py`
- Commit cited: `a127f77009ca`
- Snapshot reviewed: `99da6fb7dd7ecd4a95cd7188d77bb7e7785012eb`
- Local file: `tool/modules/producer_flood.py`
- Relationship: adapted. `_multipart()` keeps the upstream part order and
  formatting, and `arm_body()` rebuilds the upstream `flood` / `spray` arms
  (500,000 `X: v` headers, 1001 filler parts, `PHPSESSID` /
  `PHP_SESSION_UPLOAD_PROGRESS` / file-part tail). The terminal stage of the
  upstream chain is not copied.

The upstream file is MIT-licensed, Copyright (c) 2026 WoYinDao. The full
notice is reproduced below and must be retained with redistributions of the
adapted material in `producer_flood.py`.

## 2. PHP-UP-2026 — `poc0_109618.py` / `poc1_109619.py` (no open-source license)

- Bundle author: J4ck3LSyN. The PoCs are credited to Andrew Dorman
  (@acd421).
- Published: <https://jackalsyn.com/posts/php-up-2026.html>
- Mirror: <https://github.com/cereZ23/php-up-2026>, commit
  `c63f145596dbe9cdd437d24ed2418f0c1e59bcc2`
- Upstream files: `poc0_109618.py` (CVE-2026-109618) and `poc1_109619.py`
  (CVE-2026-109619)
- Local files: `tool/modules/producer_618.py` and
  `tool/modules/producer_619.py`
- Relationship: adapted. The local builders follow the upstream staged
  multipart shape: the `PHPSESSID` / `PHP_SESSION_UPLOAD_PROGRESS` preamble,
  149 `t[]` reclaim parts, 5120-byte fill segments, the 288-byte forged
  record, and the `B7kQpoc618` / `B7kQpoc619` boundary pattern.

The bundle states no open-source license and marks its material "Authorized
defensive-research / scoped-engagement use only." That is a restricted
permission statement, not an open-source license: it grants no redistribution
rights and limits use to that stated scope. The adaptations in
`producer_618.py` and `producer_619.py` remain subject to the upstream terms.
This repository's AGPL-3.0 does not relicense that material and cannot grant
rights the upstream authors did not grant.

## 3. Zer061 / PHP-UP-2026 — STOCK and COMPACT shape notes

- Original repository: `Zer061/CVE-2026-109618` (removed)
- Snapshot consulted:
  <https://web.archive.org/web/20261021082048/http://github.com/Zer061/CVE-2026-109618/>
- Local files: `tool/modules/native-output-leak-stock-arm.py` (STOCK) and
  `tool/modules/compact-stock-tail.py` (COMPACT)
- Relationship: reconstructed from the published shape notes plus the local
  LEAK module spec. The bodies are not verbatim upstream code and are not a
  copy of the author's original release; the reconstruction is documented in
  the module docstrings, with per-semantic VERIFIED/INFERRED markers.

No license is asserted for these upstream notes: the repository is no longer
available and no license text was recovered from the snapshot. If the
original author publishes license terms, they should be added here.

## 4. 9bie — php2shell-bypass-aslr-exp (stage-layout reference)

- Upstream: <https://github.com/9bie/php2shell-bypass-aslr-exp>
- Local file: `tool/debian8424.py`
- Relationship: the four-stage layout (A1 OOM -> B1 leak -> A2 OOM -> B2
  fake zend_array / `zif_system`) follows / is inspired by that project. The
  bodies, geometry, and offsets in `debian8424.py` are local measurements
  against `libapache2-mod-php8.4 8.4.24-1~deb13u1`.

Code-level reuse is unresolved: this is a shape reference, not a "taken
from" attribution. No license is asserted for 9bie's work.

## 5. Reviewed but not incorporated

The following projects were reviewed for cross-checking. No code from them
was copied into this repository.

- `ACD421/PHP` — the repository itself; the acd421 PoCs are credited in
  section 2.
- `offline-ant/php2fix`
- `Percivalll/php2shell-wordpress-rce`
- `kengwang/php2shell-fpm-exp`

## MIT license text (WoYinDao)

```text
MIT License

Copyright (c) 2026 WoYinDao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Licensing caveat

- `producer_flood.py` carries the WoYinDao MIT notice; retain it when
  redistributing that file or a substantial portion of it.
- `producer_618.py` and `producer_619.py` adapt PHP-UP-2026 material that has
  no open-source license and is restricted to authorized defensive research /
  scoped engagements. AGPL-3.0 does not relicense that material.
- STOCK / COMPACT and `debian8424.py` are shape references only; no upstream
  license is asserted for them.

Whether to keep, rewrite, or remove the no-license modules is a decision for
the distributor; a repository-wide license cannot cure missing upstream
permission.
