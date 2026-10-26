# Third-Party Notices

## Scope

php2slop is distributed under AGPL-3.0 (see `LICENSE`). This file credits the
upstream projects, proof-of-concept (PoC) material, and published shape notes
that informed this repository, and records the terms attached to each. It does
not relicense any third-party material and grants no rights that the upstream
authors did not grant. It is informational, not legal advice.

## 1. WoYinDao — CVE-2026-109618-CVSS-9.2-Critical

- Upstream: <https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical>
- File: `tools/exploit_128m.py`
- Commit: `a127f77009ca` (reviewed snapshot
  `99da6fb7dd7ecd4a95cd7188d77bb7e7785012eb`)
- Useful for: multipart framing and the 128M flood arms.
- License: MIT, Copyright (c) 2026 WoYinDao. The full notice is reproduced
  below and must be retained with redistributions of the adapted material.

## 2. PHP-UP-2026 — `poc0_109618.py` / `poc1_109619.py`

- Bundle author: J4ck3LSyN; the PoCs are credited to Andrew Dorman
  (@acd421).
- Published: <https://jackalsyn.com/posts/php-up-2026.html>
- Mirror: <https://github.com/cereZ23/php-up-2026>, commit
  `c63f145596dbe9cdd437d24ed2418f0c1e59bcc2`
- Files: `poc0_109618.py` (CVE-2026-109618) and `poc1_109619.py`
  (CVE-2026-109619)
- Useful for: the staged CVE-2026-109618 / CVE-2026-109619 producers.
- Terms: no open-source license. The bundle marks its material "Authorized
  defensive-research / scoped-engagement use only." That is a restricted
  permission statement, not an open-source license: it grants no redistribution
  rights and limits use to that stated scope. This repository's AGPL-3.0 does
  not relicense that material and cannot grant rights the upstream authors did
  not grant.

## 3. Zer061 / PHP-UP-2026 shape notes

- Upstream: `Zer061/CVE-2026-109618` (repository removed)
- Snapshot: <https://web.archive.org/web/20261021082048/http://github.com/Zer061/CVE-2026-109618/>
- Useful for: reconstructing the STOCK and COMPACT body shapes.
- License: none asserted; no license text was recoverable from the snapshot.
  The reconstruction contains no verbatim upstream code.

## 4. 9bie — php2shell-bypass-aslr-exp

- Upstream: <https://github.com/9bie/php2shell-bypass-aslr-exp>
- Useful for: stage-layout reference (A1 OOM, B1 leak, A2 OOM, then B2 fake
  `zend_array` / `zif_system`).
- Relationship: follows / is inspired by that project, not "taken from" it.
  Body geometry and offsets are this repository's own measurements rather than
  upstream values. Code-level reuse is unresolved.
- License: none asserted.

## Reviewed but not incorporated

Reviewed for cross-checking only; no code was copied from these.

- `ACD421/PHP` — the repository itself; the acd421 PoCs are credited above.
- `offline-ant/php2fix`
- `Percivalll/php2shell-wordpress-rce`
- `kengwang/php2shell-fpm-exp`
- `KillaBoi/StealMyBitcoin-PoC` — commit
  `3244dd00ffc35ae23cb0aba2ee8536061e7ea516`; no license; per-build PHP 8.4.26
  cli-server CTF PoC, reviewed for comparison only; no code copied. Its private
  key and payload are not reproduced here.

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

- The WoYinDao MIT notice must be retained with redistributions of the adapted
  multipart and flood-arm material.
- PHP-UP-2026 material has no open-source license and is restricted to
  authorized defensive research and scoped engagements; AGPL-3.0 does not
  relicense it.
- The Zer061 shape notes and the 9bie stage-layout reference carry no asserted
  upstream license; both are shape references only.

A repository-wide license cannot cure missing upstream permission. Whether to
keep, rewrite, or remove material derived from unlicensed sources is the
distributor's decision.
