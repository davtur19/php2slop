# Public PoC / technical-analysis search — PHP 8.4 mod_php + PHP-FPM "php2shell" RCE

**Task:** find published, non-embargoed PoCs or technical analyses of the CVE-2026-109618 / CVE-2026-109619
(GHSA-w8hw-w9fx-j79w) chain we are testing, judge usefulness, and say whether any public work already
covers (a) the A1→B1→A2→B2 chain, (b) ASLR bypass, (c) a stock WordPress/MediaWiki endpoint, (d) FPM.

**Search window:** 2026-10-21 → 2026-10-23 (UTC). **Report generated:** 2026-10-23T12:29:56Z.

**Method / handling rules honoured**
- Only public pages were read: GitHub repos and issues, vendor blogs, GHSA/php-src advisories, Exploit-DB,
  SANS ISC, Substack, aggregator snippets. No private repos, no leaks, no credentials.
- **No PoC was downloaded to disk and none was executed.** Where a page renders exploit source inline
  (Exploit-DB, GitHub), it was read as text only for classification; nothing was saved or run.
- Repo census: GitHub API `q=php2shell` → 779 repos; the credible subset was opened by hand. The long tail is
  forks/renames of the same 4–5 artifacts and was not individually cited.
- Queries used: both CVE IDs, the GHSA id, commit `31c0ea7d7f`, `php_session_rfc1867_callback`, "multipart UAF",
  9bie / ikow / Qi Deng / 78ResearchLab / devploit / dinosn / godylockz / eness / RemiPelloux, plus
  "wordpress", "mediawiki", "php-fpm", Exploit-DB and Packet Storm.

---

## 1. Bottom line

1. **An exact public full chain does exist — for PHP 8.4.26 NTS mod_php only.** `9bie/php2shell-bypass-aslr-exp`
   is a complete, working A1→B1→A2→B2 exploit with the same stage naming we use, and the same technique is now
   packaged as a turnkey script on **Exploit-DB 52704** (OffSec, 2026-10-22) — turnkey for *its own lab profile*
   (single worker, `display_errors=1`, `memory_limit=8M`), not for a stock server. ASLR is solved publicly, by
   two leaks (Zend-MM chunk base, then libphp base).
2. **No public PoC solves a stock WordPress or MediaWiki endpoint.** 9bie's own issue #1 asks exactly that and
   the author answers "还不行" ("not yet"). The WordPress demos that exist (Wiz, and per an unverified claim Calif)
   use the *other* bug, CVE-2026-109619 (OPcache type confusion / fatal-error backtrace), and publish no code.
3. **No public PoC demonstrates FPM RCE with code.** Public FPM results are crash/DoS, GDB screenshots, or
   paywalled. The php-src advisory itself says the FPM variant of the startup-failure sequence does not survive.
   Our FPM work is therefore not duplicated by anything public.
4. **Nothing public is turnkey against a hardened, multi-worker production target.** Every runnable artifact
   requires at least one of: `display_errors=1`, `memory_limit=8M`, or a **single** prefork worker.
   9bie's is the only one that claims `display_errors=Off` + `memory_limit=128M` + `MaxRequestWorkers=150`,
   and its own issue tracker documents reliability gaps and failures on 8.3.35 / 7.4.33.

**Most useful source:** `https://github.com/9bie/php2shell-bypass-aslr-exp` (plus its issue #3).
It is the reference implementation of our exact chain and the only public work that addresses the hardened,
multi-worker, ASLR-on case. Exploit-DB 52704 is the most convenient *packaging* of the same technique, but it
weakens the target model (single worker, `display_errors=1`, 8M) and is derived from 9bie/eness.

---

## 2. Table A — sources that ship an end-to-end mod_php chain

| # | URL | Title | Author / date | Public status | Target PHP + SAPI | Exact prerequisites | Code or writeup | Claimed evidence | A1/B1/A2/B2 | Verdict |
|---|-----|-------|---------------|---------------|-------------------|---------------------|-----------------|------------------|-------------|---------|
| A1 | https://github.com/9bie/php2shell-bypass-aslr-exp | php2shell-bypass-aslr-exp | 9bie, Oct 2026 | Public repo (code) | 8.4.26 NTS, **mod_php** (Apache 2.4.69 prefork, Debian 13) | page = `<?php echo "OK\n"; ?>` (no `session_start()`), files session handler, `php.ini-production` (`display_errors=Off`, `memory_limit=128M`), `MaxRequestWorkers=150`; pins a worker with 149 holders; chunked multipart to bypass `post_max_size` | Full exploit code + README | 10/10 on "official" profile, 20/20 single-worker, ~3–4 s; leaks chunk base and libphp base, then `pDestructor=zif_system` | Yes — identical stage naming; offsets `zval_ptr_dtor=libphp+0x65EB60`, `zif_system=libphp+0x465370`, `S=main+0xF8398`, `hsv=main+0x7D720` | **Directly reusable (reference) / technique only for our hardening** — closest public match; not turnkey |
| A2 | https://www.exploit-db.com/exploits/52704 | PHP2Shell (CVE-2026-109618) – PHP core versions after v5.4 – RCE | **OffSec**, 2026-10-22, EDB-ID 52704, type remote, platform PHP | Public | 8.4.26 **mod_php**, profiles `bookworm` (official `php:8.4.26-apache`, Apache 2.4.69) and `lab` (Apache 2.4.68) | **`display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`, `session.use_cookies=1`, `session.use_strict_mode=0`, `session.upload_progress.enabled=1`, single-worker prefork**; command ≤ **14 bytes** | Full Python 3 exploit, self-described as *"credited to 9bie and eness, adjusted using AI by OffSec"* | Ships `docker/` target + `offsets.py`; reads proof file written by `id>/out/p1`; 3-stage leak/overwrite | Yes — same 4 stages, renamed: worker rotation → heap leak → libphp leak → `upload_progress` fake-ref → `pDestructor=zif_system` | **Technique only, weaker target model** — not stock; requires 8M + `display_errors=1` + 1 worker |
| A3 | https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC | php2shell PoC (both CVEs) | eness, Oct 2026 | Public repo | 8.4.26 **mod_php** | `display_errors=1`, `memory_limit=8M`, single worker | Full code | ~931 stars; demo run | Yes (same stages) | **Technique only** — same lab-only prerequisites; effectively a 9bie port |
| A4 | https://github.com/godylockz/cve-2026-109618-php2shell | cve-2026-109618-php2shell | godylockz, Oct 2026 | Public repo | 8.4.26 `php:8.4.26-apache` **mod_php** | `display_errors=On`, `memory_limit=8M` (hard requirements, documented) | Python port of 9bie | Documented run against the official image with those settings; notes a WordPress lab on 8.3.13 **does not leak** | Yes | **Technique only** — honest about prerequisites; confirms the 8.3.x leak failure |
| A5 | https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit | PHP2Shell Full-Chain Exploit | 78ResearchLab, Oct 2026 | Public repo | **mod_php only**; states FPM is out | single prefork worker, `session.upload_progress=On`, build-specific offsets, brute-forces `r0` | Full code + writeup | Working mod_php run | Yes | **Technique only** — explicitly: *"On PHP-FPM the worker is respawned on OOM, so this chain does not land"* |
| A6 | https://github.com/devploit/php2shell | php2shell toolkit / per-build profiles | devploit, Oct 2026 | Public repo | Verified 8.5.11 / 8.5.10 / 8.4.26 / 8.4.25 **mod_php** | per-build offset profiles; `display_errors=Off` and FPM listed as **open research items**; HTTPS unverified; 14-byte command | Full code + profiles | Verified RCE on the four builds above | Yes | **Technique only** — best *offset-portability* reference; no FPM, no HTTPS |

## 3. Table B — partial, adjacent, or claim-only sources

| # | URL | Title | Author / date | Public status | Target + SAPI | Prereqs / scope | Code or writeup | Evidence | Relation to chain | Verdict |
|---|-----|-------|---------------|---------------|---------------|-----------------|-----------------|----------|-------------------|---------|
| B1 | https://github.com/9bie/php2shell-bypass-aslr-exp/issues/1 | "how to test on wordpress?" | 9bie (reply), Oct 2026 | Public issue | mod_php | — | Writeup/answer | Author: **"还不行"** ("not yet"), points to #3 | Direct: our exact question | **Decisive negative** — no public WP path from this chain |
| B2 | https://github.com/9bie/php2shell-bypass-aslr-exp/issues/3 | reliability caveats | 9bie + reporters, Oct 2026 | Public issue | mod_php | — | Field reports | `Set-Cookie` sometimes absent / no heap pointer; parser accepted only `0x7f…` while the env used `0x75–0x7c` (fixed → worked); leaks failed on **8.3.35 / 7.4.33**, so offset swap is not portable; 14-byte command limit | Direct | **Critical caveat source** — bounds how much we can copy |
| B3 | https://github.com/ikow/php2shell-poc | php2shell 5-chain framework | ikow (Qi Deng), Oct 2026 | Public repo; **Chains D/E exploits paid-only** | A: session+LFI, B: app `unserialize`, C: handler mismatch (public); D: **mod_php zero-dependency**, E: **FPM `BG(unserialize)`** | D/E behind paywall | Mixed: public code for A/B/C, writeup for D/E | Chain E proof is GDB/error output, **no public uid marker** | Chain E is the FPM variant of our A2/B2 idea | **Unverified** for FPM; public A/B/C need app cooperation → **not relevant** to a stock endpoint |
| B4 | https://qideng.substack.com/p/php2shell-dissecting-phps-critical | "PHP2Shell: dissecting PHP's critical…" | Qi Deng (ikow), Oct 2026 | Public post; code paywalled | mod_php + FPM discussion | — | Writeup | Describes Chain E FPM path; no runnable public artifact | Direct conceptual overlap with our FPM question | **Technique only / unverified** |
| B5 | https://www.wiz.io/blog/php2shell-php-rce | PHP2Shell PHP RCE | Wiz, Oct 2026 | Public blog | `wordpress:latest`, `drupal:latest`, `joomla:latest` | Default images; pre-auth | **Writeup only — no exploit code published** | Claims pre-auth RCE on all three | WordPress path uses **CVE-2026-109619** (OPcache type confusion); Drupal used a fatal-error backtrace | **Not our A1/B1/A2/B2 chain**; relevant only as "what a stock-app win looks like" |
| B6 | https://www.exaforce.com/blogs/php2shell-php-rce-analysis | PHP2Shell analysis | Exaforce, Oct 2026 | Public blog | mod_php demo; FPM affected | — | Writeup | States the working exploit was demonstrated on **mod_php**; FPM affected but no public chain | Confirms the mod_php/FPM split | **Corroborating** |
| B7 | https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp | php-src advisory (FPM section) | PHP project, Oct 2026 | Public advisory | FPM + mod_php | — | Authoritative text | FPM *"terminates a child when this startup fails, so that exact sequence does not survive"*; the validated FPM path needs state published **during application execution**, a fatal error, then upload-progress as early consumer | Defines why our A1 must be re-derived for FPM | **Authoritative constraint** |
| B8 | https://github.com/php/php-src/commit/31c0ea7d7f | "Avoid state corruption via bailout" (8.5.12) | PHP project | Public commit | core | — | Patch, 423 files | Not a PoC; the fix boundary | Fix-diff reference for what the bug *is* | **Not a PoC** — useful only as patch ground truth |
| B9 | https://github.com/dinosn/php-cve-2026-10961x-lab-poc | cve-2026-10961x lab PoC | dinosn, Oct 2026 | Public repo | 8.5.11 **mod_php**, "stock-config" claim | `display_errors=On`, single worker, `memory_limit=16M`, `post_max=32M`, `pm=static max_children=1` for FPM | Code | 4-request RCE 12/12 under those settings | Yes for mod_php | **Technique only** — "stock" claim does not survive its own ini list |
| B10 | same repo, FPM section | FPM stale `BG(unserialize)` | dinosn | Public | FPM | — | Code | Stale state only produces **worker SIGSEGV / DoS**; RCE unproven | FPM variant of A2 | **Not RCE** — DoS only |
| B11 | https://github.com/RemiPelloux/php-session-upload-progress-uaf | php-session-upload-progress-uaf | Remi Pelloux, Oct 2026 | Public repo | none (analysis harness) | — | Analysis + reproducer | Independent confirmation of the session/upload-progress UAF mechanism; **explicitly no RCE, no FPM testing** | Explains A1/A2 primitives | **Technique only** (mechanism corroboration) |
| B12 | https://isc.sans.edu/diary/Critical+PHP+Vulnerability+CVE2026109618+CVE2026109619+infocon+yellow/33440/ | Critical PHP Vulnerability (CVE-2026-109618, CVE-2026-109619) [infocon yellow] | SANS ISC, 2026-10-21 | Public | mod_php (general) | — | Writeup + request-shape IOCs | Early third-party PoC (jackalsyn) described as **unreliable/incomplete**; trigger involves a ~5 MB filename; `session.upload_progress.enabled=0` as partial mitigation | Adjacent | **Not relevant for reuse**; useful for detection only |
| B13 | https://www.vulncheck.com/blog/php2shell-vulnerabilities | PHP2Shell Vulnerabilities: CVE-2026-109618 and CVE-2026-109619 | VulnCheck, 2026-10-22 | Public | cross-check | — | Writeup + canary/IOC data | Their own exploit reached RCE on **8.4.26, x86-64, ASLR on, `display_errors=off`** (not published); states only **one public** PoC (9bie) bypassed ASLR on x86-64, single version, default heap, and did not work outside that setup; ARM64 ASLR is bruteforceable | Independent validation of A1 and of the ASLR claim | **Corroborating** |
| B14 | https://packetstormsecurity.com/ | Packet Storm search | — | Public | — | — | **No dedicated php2shell entry found**; only a Vulners aggregator reference | — | — | **No hit** |
| B15 | GitHub API `search/repositories?q=php2shell` | 779-repo census | 2026-10-23 | Public | — | — | Metadata only | Long tail = forks/renames of A1/A3/A4/A5/A6; no independent 7th chain found | — | **No new signal** |
| B16 | (no public URL located) | Calif claim | Calif, Oct 2026 | Public claim | stock apps | — | **Claim only, no code located** | Version strings as reported, not independently verified here | Would be the only stock-app claim | **Unverified — do not rely on** |

---

## 3b. Table C — vendor analyses (no public exploit code)

These do not ship code but constrain what is true. All are public blogs, Oct 2026.

| URL | Title | Author / date | Target + SAPI | Claim of note | Verdict |
|---|---|---|---|---|---|
| https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/ | PHP2Shell – critical vulnerabilities in PHP | Datadog Security Labs, Oct 2026 | 8.5.11 reproduction | Independently reproduced the OOM corruption with one unauthenticated POST; app-level auth cannot block it because PHP parses before app code | Writeup only — **corroborating** |
| https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/ | CrowdStrike protects customers from PHP2Shell | CrowdStrike, 2026-10-21 | mod_php | Private exploit "operated consistently across x86-64 and ARM", "reliable across worker restarts"; on ARM defeated ASLR with HTTP only; single anonymous POST → shell | **No code** — important *existence proof* for multi-worker reliability |
| https://sansec.io/research/php2shell | PHP2Shell: PHP RCE | Sansec, Oct 2026 | core | Mitigations `memory_limit=-1` + `session.upload_progress.enabled=0`; relays core dev warning that upload-progress off alone is insufficient | Writeup only — mitigation/detection |
| https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619 | PHP2Shell – critical PHP RCE | Abstract Security, Oct 2026 | core | Publishes ModSecurity/Suricata rules built on ikow's Chains A/B/C shapes (PHPSESSID as form field, PHP tag in filename, serialized syntax in filename) | Writeup only — detection; **confirms chain A/C request shapes** |
| https://www.tanium.com/blog/php2shell-responding-to-cve-2026-109618-and-cve-2026-109619 | Responding to CVE-2026-109618 / -109619 | Tanium, Oct 2026 | mod_php | "Dozens of public PoCs exist, but very few work and **none bypass ASLR on x86-64**" | Writeup only — **stale**: superseded by 9bie/VulnCheck on 2026-10-22 |
| https://watchtowr.com/intelligence/php-cve-2026-109618-faq/ | PHP2Shell FAQ | watchTowr, Oct 2026 | all | Fixed versions 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | Reference only |
| https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained | PHP2Shell explained | Picus, Oct 2026 | all | Advisory wording: disabling upload progress "blocks the confirmed session paths but not other variants" | Reference only |

---

## 4. What the public record actually establishes

### 4.1 The chain itself is public and matches ours exactly
9bie's stage names are literally A1/B1/A2/B2-equivalent:
`send_cookie` OOM at request end → stale session id gives an OOB read that leaks both the Zend-MM chunk and a
libphp pointer → cheap OOM on `PS(hash_serialize_verifier)` → overwrite with a fake array whose
`pDestructor = zif_system`. Everything downstream (A3–A6, A2/EDB) is a port of this. So the *mechanism* is
fully corroborated in public; we are not re-deriving something unknown.

### 4.2 ASLR is publicly solved — for one build family
Two leaks, both through `Set-Cookie`:
- heap/chunk base from a decoded cookie containing many `0x7f…` pointers (2 MB-aligned mode), and
- libphp base from the stale-id read where the `HashTable` page begins at `PS(id)+0x18`
  (`nNextFreeElement|pDestructor`), page-aligned on 4 KB (the "official image maps at 4 KB, lab at 2 MB" note
  in EDB 52704 is a genuine correction to 9bie).

No public work bypasses ASLR any other way, and none avoids leaking. VulnCheck independently confirms only
9bie *publicly* succeeded on x86-64, on 8.4.26, with default heap configuration — while also saying their own
(non-published) exploit reached RCE on 8.4.26/x86-64 with ASLR **on** and `display_errors=off`, i.e. the ASLR
leak is reproducible but was publicly released for exactly one build. CrowdStrike goes further, claiming a
private exploit reliable "across worker restarts" on both x86-64 and ARM, with ARM ASLR defeated over HTTP
only — no code, so this remains a claim, but it means the multi-worker reliability 9bie struggles with is not
known to be impossible.

Note the record moved fast: Tanium (2026-10-21) still wrote "none bypass ASLR on x86-64"; VulnCheck and 9bie
(2026-10-22) contradict that. Early summaries of this bug family are already stale.

### 4.3 The stock WordPress / MediaWiki endpoint is **not** publicly solved
- 9bie issue #1 is the direct question; the answer is "not yet", with the reporter pointed at issue #3.
- 9bie issue #3 shows the leak parser was environment-sensitive (`0x7f` only vs an actual `0x75–0x7c` heap) and
  that 8.3.35 / 7.4.33 leaks simply fail. godylockz independently reports a WordPress lab on 8.3.13 does not leak.
- The only public stock-CMS wins (Wiz: `wordpress:latest`, `drupal:latest`, `joomla:latest`) belong to
  **CVE-2026-109619**, not to our chain: WordPress via OPcache type confusion, Drupal via fatal-error backtrace.
  No code was released for either.
- Consequence: for a stock WordPress/MediaWiki page we would need either 109619 or an application-level producer
  of the corrupted state. Nothing public hands us that for 109618.

### 4.4 FPM is publicly **unproven**
- 78ResearchLab: "on PHP-FPM the worker is respawned on OOM, so this chain does not land."
- dinosn: FPM stale `BG(unserialize)` yields worker SIGSEGV/DoS only.
- ikow Chain E (FPM) is paid-only and evidenced by GDB/error text, not by a public command-execution marker.
- GHSA-6wmf-4rv5-p3rp is explicit: FPM terminates the child when the startup-time sequence fails, so the
  mod_php ordering does not transplant; the FPM path the maintainers validated needs the state published during
  **application execution**, then a fatal error, then upload-progress as the early consumer.
- Nothing public contradicts our working assumption that the FPM variant needs a different producer/consumer order.

### 4.5 Every runnable artifact weakens the target model
| Artifact | `display_errors` | `memory_limit` | workers | Other |
|---|---|---|---|---|
| 9bie (A1) | **Off** (production ini) | 128M | **150**, pins one with 149 holders | chunked multipart to beat `post_max_size` |
| EDB 52704 (A2) | **On (1)** | **8M** | **1** | `max_input_vars=1000`, `use_strict_mode=0` |
| eness (A3) | **On (1)** | **8M** | **1** | — |
| godylockz (A4) | **On** | **8M** | 1 | — |
| 78ResearchLab (A5) | — | — | **1** | brute-forces `r0` |
| devploit (A6) | Off (listed open) | — | — | per-build offsets, HTTPS unverified |
| dinosn (B9) | **On** | **16M** (post 32M) | **1** | "stock" in name only |

Only 9bie claims the hardened, multi-worker case — and even it is a lab demo with acknowledged gaps, not a
weaponised exploit. The EDB "bookworm / official image" profile is the official image *plus* their docker ini
overrides; it is **not** `php.ini-production` and **not** the stock Apache worker count.

### 4.6 Two practical details worth stealing (not the code)
- The leak parser must accept the actual heap prefix range, not just `0x7f…`. EDB 52704 still hardcodes
  `0x7F0000000000 ≤ v < 0x800000000000` in both leak stages, so it inherits 9bie issue #3's failure mode on
  hosts whose heap lands in `0x75–0x7c`. That is a concrete, checkable bug in the most "official" public release.
- EDB 52704 rotates workers over plain HTTP (abort the child; prefork forks a fresh one) instead of pinning.
  That only works with a single worker; it is not a substitute for 9bie's 149-holder pinning at
  `MaxRequestWorkers=150`.

---

## 5. Verdict summary

| Question | Public answer | Confidence |
|---|---|---|
| Exact public PoC for A1/B1/A2/B2? | **Yes** — 9bie (code), mirrored by EDB 52704, eness, godylockz, 78ResearchLab, devploit | High |
| Public ASLR bypass for this chain? | **Yes** — two `Set-Cookie` leaks; only demonstrated on 8.4.26 mod_php, default heap | High |
| Public PoC for stock WordPress / MediaWiki endpoint? | **No.** 9bie: "not yet". Wiz uses 109619 and ships no code; Calif claim unverified | High |
| Public FPM RCE with code? | **No.** DoS/crash only; paid/unverified Chain E; advisory says the sequence does not survive | High |
| Anything turnkey for hardened production (display_errors=Off, 128M, 150 workers)? | **No.** 9bie is the closest and is a lab demo with open reliability issues | Medium-high |

**Recommendation for our work:** use 9bie (repo + issues #1/#3) as the primary technical reference and
EDB 52704 only as an independent packaging cross-check of offsets/stage shapes. Treat the public record as
*solved mechanism, unsolved deployment*: our remaining value is precisely (i) a stock WordPress/MediaWiki
endpoint and (ii) FPM — neither of which any public artifact demonstrates.

---

## 6. Sources (retrieved 2026-10-23)

Primary: `github.com/9bie/php2shell-bypass-aslr-exp` (+ `/issues/1`, `/issues/3`);
`exploit-db.com/exploits/52704`; `github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit`;
`github.com/devploit/php2shell`; `github.com/ikow/php2shell-poc`; `qideng.substack.com/p/php2shell-dissecting-phps-critical`;
`github.com/dinosn/php-cve-2026-10961x-lab-poc`; `github.com/godylockz/cve-2026-109618-php2shell`;
`github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC`;
`github.com/RemiPelloux/php-session-upload-progress-uaf`.
Vendor/advisory: `wiz.io/blog/php2shell-php-rce`; `exaforce.com/blogs/php2shell-php-rce-analysis`;
`github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp`; `github.com/php/php-src/commit/31c0ea7d7f`;
`isc.sans.edu/diary/…/33440`; `vulncheck.com/blog/php2shell-vulnerabilities`;
`crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days`;
`securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php`; `sansec.io/research/php2shell`;
`abstract.security/blog/php2shell-…`; `tanium.com/blog/php2shell-…`; `watchtowr.com/intelligence/php-cve-2026-109618-faq`.
Negative: Packet Storm (no dedicated entry); GitHub census (no independent chain beyond the above).

**Caveats:** star counts, dates and "verified" badges are as displayed by the platforms and were not audited.
No claim in this report is based on running any third-party code; all results above are the authors' claims or
textual evidence read from the pages.
