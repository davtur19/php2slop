# Independent audit — PHP 8.4.26 multi-worker RCE report (G51)

**Report audited:** `/tmp/opencode/research/php8426_multiw_20261023T191822Z/report.md`  
**Report SHA-256:** `57ddf8596bdbe0eecdae00a0aace3dc990f9b0c9879b4ec869311fda9213ada2` (516 lines)  
**Run root audited:** `/tmp/opencode/research/php8426_multiw_20261023T191822Z/`  
**Audit root:** `/tmp/opencode/research/audit_8426_20261023T202924Z/`  
**Audit date:** 2026-10-23, 20:29–20:47 UTC  
**Repo at report time:** `/home/davide/ailocal/php2slop` @ `6bf1d184c99a2567e58c1c72f38e63e4a3dfbe36` (commit 2026-10-23 19:11:20Z, before the first container at 19:19:25Z).  
**Repo at audit end:** HEAD advanced by concurrent work to `e6438b13fd78d714952aeebe46d8466785fb56c7` (20:46:55Z; intermediate `daa0306` at 20:39:45Z); working tree clean. The report's pin was valid at run time but is no longer current HEAD.

---

## 0. Overall verdict

**PROMOTE WITH CAVEATS — GO for a corrected README cell; NO-GO for verbatim promotion of the report's title, §0, or §10.**

The core technical result is independently confirmed:

* The official `php:8.4.26-apache` image (PHP 8.4.26 NTS, Apache 2.4.69 / Debian 13.7, `mpm_prefork` + `php_module`) was run with the stock prefork worker model (`StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0`).
* Three fresh five-child pools each produced a **target-written** proof file on the first chain attempt (`MW26001`, `MW26B001`, `MW26C001`), and a fourth fresh pool produced `MW26D001` with the full 1,060,211-B A1 body.
* In all four successes the A1/leak child is different from the proof child; the proof child writes the proof and then dies with SIGSEGV. The A1/leak child survives the success sequence (it is later reused and can abort in retries — see D12).
* Every proof contains `uid=33(www-data) gid=33(www-data) groups=33(www-data)` and the run marker, is owned by host `100032:100032` (rootless mapping of container uid 33), and is written 0.045–0.96 s before the SIGSEGV log line.
* The docroot is byte-identical before/after (3,735 files, 109,646,539 B; manifest SHA-256 `0a0afc22…`; target 28-B file MD5 unchanged), the docroot is mounted read-only, and `docker diff` shows no `/var/www/html` changes.
* The `post_max_size=8M` gate is real for a declared-length B1 (200/192, body 0, no `Set-Cookie`, warning “POST Content-Length of 33128677 bytes exceeds the limit of 8388608 bytes”); the chunked B1 reaches PHP without changing the INI.
* ASLR is 2; Docker is rootless; `/var/run/docker.sock` is absent; no container is privileged and no host network or added capabilities are used.

The report must nevertheless be corrected before promotion because it overstates **scope** and **mechanism** in ways that would mislead a README reader:

1. **“WordPress RCE”** is not what was demonstrated. The target is the official 28-byte `/wp-content/index.php` silence file (`<?php // Silence is golden.`). No WordPress application code, `wp-config.php`, plugin, or theme is loaded. The report itself says this in §8.4; the title and §0 do not.
2. **“Stock upstream”** is only true at the image level. The image ships **no active php.ini**; the run mounts the image's own `php.ini-production` unmodified. The default no-INI startup was not tested and, per the report's own cross-reference, uses different heap geometry (`S = main + 0xF5398`). The cell documents the production-INI deployment, not the default `docker run` deployment.
3. **“The observed operational limit is heap freshness”** is a hypothesis, not a measurement. The report's §7.3 correctly calls it an inference; §0 states it as fact. The confirmed observation is a correlation: all 57 failures had prior B1 exposure on the A1 child; all four successes were first attempts on pools with no prior chain attempt. “Freshness” vs. persistent heap corruption vs. A1-on-a-polluted-child is not resolved.
4. Several smaller factual/artifact/statistical issues (C's six-PID A2 union, the §7.4 “GETs only” sentence, the `body_bytes: 33128677` JSON bug, the 9×200/192 session-startup responses, the “briefly six after a crash” causality, and the Wilson independence assumption) are listed in §4 and must be fixed or qualified.

No claim that invalidates the core RCE or the multi-worker result was found. The defects are documentation, scope, and evidence-presentation issues, not a failed reproduction.

**Confidence:** high on build identity, worker distribution, proof contents/ownership, docroot integrity, the `post_max_size` gate, ASLR/rootless Docker, and the existence of the multi-worker chain; medium on leak-size/decoded details (the raw leak response was not retained; the parser output is corroborated by an independent B2 rebuild and execution); low on the “heap freshness” mechanism and on any general population success probability (three pools, serial protocol).

---

## 1. Audit method and read-only statement

* Read the full 516-line report and followed every referenced evidence path; all major paths exist (`verification/`, `out/stock_{a,b,c,d_stockA1}`, `out/cal_stock_a1`, `cal_out/`, `out/neg_s_only/`, `proof*`, `logs*`, `cal*`, `neg1*`, `bodies/`, `scripts/`, `so/`, `wordpress/`, `conf/`).
* Recomputed all rates and outcome counts from the raw `attempts.json` files (A/B/C/D), including per-attempt A1/B1/A2/B2 PIDs, abort indices, prior-B1 exposure, and first-B1/A1 PID inequality.
* Rebuilt all four bodies in memory from the repo's `tool/debian8424.py` (read-only) and compared SHA-256 to the recorded bodies: A1 shrink, A1 stock, B1, A2, and all four B2 bodies match exactly.
* Rebuilt all four B2 bodies from the recorded `S`, `zif_system`, and payload; all four SHA-256 hashes match the recorded `b2_body` hashes.
* Re-read the Apache access/error logs, proof files and mtimes, `docker diff`, pre/post docroot manifests, image/container inspects, MPM/INI files, symbol tables, and rootless-Docker evidence.
* Inspected the still-running `p26*` containers **read-only** with `docker exec ps/cat/id/sha256sum`, `docker inspect`, and `docker diff`. No p26 container was started, stopped, restarted, or removed. No host service was restarted.
* No repo or README edits were made. No writes occurred outside this audit directory. One transient `docker run --rm` was used to print the image's PHP version (no persistent container); the earlier audit work also used one transient `docker run --rm` to hash the image INI. Both are read-only with respect to the run artifacts.
* The repo is a shared, concurrently edited workspace: HEAD advanced from `6bf1d18` to `daa0306` and then `e6438b1` during/after the run. This does not affect the report's historical pin, but the README promotion must re-pin or note the advance.

---

## 2. Claim-by-claim verdicts

Verdict vocabulary: **CONFIRMED** = independently reproduced/checked; **CONFIRMED (caveat)** = true but needs qualification; **INCORRECT AS WRITTEN** = the data contradict the sentence; **HYPOTHESIS / OVERCLAIM** = presented as fact but not measured; **UNVERIFIED** = no artifact in this run; **STALE** = true at report time but no longer current.

### 2.1 Build, provenance, configuration

| ID | Report claim (location) | Verdict | Independent check / note |
|---|---|---|---|
| C01 | Official image `php:8.4.26-apache`; image ID `sha256:46b1…`; repo digest `php@sha256:6011…`; created `2026-10-21T00:32:27Z` (§2, L44–46) | **CONFIRMED** | `docker image inspect` returns the same ID, digest and creation time. |
| C02 | PHP 8.4.26 NTS, Zend 4.4.26, OPcache 8.4.26; Apache 2.4.69; Debian 13.7 (§2, L47–50) | **CONFIRMED** | In-container `php -v`, `apache2 -v`, `/etc/debian_version` all match. |
| C03 | `libphp.so` 21,241,016 B, SHA-256 `51663c…`; `zif_system=0x465370`, `zval_ptr_dtor=0x65eb60` (§2, L52–53) | **CONFIRMED** | Extracted copy and in-container module have the same size/hash; `nm`/`readelf` show the symbols at those offsets. |
| C04 | Official WordPress 7.1.3 ZIP SHA-256 `eb58a9…`; docroot 3,735 files / 109,646,539 B; target 28 B, MD5 `67442c…`, SHA-256 `bd48c2…`; `wp-config.php` = sample; 48 removed bundled files (§2, L54–57) | **CONFIRMED** | ZIP hash matches; all 3,782 ZIP files match the official checksums API; 3,734/3,734 official docroot files match; `wp-config.php` is byte-identical to `wp-config-sample.php`; exactly 47 akismet files + `hello.php` are absent; file count/size and target hashes match. |
| C05 | `randomize_va_space=2` (§2, L58) | **CONFIRMED** | Host and container both report 2. |
| C06 | Image ships no active php.ini; run mounts image's `php.ini-production` unmodified; SHA-256 `8d6fcb…` (§2, L60) | **CONFIRMED (caveat)** | `php --ini` in a fresh image reports `Loaded Configuration File: (none)`; mounted file hash equals the image's `php.ini-production`. This is not the default no-INI startup. |
| C07 | “Stock upstream” / stock configuration framing (title, §0, §10) | **CONFIRMED (caveat)** | Image and MPM are stock; the explicit `php.ini-production` mount is an image file but not the default startup. No-INI default untested and uses a different `S` (see C18). README must say which configuration. |
| C08 | Stock MPM values; `mpm_prefork_module` + `php_module`; no `mod_unique_id`; vhost differs only by logging `CustomLog`; `p2s.conf` logging only (§3.1, L64–92) | **CONFIRMED** | `mpm_runtime.txt` and `apache_modules.txt` match; the vhost diff is exactly the `CustomLog` line; `p2s.conf` contains only `LogFormat`. |
| C09 | INI effective values: `post_max_size=8M`, `memory_limit=128M`, `display_errors=Off`, `upload_max_filesize=2M`; `output_buffering=4096` loaded but not runtime-measured; `expose_php=On` (§3.2, L94–105) | **CONFIRMED** | Lines 226/400/435/504/699/851 match; 8,388,608-byte warning and 134,217,728-byte OOM confirm the first two; bodyless 500 confirms `display_errors=Off`; the `output_buffering` caveat is correctly disclosed. |
| C10 | Mounts; no host network, no privileged mode, no added capabilities; only `127.0.0.1:<port>->80` (§3.3, L107–118) | **CONFIRMED** | All seven run containers are `bridge`, `Privileged=false`, `CapAdd=null`, with loopback-only port bindings; docroot/INI/vhost/p2s mounts are read-only, logs/proof writable. |
| C11 | Each fresh pool starts with five `www-data` children (17–21); ten sequential GETs hit five distinct PIDs on every container (§3.4, L120–142) | **CONFIRMED** | `pool_initial.txt`, `pool_mw2_initial.txt`, `pool_mw3_initial.txt`, `pool_mw4_initial.txt` all show 17–21; `get_pids*.txt` each show five distinct PIDs over ten GETs. |
| C12 | One fresh pool per proof (A/B/C/D) | **CONFIRMED** | p26mw/p26mw2/p26mw3/p26mw4 were created at 19:19:25/19:22:01/19:23:36/19:27:31Z, each immediately before its first chain attempt; no prior chain attempt in any pool. |
| C13 | “In every success the A1/B1/A2 stages span five distinct PIDs” (§3.4, L142) | **INCORRECT AS WRITTEN** | A/B/D union = 5 PIDs; **C union = 6 PIDs** (`17,18,19,20,21,47`). C's A2 block hit 19,20,21,17,47; the A1/leak child 18 was **not** A2-hit. The §6.2 table (L252) correctly shows 47, but the sentence contradicts it. |
| C14 | In every success the proof child is a different worker from the A1/leak child; proof child = crash PID (§0, L15; §6.2, L260–261) | **CONFIRMED** | A: leak 20, proof/crash 21; B: 18/19; C: 18/19; D: 18/19. Error logs show SIGSEGV on exactly the proof child. |
| C15 | Apache respawn kept the pool at five children, “briefly six after a crash”; p26mw ended with five new children, p26mw2/3 with six (§7.3, L361) | **CONFIRMED (caveat)** | Final pools are 5/6/6/5 as stated, but spares 46 (p26mw2) and 47 (p26mw3) existed **before** the proof crash (B's first B2 hit 46; C's A2 hit 47); the six-child state was not caused by the crash. Reword causality. |

### 2.2 Bodies and geometry

| ID | Report claim (location) | Verdict | Independent check / note |
|---|---|---|---|
| C16 | A1 shrink 993,911 B `9f5b04…`; A1 stock 1,060,211 B `8e8fc1…`; B1 33,128,677 B `b6c547…`; A2 279,369 B `7af66c…`; B2 451,384 B per leak (§4, L148–163) | **CONFIRMED** | In-memory rebuilds from `tool/debian8424.py` match every size and SHA-256; all four B2 bodies also match after independent rebuild from recorded `S`/`zif`/payload. |
| C17 | `S=main+0xF8398`; `zif_system=lib+0x465370`; `zval_ptr_dtor=lib+0x65eb60`; main bucket 87; A2 fillers 115; 880 parts/depth 64 (§4.1, L165–173) | **CONFIRMED** | Symbols verified; all four leaks show candidate counts 87/79; `build_a2(fillers=115)` returns 279,369 B with 880 parts/depth 64; four proofs validate `S`; wrong-S control fails B2. |
| C18 | `S` is INI-layout-specific; same image with no active php.ini uses `main+0xF5398` “in a prior no-INI lane” (§4.1, L175) | **UNVERIFIED** | No artifact/path in this run; the no-INI default was not tested. Remove or cite. This matters because the “stock” caveat depends on the production-INI mount. |
| C19 | Blind series A/B/C use the 993,911-B A1 shrink; D uses the full 1,060,211-B stock A1; D is not in the blind denominator (§4, L146; §6.1, L244; §9, L408) | **CONFIRMED (caveat)** | True and disclosed in §9, but the headline 3/60 is for the shrink A1; §0/§6.1 should say so up front. D has 1/1 proof, no rate. |

### 2.3 Protocol and stock gates

| ID | Report claim (location) | Verdict | Independent check / note |
|---|---|---|---|
| C20 | Per attempt: one A1 chunked POST; up to 12 B1 chunked POSTs, stop on leak; five A2 plain POSTs; up to 10 B2 plain POSTs, stop on proof; B1 continues after status 0 (§5, L179–209) | **CONFIRMED** | `scripts/driver.py` implements exactly these counts/stop rules; `--continue-on-crash` is set; headers match; chunked sends are 64 KiB chunks + `0\r\n\r\n`; plain sends use `Content-Length`. |
| C21 | Declared-length B1 control: 200/192, body 0, no `Set-Cookie`, warning at 8,388,608 bytes, no leak (§5.1, L211–222) | **CONFIRMED (caveat)** | `verification/b1_declared_control_meta.json` says body 0/header 188/total 192; `.resp` is 192 B with `Content-Length: 0`; warning text matches. **But** `out/b1_declared_control.json` says `body_bytes: 33128677` — an artifact bug (D5). |
| C22 | A1 chunked control: 500/211, body 0, OOM logged, `display_errors=Off` (§5.2, L224–226) | **CONFIRMED** | `verification/a1_chunked_response.json` and `.raw` match; error log shows 134,217,728-byte exhaustion; body is 0. |
| C23 | “The GETs are the only non-chain requests” (§7.4, L366) | **INCORRECT AS WRITTEN** | Series A access log has a pre-chain declared-length control POST: `19 1792783196.546115 POST /wp-content/index.php 200 - 32017`, before the first A1 `20 1792783243.012564 ... 500`. Warning at 19:19:56.546 confirms. It was rejected at request startup and hit pid 19, not the eventual A1/leak child 20, so it did not cause the success; but the sentence is false and “fresh” must mean “no prior chain attempt,” not “no prior POST.” |
| C24 | 9× B1 `200/192` are “headers-only/request-startup-warning response, no leak” (§6.5, L312) | **CONFIRMED (caveat)** | All 9 occur in attempt 2 of A/B/C (3 each) on children with prior B1 exposure; error logs show `PHP Request Startup: Session ID is too long or contains illegal characters…` and `Failed to read session data: files (path: )`. They are not normal 200/256 pages and not the `post_max_size` gate; the report should distinguish them from §5.1. |

### 2.4 Rates, outcomes, and proofs

| ID | Report claim (location) | Verdict | Independent check / note |
|---|---|---|---|
| C25 | A/B/C each 1/20 = 5.0% (Wilson 0.9–23.6%); blind total 3/60 = 5.0% (1.7–13.7%) (§6.1, L232–242) | **CONFIRMED (caveat)** | Arithmetic verified exactly. The 20 attempts per pool are serially dependent (first attempt succeeds, the remaining 19 fail under the observed pattern); Wilson assumes i.i.d. trials. Quote as a descriptive protocol rate, not a general per-request probability; effective independent units are 3 pools. |
| C26 | Extra D 1/1 with full stock A1; not in blind denominator; “not blind (the pool was known fresh)” (§0, L13; §6.1, L244) | **CONFIRMED (caveat)** | D produced `MW26D001` on its first attempt. The exclusion is justified as a single deliberate non-protocol full-A1 run, but **not** because “the pool was known fresh” — A/B/C pools were also known fresh. Reword (D10). |
| C27 | First attempt only: 3/3 blind = 100% (43.9–100%); first + D: 4/4 = 100% (51.0–100%) (§6.1, L239–240) | **CONFIRMED (caveat)** | Arithmetic correct; n=3/4, very wide interval; do not present as a general success probability. |
| C28 | Post-first attempts: 0/57 = 0.0% (0–6.3%) (§6.1, L238) | **CONFIRMED** | All 57 non-success blind attempts; no leak, no proof. Wilson upper 6.31% verified. |
| C29 | Outcome totals: A1 60×500/211; B1 630×200/256, 9×200/192, 57×status 0, 3 leaks; A2 15×500/211; B2 3×status 0 + 2×200/256; 3 proofs (§6.5, L308–320) | **CONFIRMED** | Recomputed from `out/stock_{a,b,c}/attempts.json`; `out/b1_and_signals.json` agrees (630/9/57/3; 4 SIGSEGV includes D; 57 aborts). |
| C30 | Leak sizes 1,652,356 / 1,681,214 / 1,679,452 B (D 1,691,940 B); decoded 819,208 B; leak in `Set-Cookie` (§6.2, L250–253; §6.5, L314) | **CONFIRMED (caveat)** | Sizes and decoded length are recorded in `attempts.json`/`aslr_success_addresses.json`; parser finds `Set-Cookie: PHPSESSID=` and empty body (`%b -`). No raw leak response was retained, so this is parser-derived; the independent B2 rebuild/execution corroborates the addresses. |
| C31 | Main-bucket candidate count 87 (decoy 79) in all four leaks (§4.1, L172; §6.4, L304) | **CONFIRMED** | `cand_counts` for A/B/C/D are 87/79/1; the extra `0x41414141400000` count is 1. |
| C32 | Success path/PIDs: A1 500/211 and survives; first four B1s other children 200/256; fifth B1 leaks on A1 child; A2 500/211; B2 proof on a different A2 child; proof child SIGSEGV after proof (§6.2, L248–261) | **CONFIRMED (caveat)** | All four matrices match. A: 20→(21,17,18,19,20 leak)→A2 21,17,18,19,20→proof 21; B: 18→(19,20,21,17,18)→A2 19,20,21,17,18→B2 46/200 then 19/0; C: 18→(19,20,21,17,18)→A2 19,20,21,17,47→B2 18/200 then 19/0; D: 18→(19,20,21,17,18)→A2 19,20,21,17,18→B2 19/0. The A1/leak child survives the success sequence but is later reused and aborts in retries (D12). |
| C33 | Proof contents exactly `uid=33(www-data) gid=33(www-data) groups=33(www-data)` + marker; sizes 62/63/63/63; owner `100032:100032` (§6.3, L267–291) | **CONFIRMED** | `verification/success_proofs.txt` and direct reads match; `stat` shows `100032:100032`; container `id www-data` is 33; `/proc/self/uid_map` is `0→1000`, `1→100000`, so 33→100032. |
| C34 | Proof mtimes precede SIGSEGV logs by 0.045–0.96 s; proof child = crash PID (§0, L15; §6.2, L261) | **CONFIRMED** | A 19:20:43.738 vs 19:20:44.700 (0.962 s); B 19:22:07.417 vs 19:22:08.085 (0.668 s); C 19:23:42.268 vs 19:23:42.790 (0.522 s); D 19:27:37.486 vs 19:27:37.531 (0.045 s). |
| C35 | “Every proof was written by the target child” (§0, L14) | **CONFIRMED (caveat)** | Ownership, timing, payload (`id>/out/p1_<marker>`), and the SIGSEGV on the same PID make this the only plausible explanation; there is no syscall/audit trace. Phrase as target-written (timing/ownership inference) if strict. |
| C36 | “In every success the A1/leak child survives” (§0, L15; §6.2, L261) | **CONFIRMED (caveat)** | True within the success sequence. The same PID later aborts when reused: A leak 20 aborts 19:21:06; B leak 18 aborts 19:22:13; C leak 18 aborts 19:23:50. Do not read as “never crashes.” |
| C37 | Post-first failure mechanism: every child that processed a B1 and was later hit by A1→B1 aborts; 57 failures, first abort at B1 #5 (43) or #6 (14); abort PID = A1 PID; A1 absent from pre-abort responders; all 57 A1 PIDs had prior B1 exposure; no failure leaked (§7.2, L335–352) | **CONFIRMED** | Recomputed 43/14; abort log PID = A1 PID 57/57; A1 absent from prior B1 responders 57/57; A1 had prior B1 exposure 57/57; no failure leak. |
| C38 | No stuck/crashed child required; A1/leak child alive through A1/B1/A2; proof child crashes after proof; no manual kill/restart/pinning/`mod_unique_id`; fresh-child requirement is an inference (§7.3, L356–362) | **CONFIRMED (caveat)** | Successes start with five live children; A1/leak child survives the sequence; proof child SIGSEGVs after proof; no pinning/unique_id in config; no manual restart evidence. The “fresh child” sentence is correctly labeled an inference here. |
| C39 | “The observed operational limit is heap freshness, not worker count” (§0, L17) | **HYPOTHESIS / OVERCLAIM** | The correlation is confirmed (57/57 failures prior B1 exposure; 4/4 successes first attempts), but “freshness” is not measured. §7.3 itself says “heap-state inference … not directly instrumented.” Reword to “correlates with prior B1 exposure; consistent with a fresh-child requirement (hypothesis).” |
| C40 | Wrong-S control: `S=0xF7398`, B1 leak 2/2 (1,694,274 and 1,684,946 B; decoded 819,208), A2 500/211, B2 0/2, first B2 200/192, rest 200/256 (§8.1, L378–384) | **CONFIRMED** | `out/neg_s_only/attempts.json`: two attempts, both leak; A2 500/211; B2 first 200/192 then 200/256; no proofs; `neg1_proof` empty. |
| C41 | Docroot integrity: 3,735 files/109,646,539 B; pre/post manifest identical; post SHA-256 `0a0afc22…`; target MD5 unchanged; `docker diff` zero under `/var/www/html`; 215 added = 211 sessions + pid + 3 mounts; 10 changed; read-only touch fails; endpoint standalone 28 B; no WP code loaded (§8.4, L396–400) | **CONFIRMED** | All 3,735 current hashes match the manifest; manifest hash matches; target MD5 before/after matches; `docker diff` has 215 A/10 C and 0 `/var/www/html`; 211 `/tmp/sess_*`; read-only touch fails. Note: `docker diff` cannot see bind-mount changes; the pre/post manifest is the load-bearing evidence. |
| C42 | “The request targets the standalone 28-byte `/wp-content/index.php`; no WordPress application code, plugin, theme or `wp-config.php` is loaded” (§8.4, L400) | **CONFIRMED** | File is exactly `<?php\n// Silence is golden.\n`; no include/require; plugins dir only the 28-B index; no `.htaccess`/`.user.ini`/uploads/mu-plugins; `wp-config.php` exists but is not loaded by this endpoint. |

### 2.5 Operations and scope

| ID | Report claim (location) | Verdict | Independent check / note |
|---|---|---|---|
| C43 | Rootless Docker; no `/var/run/docker.sock`; context `rootless` uses `/run/user/1000/docker.sock` (§1, L33) | **CONFIRMED** | `docker info` security options include `name=rootless`; `/var/run/docker.sock` absent; context is rootless. |
| C44 | No pre-existing containers or host services were touched (§9, L412) | **CONFIRMED (caveat)** | No p26 container was started/stopped/restarted; restart counts 0; only the 7 run containers mount the run root; p26* remain running. The host is shared with concurrent `p8183-*` experiments; `p8183-g8234` was started at 20:29:46Z during the audit, outside the p26 run window. No p26 mount/capability can reach host services, but a host-wide docker-events audit was not performed. |
| C45 | Repo `@6bf1d18`, working tree clean; no repo/README edits (§header, §10, L5/L416) | **CONFIRMED at report time / STALE now** | 6bf1d18 was HEAD at run time (commit 19:11:20Z; first container 19:19:25Z) and the tree was clean. Concurrent work advanced HEAD to `daa0306` (20:39:45Z) during the audit and to `e6438b1` (20:46:55Z) at audit close; `tool/debian8424.py` is unchanged between 6bf1d18 and HEAD; no audit edits. Re-pin or note the advance before promotion. |
| C46 | “G51 is now closed by this stock multi-worker evidence” (§10, L416) | **CONFIRMED (caveat)** | Within the repo's convention (official WP docroot, 28-B core file, stock prefork), the cell is supplied. But it is conditional on mounting the image's `php.ini-production`; the default no-INI startup was not tested and uses different geometry. Say “G51 closed for the production-INI deployment; no-INI default remains a variant/gap.” |
| C47 | Artifacts listed in §11 exist and support the claims (§11, L420–436) | **CONFIRMED (caveat)** | All listed paths exist. One artifact is wrong: `out/b1_declared_control.json` `body_bytes: 33128677` (D5). `verification/b1_declared_control_meta.json` is correct. |
| C48 | Reproduction commands in §12 are sufficient to recreate the run (§12, L440–475) | **CONFIRMED (plausible)** | Commands match the actual driver/args/mounts; the repo tool is unchanged; `conf/mpm_prefork_w1.conf` exists for calibration. The commands do not show the pre-chain control; add it if reproducing series A exactly. |

**Lab-assisted/control separation (not part of the 48 claims).** The stock multi-worker result rests only on A/B/C (blind routing, 3/60; first attempts 3/3) and D (extra, non-protocol, 1/1). The single-worker calibration (`CAL001`, `CAL002`, `CALA1001`) is **lab-assisted** — one child, known target geometry — and is not part of the multi-worker rate; it independently confirms the primitive 3/3 (`500/211 → leak → 500/211 → proof`). The wrong-anchor run (`NEGS001`/`NEGS002`) is a negative control (B1 leak 2/2, B2 0/2). The declared-length B1 and chunked A1 are gate/protocol controls. None of these should be pooled with 3/60.

---

## 3. Verdict tally

Of 48 material claims:

* **CONFIRMED:** 25
* **CONFIRMED (caveat):** 18 (includes C48 “plausible”)
* **INCORRECT AS WRITTEN:** 2 (C13 five-PID sentence; C23 GETs-only sentence)
* **HYPOTHESIS / OVERCLAIM:** 1 (C39 heap freshness in §0)
* **UNVERIFIED:** 1 (C18 no-INI `S=0xF5398`)
* **STALE:** 1 (C45 repo HEAD)

No claim that invalidates the core RCE or multi-worker result. The two “incorrect as written” sentences are contradicted by the report's own tables/artifacts; they are documentation defects, not data defects. The overclaim and unverified item are scope/mechanism issues. The stale item is expected in a shared repo.

---

## 4. Discrepancies and required corrections

### 4.1 Major (must fix before README promotion)

**D1 — “WordPress RCE” is a scope overclaim.**  
The target is the official 28-B `/wp-content/index.php` silence file; no WordPress application code, `wp-config.php`, plugin, or theme is loaded. The report says this in §8.4, but the title, §0, and §10 say “WordPress RCE” / “WordPress cell.” A README reader will infer application-level WordPress exploitation. Required: retitle/re-scope to “PHP 8.4.26 mod_php multi-worker RCE on an official WordPress 7.1.3 docroot (28-B `/wp-content/index.php` silence endpoint)” and add one sentence: “The endpoint does not bootstrap WordPress; this is a mod_php heap primitive on an official core file, not an application-level WordPress RCE.” The existing README already uses “WordPress 7.1.3” as docroot shorthand for the Debian 8.4.24 cell; keep consistency, but define it once.

**D2 — “Stock upstream” hides the INI mount.**  
The image ships no active php.ini; the run mounts the image's own `php.ini-production` unmodified. That is a documented image file, but it is not the default no-INI startup. The report's own §4.1 says the no-INI lane uses a different anchor (`main+0xF5398`), and §9 says the no-INI default was not tested. Required: say “official image; image's `php.ini-production` mounted unmodified; the no-INI default was not tested and uses different heap geometry.” Do not write “stock default deployment” or “stock upstream” without that qualification.

**D3 — Heap freshness is asserted as fact.**  
§0: “The observed operational limit is heap freshness, not worker count.” §7.3 correctly says “heap-state inference … not directly instrumented.” The data confirm a correlation (57/57 failures had prior B1 exposure on the A1 child; 4/4 successes were first attempts on fresh pools; abort PID = A1; first abort at B1 #5/#6). They do not distinguish freshness from persistent corruption or from an A1-on-polluted-child effect. Required: downgrade to “correlates with prior B1 exposure; consistent with a fresh-child requirement (hypothesis, not measured).”

**D4 — §7.4 “GETs are the only non-chain requests” is false for series A.**  
The series A access log contains a pre-chain declared-length control POST at `1792783196.546115` (pid 19, 200, 32,017 µs), before the first A1 at `1792783243.012564` (pid 20, 500). The warning at 19:19:56.546 confirms. The control was rejected at request startup and hit pid 19, not the eventual A1/leak child 20, so it did not cause the success; but the sentence is false. Required: replace with “Series A included one pre-chain declared-length control at 19:19:56 (200/192, no leak); B/C/D had only the 10 GETs. ‘Fresh’ means no prior chain attempt, not no prior POST.”

**D5 — `out/b1_declared_control.json` contradicts the correct metadata.**  
`out/b1_declared_control.json` has `"body_bytes": 33128677`; `verification/b1_declared_control_meta.json` has `body_bytes: 0`, `header_bytes: 188`, `resp_bytes: 192`; `out/b1_declared_control.resp` is 192 B with `Content-Length: 0` and no `Set-Cookie`. The report's prose cites the meta and is correct, but the artifact is self-contradictory. Required: fix the JSON (body_bytes 0) or annotate it as a request-size field, not a response-body field.

**D6 — C's A2 six-PID union is hidden by the “five distinct PIDs” sentence.**  
C success: A1/B1 pids 18 + 19,20,21,17; A2 pids 19,20,21,17,47; union 6. The table (L252) is correct; the sentence (L142) and §7.1 “A2 runs on the five children” are not. Required: say “C's A2 block hit 19,20,21,17,47 (spare 47), so the A1 child 18 was not A2-hit; the proof child 19 was. B2 on 18 returned 200/256, consistent with B2 requiring an A2-primed child.” This strengthens the mechanism and removes the contradiction.

**D7 — Wilson intervals assume independence that the protocol does not have.**  
The arithmetic is correct, but the 20 attempts per pool are serially dependent: the first attempt succeeds and the remaining 19 fail deterministically under the observed pattern. Wilson assumes i.i.d. Bernoulli trials. Required: label the intervals “descriptive Wilson interval (serial/clustered protocol)” and state that the effective independent units are 3 pools, not 60 attempts. Do not quote 5.0% as a general per-request success probability. Also note that the “3/300 at 100 attempts” sentence is an illustrative extrapolation, not a measurement.

**D8 — D's “not blind” rationale is inconsistent.**  
§0 says D was not blind because “the pool was known fresh”; but A/B/C pools were also known fresh. D is excluded because it is a single deliberate full-A1 run outside the fixed 20-attempt protocol, not because freshness was unknown. Required: call D “extra, non-protocol, not in the blind denominator” and define “blind” as blind routing (the driver does not use PID observations to choose requests), not double-blind.

**D9 — The 3/60 rate is for the 993,911-B A1 shrink, not the full stock A1.**  
§9 discloses this, but §0/§6.1 do not. Required: state up front “the 20-attempt blind series uses the 993,911-B A1 shrink (`build_a1(big_len=7150)`); the full 1,060,211-B A1 has 1/1 proof (D) and no rate.” Do not let a README reader think 5.0% is the full-A1 rate.

**D10 — G51 closure is conditional on the production-INI deployment.**  
The gap asks for “upstream `php:8.4.26-apache` stock multi-worker.” The run supplies that for the image's `php.ini-production` mount, with official WP docroot and stock prefork. It does not supply the no-INI default. Required: “G51 closed for the production-INI deployment; the no-INI default remains a variant/gap.” If the README wants a single unqualified ✅, that is not supported.

### 4.2 Minor (should fix for accuracy)

**D11 — 9× B1 200/192 are session-startup no-ops, not the `post_max_size` gate.**  
All 9 occur in attempt 2 of A/B/C (3 each) on children with prior B1 exposure; error logs show `PHP Request Startup: Session ID is too long or contains illegal characters…` and `Failed to read session data: files (path: )`. The report's table says “headers-only/request-startup-warning,” which is accurate, but the same 200/192 size as §5.1's declared-length control invites confusion. Add a footnote distinguishing “post_max_size control” from “session-startup no-op.”

**D12 — “A1/leak child survives” needs a time scope.**  
It survives the success sequence, but the same PID later aborts in retries: A leak 20 at 19:21:06; B leak 18 at 19:22:13; C leak 18 at 19:23:50. Add “survives the success sequence; later reuse can abort.”

**D13 — “Briefly six after a crash” is the wrong causality.**  
Spares 46 (p26mw2) and 47 (p26mw3) existed before the proof child 19 SIGSEGV; B's first B2 hit spare 46 and C's A2 hit spare 47. The pools were already six. Final pools are 5/6/6/5. Reword to “Apache forked spares under load (46/47 before the proof crash); final pools 5/6/6/5.”

**D14 — “Exactly the sweep reaching the A1 child” is rhetorical.**  
Supported by abort PID = A1 PID 57/57 and A1 absent from prior responders 57/57; “consistent with” is more precise than “exactly.”

**D15 — `docker diff` cannot see bind-mount changes.**  
The docroot is a read-only bind mount; `docker diff` would be empty even if the host directory changed. The pre/post manifest is the load-bearing integrity evidence. The report has the manifest, so this is a presentation note, not a data defect.

**D16 — “No host service changes” / “no sudo” are not independently verified.**  
No evidence in the p26 artifacts; plausible, but a host-wide docker-events/shell audit was not performed. Say “no evidence this run touched pre-existing containers/services; host was shared.”

**D17 — Repo HEAD is stale at audit time.**  
6bf1d18 was HEAD at run time; concurrent commits advanced HEAD to daa0306, then e6438b1. The report's “working tree clean” was true at write time. Before README promotion, re-pin or note the advance; `tool/debian8424.py` is unchanged, so the body rebuild remains valid.

**D18 — No-INI `S=0xF5398` has no artifact in this run.**  
Remove or cite the prior lane. This is minor because the production-INI path is fully validated, but it matters to the “stock/default” caveat.

### 4.3 Evidence limitations (not errors)

**L1 — Raw B1 leak response not retained.**  
The 1.65–1.69 MB response and 819,208-B decoded cookie are parser outputs. The independent B2 rebuild from the derived `main`/`lib`/`S`/`zif` matches all four recorded B2 hashes, and the proofs executed; this corroborates the addresses, but the leak size/decoded count is not independently re-measured from a saved raw response. Future runs should retain the raw headers.

**L2 — Proof-write provenance is timing/ownership inference.**  
Ownership `100032:100032`, mtime 0.045–0.96 s before SIGSEGV, and the payload `id>/out/p1_<marker>` make target-child provenance the only plausible explanation; there is no syscall/audit trace. Phrase as “target-written (timing/ownership inference)” if strict.

**L3 — No allocator instrumentation.**  
“Heap freshness” is a correlation/inference, not a measured allocator state. The report's §7.3 says so; §0 does not.

**L4 — Small, clustered sample.**  
Three blind pools, 20 attempts each, all successes on the first attempt. The 3/60 point estimate is exact for the protocol, but the interval is descriptive and the population estimate is weak. The 3/3 first-attempt result is the more useful operational statement, with n=3.

**L5 — One host, loopback only, rootless Docker.**  
No reverse proxy/WAF/CDN/external network; real-world reachability/rate limits are out of scope. The host was shared with concurrent experiments.

**L6 — No host-wide non-interference audit.**  
No p26 container can reach the host Docker socket (no mount, no privileges), and only the 7 run containers mount the run root. But a host-wide docker-events audit was not performed; the concurrent `p8183-*` activity is external to this run.


---

## 5. Required pre-promotion checklist

The README may cite the technical result only after the following corrections are applied to the report (or the README wording explicitly carries the qualifications in §6). Items P1–P10 are mandatory; P11–P15 are strongly recommended.

- [ ] **P1 (D1) — Re-scope “WordPress RCE.”** State that the endpoint is the 28-B `/wp-content/index.php` silence file and that no WordPress application code, `wp-config.php`, plugin, theme, or front controller is loaded. Do not call it an application-level WordPress RCE.
- [ ] **P2 (D2) — Disclose the INI mount.** State “official image; image's `php.ini-production` mounted unmodified; the no-INI default was not tested and uses different heap geometry.” Remove unqualified “stock upstream/default.”
- [ ] **P3 (D3) — Downgrade heap freshness.** Replace “the operational limit is heap freshness” with “correlates with prior B1 exposure; consistent with a fresh-child requirement (hypothesis, not measured).”
- [ ] **P4 (D4) — Fix §7.4.** Delete “the GETs are the only non-chain requests.” Record the series-A pre-chain declared-length control (19:19:56, PID 19, 200/192) and define “fresh” as “no prior chain attempt,” not “no prior POST.”
- [ ] **P5 (D5) — Fix or annotate `out/b1_declared_control.json`.** Set `body_bytes` to 0 (response body), or rename the field to `request_body_bytes`; keep `verification/b1_declared_control_meta.json` as the authoritative response record.
- [ ] **P6 (D6) — Fix the five-PID sentence for C.** Say A/B/D span five PIDs, C spans six; C's A2 block hit 19/20/21/17/47 and the A1 child 18 was not A2-hit; B2 on 18 returned 200/256.
- [ ] **P7 (D7) — Relabel the intervals.** Call them “descriptive Wilson intervals for a serial/clustered protocol”; effective independent units = 3 pools. Do not quote 5.0% as a per-request probability. Mark the 3/300 extrapolation as illustrative.
- [ ] **P8 (D8) — Fix D's exclusion rationale.** D is “extra, non-protocol, not in the blind denominator,” not excluded because its freshness was unknown. Define “blind” as blind routing.
- [ ] **P9 (D9) — State the A1 variant up front.** The 3/60 series uses the 993,911-B A1 shrink; the full 1,060,211-B A1 has 1/1 (D) and no rate.
- [ ] **P10 (D10) — Qualify G51 closure.** “G51 closed for the production-INI deployment; the no-INI default remains a variant/gap.”
- [ ] **P11 (D11–D14) — Minor wording.** Distinguish the 9× session-startup 200/192 from the `post_max_size` control; time-scope “A1/leak child survives”; fix “briefly six after a crash”; prefer “consistent with” over “exactly the sweep.”
- [ ] **P12 (D15–D16) — Evidence presentation.** Say the pre/post manifest, not `docker diff`, proves bind-mounted docroot integrity; say “no evidence this run touched pre-existing containers/services,” not “no host changes.”
- [ ] **P13 (D17) — Re-pin.** Either cite `6bf1d18` as the historical run pin and note the current HEAD, or re-run/re-pin at promotion time. `tool/debian8424.py` is unchanged, so the body rebuild remains valid.
- [ ] **P14 (D18/L1–L6) — Resolve or label unverified items.** Remove the no-INI `S=0xF5398` sentence or cite the prior lane; label proof-write provenance and leak size/decoded count as parser/timing inference.
- [ ] **P15 — Preserve artifacts.** Do not rewrite `out/b1_declared_control.json` in place without a note; if fixed, record the correction in the report changelog so the audit trail remains reproducible.

---

## 6. Suggested README wording

### 6.1 Preferred change: add an Applications row, remove the G51 gap

Add this row to the Applications table, immediately after the existing 8.4.26 mod_php engine-level row:

| WordPress 7.1.3 | Apache 2.4.69 prefork + mod_php 8.4.26 (official `php:8.4.26-apache`, Debian 13.7) | stock prefork 5/150; image's `php.ini-production` mounted unmodified; `/wp-content/index.php` 28-B core file, read-only | ✅ | **stock multi-worker cell for this deployment**; 4/4 target-written proofs on fresh pools (3 blind first attempts + 1 extra full-A1); 3/60 = 5.0% is a descriptive serial-protocol rate (Wilson 1.7–13.7%), not a per-request probability; the endpoint does not bootstrap WordPress; no-INI default not tested |

Then remove the G51 line from the gap table (the row currently reading “the audited stock prefork 5/150 WordPress proof is Debian 8.4.24 …”). If the gap table must retain a trace, replace it with:

| G51 | — | App | WordPress 7.1.3 + official `php:8.4.26-apache` (`php.ini-production`, prefork 5/150) | **closed for the production-INI deployment**; 4/4 fresh-pool target-written proofs; no-INI default remains untested (different heap geometry) | — |

and update the closing sentence (“The remaining WordPress cells are … upstream 8.4.26 stock multi-worker (G51)”) to remove G51 from the open-gap list.

### 6.2 Scope paragraph to place under the Applications table

> The G51 cell is a mod_php heap primitive executed on the official WordPress 7.1.3 docroot's 28-byte `/wp-content/index.php`; it does not bootstrap WordPress or load `wp-config.php`, plugins, or themes. The image ships no active php.ini; the cell mounts the image's own `php.ini-production` unmodified. The no-INI default was not tested and is expected to use different heap geometry (not re-verified in this run). “Fresh pool” means no prior A1→B1 chain attempt, not no prior POST. The 993,911-B A1 shrink was used for the 20-attempt blind series; the full 1,060,211-B A1 has a single proof (series D) and no measured rate.

### 6.3 Rate sentence, if a rate is quoted at all

> On three fresh five-child pools, the first chain attempt succeeded 3/3 (blind) and 4/4 including the extra full-A1 pool; the fixed 20-attempt protocol scored 3/60 = 5.0% (descriptive Wilson 1.7–13.7%; serial/clustered protocol, effective independent units = 3 pools). This is not a per-request success probability.

### 6.4 Minimum one-line note if the README keeps “WordPress 7.1.3” shorthand

> “WordPress 7.1.3” denotes the official docroot; the tested endpoint is the 28-B `/wp-content/index.php` silence file, not the WordPress front controller.

---

## 7. Wording to avoid

| Do not write | Write instead |
|---|---|
| “WordPress RCE” / “WordPress 7.1.3 RCE” unqualified | “mod_php RCE on an official WordPress 7.1.3 docroot (28-B `/wp-content/index.php` silence endpoint); WordPress is not bootstrapped” |
| “stock upstream” / “stock default deployment” unqualified | “official `php:8.4.26-apache`; image's `php.ini-production` mounted unmodified; no-INI default not tested” |
| “the operational limit is heap freshness” | “correlates with prior B1 exposure; consistent with a fresh-child requirement (hypothesis, not measured)” |
| “5.0% success rate” / “1 in 20 requests” | “3/60 descriptive serial-protocol rate; 3/3 first attempts on fresh pools (n=3)” |
| “the GETs are the only non-chain requests” | “series A included one pre-chain declared-length control; B/C/D had only the 10 GETs” |
| “the A1/B1/A2 stages span five distinct PIDs” | “A/B/D span five PIDs; C spans six (spare 47 in A2; A1 child 18 not A2-hit)” |
| “briefly six after a crash” | “Apache forked spares under load (46/47 before the proof crash); final pools 5/6/6/5” |
| “the A1/leak child survives” unqualified | “the A1/leak child survives the success sequence; later reuse can abort” |
| “no pre-existing containers or host services were touched” as a proven host-wide fact | “no evidence this run touched pre-existing containers/services; the host was shared with concurrent experiments” |
| “G51 is now closed” unqualified | “G51 is closed for the production-INI deployment; the no-INI default remains a variant/gap” |
| “no-INI uses `S = main + 0xF5398`” in this run | omit, or “a prior lane reported `main+0xF5398`; not re-verified here” |
| “every proof was written by the target child” as a syscall-verified fact | “target-written (ownership/timing/payload inference; no syscall trace)” |

---

## 8. Evidence-integrity appendix

| Check | Evidence path | Independent result |
|---|---|---|
| Report identity | `report.md` | 516 lines; SHA-256 `57ddf8596bdbe0eecdae00a0aace3dc990f9b0c9879b4ec869311fda9213ada2`. |
| Image identity | `out/image_inspect.json`, live `docker image inspect` | ID `sha256:46b195b6…`, repo digest `php@sha256:60111400…`, created `2026-10-21T00:32:27Z`. |
| PHP/Apache build | live `php -v`, `apache2 -v`, `/etc/debian_version` | PHP 8.4.26 NTS / Zend 4.4.26; Apache 2.4.69; Debian 13.7. |
| `libphp.so` | `so/libphp.so`, in-container module | 21,241,016 B; SHA-256 `51663cf8…`; `zif_system=0x465370`, `zval_ptr_dtor=0x65eb60`. |
| MPM/config | `verification/mpm_runtime.txt`, `apache_modules.txt`, `conf/` | Start 5 / MinSpare 5 / MaxSpare 10 / MaxRequestWorkers 150 / MaxConnectionsPerChild 0; prefork + php_module; no `mod_unique_id`; vhost diff = logging only. |
| INI | mounted `php.ini`, image `php.ini-production` | Hashes equal (`8d6fcbbc…`); `post_max_size=8M`, `memory_limit=128M`, `display_errors=Off`, `output_buffering=4096`; fresh image loads no php.ini. |
| Initial pools | `pool_*_initial.txt`, `get_pids*.txt` | 17–21 on all four pools; ten GETs hit five distinct PIDs each. |
| Bodies | `bodies/`, repo `tool/debian8424.py` | A1 shrink 993,911 B, A1 stock 1,060,211 B, B1 33,128,677 B, A2 279,369 B, B2 451,384 B; all hashes match in-memory rebuilds. |
| B2 per leak | recorded `S`/`zif_system`/payload | All four B2 bodies independently rebuilt; all four SHA-256 match; all four executed. |
| Blind series | `out/stock_{a,b,c}/attempts.json` | A/B/C = 1/20 each; total 3/60; first attempts 3/3; post-first 0/57. |
| Failure mechanism | `out/*/attempts.json`, `logs*/error.log`, access logs | First status-0 at B1 #5 (43) / #6 (14); abort PID = A1 PID 57/57; A1 absent from prior responders 57/57; prior B1 exposure 57/57. |
| Success routing | `verification/success_worker_excerpts.txt` | A 20→…→21; B 18→…→19; C 18→…→19; D 18→…→19; B2 proof child = crash PID in all four. |
| Proofs | `proof/p1_MW26001`, `proof2/p1_MW26B001`, `proof3/p1_MW26C001`, `proof4/p1_MW26D001` | 62/63/63/63 B; owner `100032:100032`; exact `id` text + marker; mtimes 0.045–0.96 s before SIGSEGV. |
| Leak size | `attempts.json`, `aslr_success_addresses.json` | 1,652,356 / 1,681,214 / 1,679,452 B (D 1,691,940 B); decoded 819,208 B; parser-derived (L1). |
| `post_max_size` control | `verification/b1_declared_control_meta.json`, `.resp` | 200/192; body 0; header 188; no `Set-Cookie`; 8,388,608-B warning. `out/b1_declared_control.json` `body_bytes` is wrong (D5). |
| A1 control | `verification/a1_chunked_response.json`, `.raw` | 500/211; body 0; 134,217,728-B OOM; `display_errors=Off`. |
| Wrong-S control | `out/neg_s_only/attempts.json` | B1 leak 2/2; A2 500/211; first B2 200/192 then 200/256; 0/2 proofs. |
| Docroot | `verification/wordpress_manifest_pre/post.txt` | 3,735 files / 109,646,539 B; post SHA-256 `0a0afc22…`; all 3,735 hashes match; target 28 B MD5 `67442c56…`. |
| Docroot mount | `verification/docker_diff_p26mw.txt`, live `docker diff` | Zero `/var/www/html` changes; 215 added (211 sessions + pid + 3 mounts); 10 changed; read-only touch fails. |
| ASLR / Docker | host/container `/proc/sys/kernel/randomize_va_space`, `docker info` | ASLR 2; rootless; no `/var/run/docker.sock`; no privileged/caps. |
| Run isolation | `docker ps/inspect`, mounts | Seven run containers mount the run root; no other container does; no p26 restart (count 0). |
| Repo pin | `git log`, `git diff 6bf1d18..HEAD -- tool/debian8424.py` | 6bf1d18 valid at run time; HEAD now `e6438b1` (via `daa0306`); `debian8424.py` unchanged; working tree clean. |

---

## 9. Sign-off

**Recommendation: PROMOTE WITH CAVEATS.** The RCE, the A1→B1→A2→B2 multi-worker chain, the target-written proofs, the stock-prefork worker distribution, and the `post_max_size` gate are independently confirmed. The report is not suitable for verbatim promotion: the title/§0 overstate scope (“WordPress RCE”), configuration (“stock upstream”), and mechanism (“heap freshness”), and there are two sentences contradicted by the report's own data (C13, C23) plus one self-contradictory artifact (D5).

Promotion is approved only with the corrected Applications row and scope paragraph in §6 (or equivalent wording carrying the same qualifications), after the P1–P10 corrections. No finding invalidates the core result; the required changes are documentation, scope, and statistical-labeling fixes.

**Audit constraints honored:** all p26 containers were inspected read-only; none was started, stopped, restarted, or removed; no host service was restarted; no repo or README edit was made. Writes were confined to `/tmp/opencode/research/audit_8426_20261023T202924Z/`. Two transient `docker run --rm` invocations were used only to read image metadata (PHP version / INI hash); neither created a persistent container.

**Auditor:** independent audit lane, 2026-10-23 20:29–20:47 UTC.
