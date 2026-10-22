# ASLR-on in-band leak survey — private MediaWiki/Wikibase FPM stack

Receipt: `/tmp/opencode/research/aslrleak_20261022T011500Z`

Survey window: 2026-10-22 01:12:15–01:20:45 local (23:12:15–23:20:45 UTC)

Target: private MediaWiki 1.46.2 + Wikibase, PHP 8.5.10 (`fpm-fcgi`), nginx 1.30.1, MariaDB 11.4.5.

Mode: **ASLR on** — all five stack PIDs have `personality 00000000`; host `randomize_va_space=2`.

## Verdict

**No ASLR-on heap pointer was disclosed by any MediaWiki/Wikibase response.**

A session-ID disclosure does exist:

- `Set-Cookie: wikidb_session=<32-char>` on login, token, debug-login, and invalid-cookie login responses.
- `Set-Cookie: mw_installer_session=<32-hex>` on the exposed `/mw-config/` installer.

Both values are random session identifiers, not heap addresses. The MediaWiki `wikidb_session` value is not even PHP-hex; it uses an alphabet containing `g`–`v`, and its `sessions/sess_<id>` file is a 0-byte pre-handler artifact. The installer value is a real PHP file-session ID, but its 2,621-byte session file contains only serialized installer settings and no pointer.

No response contains an `0x...` heap token or a canonical `0x7f...` / `0x55...` / `0x56...` userspace address. There is therefore no in-band value that can supply `P`, `B0`, `S`, or `B0f`; the `zif_passthru` record cannot be rebuilt under ASLR on. No ASLR-on marker was created, and no ASLR-on survivor run was attempted. The only survivor evidence remains the historical ASLR-off run on worker 1249940.

## 1. Stack and ASLR state

| Component | PID | Start | Personality |
|---|---:|---|---|
| MariaDB 11.4.5 | 52393 | 2026-10-22 01:10:00 | 00000000 |
| PHP-FPM master | 52926 | 2026-10-22 01:10:36 | 00000000 |
| PHP-FPM worker (pool `lab`) | 52927 | 2026-10-22 01:10:36 | 00000000 |
| nginx master | 52930 | 2026-10-22 01:10:36 | 00000000 |
| nginx worker | 52931 | 2026-10-22 01:10:36 | 00000000 |

- Host `randomize_va_space=2`.
- Direct evidence: `log/stack-state.txt`.
- Shared PIDs `4052217`, `4052937`, `4053032`, `4054145` were absent at restart and throughout; none were signalled, killed, or inspected further.
- Final health check `98_final_health` (`GET /index.php?title=Main_Page`) returned HTTP 200, 35,297 B; worker 52927 remained alive; no SIGSEGV in the new run.
- The stack was started with the target FPM binary and `LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib`; the known-good private configuration is copied in `conf/`.

## 2. Request coverage

98 requests were issued; 196 header/body files were saved under `req/`. The exhaustive request list is **`log/matrix.tsv`** (one row per request: label, method, URI, status, curl body size, nginx body size, access time). `log/nginx-access-window.log` is the matching nginx access-log window. `log/requests.log` is the curl-side log.

Category coverage (every label appears in `log/matrix.tsv`):

| Category | Labels | Count |
|---|---|---:|
| Baseline, main page, API, login, version, entity routes | `01_main` … `30_imgauth` | 30 |
| Session/static/cookie probes, login cookie variants | `31_sessions_static` … `46_login_post` | 16 |
| Wikibase parse, query, tokens, userinfo, debug | `47_parse_item_page` … `62_debug_api` | 16 |
| Upload-progress sessions | `63_uprog_nocookie` … `66_uprog_bodyfield` | 4 |
| Session-ID reuse/invalid variants | `67_login_leaked_id` … `72_login_bad_long` | 6 |
| Request-ID / XFF reflection | `73_reqid_custom` … `76_xff` | 4 |
| Static/session path checks | `77_sessions_leaked_id` … `82_images_htaccess` | 6 |
| Directory/load/API help probes | `83_dir_*` (7), `90_load_debug` … `92_api_paraminfo` | 10 |
| Exposed installer | `93_mwconfig_again` … `97_mwconfig_index` | 5 |
| Final health | `98_final_health` | 1 |

Representative paths are shown in the matrix and in the findings below. All 301 redirects to `Main_Page` are MediaWiki's fallback for non-existent paths, not static file serves.

## 3. What was found in responses

### 3.1 No heap pointer, and the pointer-like false positives

A full scan of all saved headers and bodies found:

- **0** `0x...` heap-address tokens that are not known constants.
- **0** standalone canonical userspace pointers (`0x7f...`, `0x55...`, `0x56...`).
- The only `0x` token in a body is **`0x811C9DC5`** in `90_load_debug` — the FNV-1a 32-bit offset basis constant in ResourceLoader JavaScript, not an address.
- A naive `[0-9a-fA-F]{12,}` regex matches random substrings inside 24-hex `X-Request-Id` values (for example `7f4e21b7eccd` inside `e7b85c3353ce7f4e21b7eccd`, and `7f1e8e2e1256` inside `1c4851c5277f1e8e2e12566e`). A token can also *start* with `7f` — `92_api_paraminfo` has `X-Request-Id: 7f32ef0b...` — but the full value is still one 24-hex `wfRandomString(24)` value, not a 12-hex pointer. These are classified as false positives: the full token is a random request ID, the value changes on every request, and the source generation is `wfRandomString(24)` (see 3.2). They are not aligned or stable addresses.
- Other long tokens are non-pointers: `20261021213001` (14-digit timestamp / cache key), `49b0edf00944` (the node part of a UUID such as `5b8dbd73-cd96-11f1-858a-49b0edf00944`), `278f00229c8bb9b5` (a parser-cache `UNIQ...` placeholder in `47_parse_item_page`), 40-hex CSRF/login tokens, and `ETag` values such as `"6ac03dcc-2df"` (mtime-size).

### 3.2 `X-Request-Id` is random, not a pointer

`X-Request-Id` is present on PHP responses (not on static nginx responses). It is 24 lowercase hex characters.

Source: `Telemetry::getRequestId()` uses `wfRandomString(24)` when `$wgAllowExternalReqID` is false and no `UNIQUE_ID` is present. `wfRandomString(24)` builds the string from `mt_rand() & 0xfffffff` formatted as `%07x`, truncated to 24 chars (`includes/GlobalFunctions.php:169-175`). The stack's `fastcgi_params` contains no `UNIQUE_ID`, and `$wgAllowExternalReqID` is not enabled.

Evidence:

- Sending `X-Request-Id: 0x7fdeadbeefcafe` or `X-Request-Id: HELLO123` is ignored; the response still has a fresh 24-hex `X-Request-Id` (`73_reqid_custom`, `74_reqid_hello`, `75_reqid_api`).
- The same value is used as `wgRequestId` in the HTML body and as `requestId` in API errors; it is a request correlation ID, not an address.
- `X-Forwarded-For` / `X-Real-IP` are not reflected (`76_xff`).

The request ID is predictable PRNG output, not a CSPRNG, but it is not derived from a heap address. It is expressly excluded as a pointer channel.

### 3.3 `wikidb_session` — MediaWiki session-ID disclosure, not a heap pointer

`Set-Cookie: wikidb_session=<32-char>; path=/; HttpOnly` appears on:

- `07_login` — `4f911jbuf5ti0432fpk3b0k6prg97r2t`
- `43_login_cookie` — `49b4dtimr39kk0e8cb3gbv3bebnpugq0`
- `44_login_phpsess` — `ai2pgsqir022lrhqvht17r3p6gabcm7h`
- `45_main_wikicookie` — `qgr2ugvdvn6u1ak8tm9k5g7scm8gtoul`
- `46_login_post` — `ebv52hbb6es82amj307fup0tncqspqkd`
- `52_tokens` (`action=query&meta=tokens`) — `5roppa1s9mrf3vlqok1o6917kt566i4c`
- `61_debug_login` — `nr69acdfme7c8i7ar6h42ahunkpiuqkh`
- `68_login_leaked_phpname` — `jajqkmovfd2t2fgtldqd1badat8986j6`
- `71_login_bad_short` — `cftr0m7luvt8rsd35silh7h8l1ult2il` (plus `wikidb_session=deleted`)
- `72_login_bad_long` — `4c9dnsmaula0flnubchb5hqu5r2u6vch`

Behavior:

- The value is **32 characters** from an alphabet that includes non-hex letters (`j`, `u`, `f`, `g`, `k`, `p`, `r`, `t`, …). It is not a hex encoding of a 64-bit pointer.
- A valid existing ID is accepted back: `67_login_leaked_id` sent `wikidb_session=4f911...` and received **no new `Set-Cookie`**; the session was reused. `69_login_both_ids` did the same.
- The name matters: `68_login_leaked_phpname` sent the same value as `PHPSESSID` and received a **new** `wikidb_session`, because `PHPSESSID` is a different session name.
- An invalid short ID (`71`, `abc`) yields `wikidb_session=deleted` plus a new ID; a 200-char ID (`72`) yields a new ID.
- The corresponding `sessions/sess_<id>` files are **0 bytes**. They are pre-`PHPSessionHandler` artifacts, not the MediaWiki session store. Actual MediaWiki session data is in the application's session backend.
- `GET /sessions/sess_4f911...` returns **301 to `Main_Page`**, not the file (`77_sessions_leaked_id`).
- No response body echoes the ID: a scan for every leaked value found it only in the `Set-Cookie` header, never in HTML/JSON.

This is a genuine session-ID disclosure, but it is random and does not encode `P`, `B0`, `S`, or `B0f`.

### 3.4 `mw_installer_session` — real PHP file-session ID, still no heap pointer

The exposed installer at `/mw-config/` returns:

`Set-Cookie: mw_installer_session=<32 lowercase hex>; path=/`

Observed IDs:

- `83_dir_mw-config` — `d5fe543299db3b3f7ca24d38ec50ea62`
- `93_mwconfig_again` — `06af8ccceb6865352c7ac683c960c0d6`
- `96_mwconfig_invalid` — `10370ec454551b8e0cbccc3163263cf3`
- `97_mwconfig_index` — `e048066e83c3f7817f659ea760a00f5f`

Behavior:

- A fresh request creates a new 32-hex ID; sending an existing ID back (`94_mwconfig_cookie`) is accepted and produces **no new `Set-Cookie`**.
- Each ID maps to a **2,621-byte** PHP file session in `sessions/sess_<id>`, with content beginning `installData|a:1:{...}` and containing installer settings. The file is real PHP session data, unlike the 0-byte `wikidb_session` files.
- The file contains **no pointer-like bytes**: no `0x...`, no standalone `0x7f/0x55/0x56` address. `log/session-files.txt` records the scan.
- `GET /sessions/sess_d5fe...` returns **301 to `Main_Page`** (`95_mwconfig_static_sid`); the `sessions/` directory is outside the nginx document root.
- The installer page itself contains a random CSP nonce (`nonce-...`, base64 with `+`/`/`) but no address.

The installer is exposed, and its session file contains configuration values (including a `wgSecretKey` field). That is a separate configuration-exposure issue, not a heap-pointer leak. No installer form was submitted; only GETs were used, so `LocalSettings.php` was not modified.

### 3.5 `PHPSESSID` — not echoed; upload-progress sessions are client-chosen

`PHPSESSID` never appears in a response header or body:

- `03_upload_cookie` used `PHPSESSID=leakprobe123`; no `Set-Cookie: PHPSESSID`, no echo.
- `64_uprog_cookie` used `PHPSESSID=chosenid1234567890abcdef123456`; file `sess_chosenid1234567890abcdef123456` (367 B), no echo.
- `65_uprog_ptrcookie` used `PHPSESSID=0x7fabcdef1234`; file `sess_0x7fabcdef1234` (351 B), no echo.
- `66_uprog_bodyfield` used a multipart `PHPSESSID=bodyid123` field; file `sess_bodyid123` (346 B), no echo.
- `63_uprog_nocookie` had no `PHPSESSID`; no progress session file and no PHP session cookie (MediaWiki's `PHPSessionHandler` sets `session.use_cookies=0`).

The progress files contain the serialized upload-progress array (keys, temp path, timestamps), not heap memory. The literal `0x7fabcdef1234` in `sess_0x7fabcdef1234` is **our own input**, not a server-disclosed pointer. The absence of a `Set-Cookie` for `PHPSESSID` is expected: MediaWiki disables PHP's session cookie handling at `includes/Session/PHPSessionHandler.php:114`.

### 3.6 API exception traces and debug paths

- `16_parse_obj_serialized` is a full Wikibase API exception trace (4,658 B). It exposes file paths, class names, and argument **types** (`string, string`), but not argument **values** or addresses.
- `56_parse_error_html`, `57_parse_error_wikitext`, and `58_parse_error_raw` exercise the API error formats; the raw format is 4,689 B. None contains a pointer.
- The PHP fatal log for a failed API parse shows a truncated `unserialize('a:3:{i:0;s:16:"...', Array)` argument. The truncation is a fixed prefix; no pointer bytes are included.
- `?debug=1` only selects ResourceLoader debug mode (`debug=2`): `60_debug_main` grows from 35,297 B to 38,450 B, `61_debug_login` to 32,820 B, and `62_debug_api` to 2,415 B. There is no server-side debug toolbar, no SQL trace, and no pointer output.
- `Special:Version` (`08_version`, 99,435 B) lists MediaWiki/PHP/ICU/MariaDB and library versions only; no addresses.
- `load.php?debug=1...` (`90_load_debug`, 126,671 B) contains the FNV constant `0x811C9DC5` and other JavaScript constants, not heap addresses.
- `api.php?action=help` (41,580 B) and `action=paraminfo` (3,063 B) are schema/help text, no addresses.

### 3.7 Static paths and error pages

| Path | Result | Note |
|---|---|---|
| `/sessions/sess_pt01` | 301 → `Main_Page` | sessions dir is outside docroot |
| `/sessions/sess_4f911...` | 301 → `Main_Page` | leaked `wikidb_session` file not served |
| `/sessions/sess_d5fe...` | 301 → `Main_Page` | installer session file not served |
| `/images/` | 403 | autoindex off |
| `/images/README` | 200, 84 B | static file, no pointer |
| `/images/.htaccess` | 200, 735 B | static file, standard rules |
| `/LocalSettings.php` | 200, 0 B | PHP executes; no source |
| `/LocalSettings.php.bak` | 301 → `Main_Page` | not served |
| `/README.md` | 200, 1,662 B | static, no pointer |
| `/composer.json` | 200, 9,001 B | static, no pointer |
| `/maintenance/` | 403 | |
| `/phpinfo.php`, `/info.php` | 404 | |
| `/cache/`, `/docs/`, `/tests/`, `/vendor/`, `/skins/`, `/resources/` | 403 | |
| `/.git/HEAD`, `/server-status`, `/rest.php/...`, `/img_auth.php/foo` | 301 → `Main_Page` | |
| `/mw-config/` | 200, 59,263 B | exposed installer; see 3.4 |
| `/mw-config/index.php` | 200, 59,317 B | exposed installer |
| `/mw-config/?page=NoSuchPage` | 200, 59,263 B | invalid page ignored; new installer session |

No static or error page served session files, source code, or memory addresses.

## 4. Static `save_path` / upload leak: reachability on this FPM stack

The staticleak chain needs a **per-request** `session.save_path` string to be freed while the session subsystem still points at it, so a later request can reclaim that block with attacker-controlled bytes and redirect session writes into the web root.

This stack does **not** provide that prerequisite:

1. `conf/fpm.conf` sets `php_admin_value[session.save_path] = /tmp/opencode/research/wikitype_20261021T212610Z/sessions` at FPM startup.
2. `OnUpdateSaveDir` (`ext/session/session.c:665`) only performs the `open_basedir` check for `PHP_INI_STAGE_RUNTIME` / `PHP_INI_STAGE_HTACCESS`; a startup `php_admin_value` does not create a per-request `zend_string` that is freed at request end.
3. `php_rshutdown_session_globals` does **not** free `PS(save_path)`; the pointer remains valid for the worker lifetime.
4. The mod_php/Apache pattern (per-directory `php_value`, restore at request end) is absent. FPM has no per-request `save_path` allocation here.
5. There is no `.user.ini` in the document root (`find www/mediawiki -name .user.ini` returned nothing), and no application write path can create one: `$wgEnableUploads = false`, there is no upload endpoint, and the only writable web directory (`images/`) is not the script directory used by `index.php`, so a `.user.ini` placed there would not affect `index.php` anyway.
6. `PHPSessionHandler::install()` sets `session.use_cookies = 0` and replaces PHP's save handler; MediaWiki's own session data is not in the PHP files session. The PHP file sessions that do exist are upload-progress sessions (`PHPSESSID`) and the installer sessions (`mw_installer_session`).
7. `sessions/` is outside the nginx document root. `GET /sessions/sess_<id>` falls through `try_files` to `index.php` and returns 301 to `Main_Page`; the same is true for the leaked `wikidb_session` and `mw_installer_session` IDs.

Even if `save_path` were redirected to a web-accessible directory, the files written there would be serialized session data (installer settings or upload-progress metadata), not heap memory. There is no overread of the session buffer in this path, and no pointer bytes are present in the session files.

**F14:** no F14-labeled patch or test description was found in the target source or receipts. The static `save_path` path is blocked by the FPM `php_admin_value` startup scope and the absence of a `.user.ini` write primitive, not by an identified F14 change. If F14 was expected to make `save_path` per-request, it is not present in this stack.

## 5. Chain attempt: why the session-ID leak does not reach `P` / `B0` / `S`

The `zif_passthru` record needs an absolute heap address for the second-decode buffer (`S` / `B0f`) and the stale `php_unserialize_data` (`P`) / binomial (`B0`). The record's fake `var_dtor_entries` must live at a known address; the typed write then targets the fixed `ps_serializers[1].decode` at `0x22c54c8`.

The discovered disclosures do not supply that address:

- `wikidb_session` is a 32-character random MediaWiki session identifier. Its alphabet includes non-hex letters, and it is accepted/reused as an opaque cookie value. It does not encode a pointer, and its 0-byte file is not the trigger record.
- `mw_installer_session` is a 32-hex random PHP file-session identifier. It names a 2,621-byte installer session file, but the file contains `installData` settings, not heap bytes. The file is outside the document root and is not served.
- `PHPSESSID` is client-chosen and never echoed. The `sess_0x7fabcdef1234` file contains the client's literal string, not a server address. The progress files contain only progress metadata/temp paths.
- `X-Request-Id` is 24 hex from `mt_rand() & 0xfffffff`, not a heap address. `ETag`, `Last-Modified`, `Content-Length`, `X-Powered-By`, `Server`, and error traces expose versions, sizes, paths, and types only.
- The static `save_path`/upload path is not reachable on this FPM stack (section 4), so it cannot be used to fetch a session file or to plant a `.user.ini`.

No response, header, cookie, JSON error, HTML error, debug output, or static file contains a canonical heap address. The exact missing channel is therefore an **in-band heap address** (`P`, `B0`, `S`, or `B0f`). Without it, the record cannot be rebuilt and the marker cannot be created under ASLR on.

## 6. Persistent poison, worker recycle, and geometry variation

### 6.1 Historical ASLR-off survivor (not reusable)

The only `zif_passthru` survivor remains the prior ASLR-off run recorded in `/tmp/opencode/research/f12b_passthru_20261021T224157Z/README.md`:

| Item | Value |
|---|---|
| Worker | 1249940 (FPM master 1086116, pool `lab`) |
| Poison | `ps_serializers[1].decode = 0xa3c074` (`zif_passthru`) |
| Write target | `ps_serializers[1].decode = 0x22c54c8`; original `ps_srlzr_decode_php = 0x9e6fae` |
| Producer geometry | `P=0x7ffff358c000`, `B0=0x7ffff359e000`, chunk `0x7ffff3400000` |
| Trigger geometry | `S=0x7ffff3401018`, `B0f=0x7ffff3402018`, `F=0x7ffff3401218`, `NW=16` |
| Marker | `/tmp/opencode/research/f12b_passthru_20261021T224157Z/WIKI_PASSTHRU`, 0 B, mtime `2026-10-22 00:46:33` |
| Survival | HTTP 200, 35,297 B, same worker PID 1249940, no SIGSEGV |

This is **ASLR-off** evidence. The absolute addresses are from the old process and cannot be reused on the ASLR-on stack.

### 6.2 Worker recycle

- The old FPM master 1086116 terminated at **01:00:55**; the log shows `Terminating ...` / `exiting, bye-bye!`.
- Worker 1249940 is now **absent**. The static poison lived in that process's writable mapping and died with it; it does not persist across the worker/stack recycle.
- The old log also records earlier SIGSEGVs and respawns (`1086117`, `1087492`, `1245307`, `1246030`), which is why the survivor process was worker 1249940.
- The new ASLR-on stack started at **01:10:36–01:10:37**: FPM master 52926, worker 52927; no SIGSEGV in the new run.
- No new producer OOM or consumer was run on the ASLR-on worker. The worker is clean and unpoisoned; creating a poison without a valid record would not help and could only destabilize the stack.

### 6.3 Geometry variation

- Old ASLR-off values (`P=0x7ffff358c000`, `B0=0x7ffff359e000`, `S=0x7ffff3401018`, `B0f=0x7ffff3402018`, `NW=16`) are invalid under ASLR on.
- The new heap base is randomized; no in-band leak exposes it. Reading `/proc/<pid>/maps`, using gdb, or using the lab probe was deliberately **not** used for leak discovery, so no new absolute geometry is claimed.
- Host `randomize_va_space=2` and all stack PIDs `personality 00000000` confirm ASLR is on.
- The only recorded variation proof is the change from the old ASLR-off absolute addresses to the new randomized, unmeasured ASLR-on layout; the poison itself did not survive the recycle.

## 7. Marker and survival status

- **ASLR-on marker:** none created. `find` in the new receipt shows no `WIKI_*` marker.
- **ASLR-on survivor run:** not attempted, because no valid record could be built.
- **Historical ASLR-off marker:** `/tmp/opencode/research/f12b_passthru_20261021T224157Z/WIKI_PASSTHRU` remains as historical evidence only. It is not an ASLR-on result.
- **Final health:** `98_final_health` returned HTTP 200, 35,297 B; worker 52927 alive; no SIGSEGV.
- **Shared PIDs:** `4052217`, `4052937`, `4053032`, `4054145` were absent and were not touched.

## 8. Exact missing channel

> The app never discloses a heap address for the PHP session buffer (`S` / `B0f`) or the stale `php_unserialize_data` (`P`) / binomial (`B0`). Session IDs (`wikidb_session`, `mw_installer_session`, `PHPSESSID`) are random or client-chosen opaque identifiers; `X-Request-Id` is `mt_rand` output; error traces and static files expose paths, types, sizes, versions, and timestamps only. The PHP session files are outside the nginx document root and contain serialized application data, not heap pointers. The static `save_path` UAF is unreachable because FPM applies `php_admin_value[session.save_path]` at startup and there is no per-request free/reclaim or `.user.ini` write primitive. Therefore no in-band value can supply `P`/`B0`/`S`/`B0f`, the `zif_passthru` record cannot be rebuilt, and the marker cannot be confirmed with ASLR on.

## 9. Evidence inventory

| File / directory | Contents |
|---|---|
| `req/` | 196 response header/body files for the 98 requests |
| `log/matrix.tsv` | exhaustive 98-row request matrix (label, method, URI, status, curl/nginx bytes, times) |
| `log/nginx-access-window.log` | matching 98 nginx access-log lines |
| `log/requests.log` | curl-side 98-request log |
| `log/stack-state.txt` | PIDs, start times, personality, shared-PID check, final health, FPM log |
| `log/source-notes.txt` | source excerpts for `wfRandomString`, `Telemetry::getRequestId`, `PHPSessionHandler`, `OnUpdateSaveDir`, RSHUTDOWN, and the FPM config |
| `log/session-files.txt` | new session files, sizes, pointer scan, and the `sess_0x7fabcdef1234` input note |
| `log/cookies-and-requestids.txt` | all `Set-Cookie` headers and `X-Request-Id` samples |
| `conf/` | exact `fpm.conf`, `nginx.conf`, and `LocalSettings.wikitype.php` copies |
| `SHA256SUMS` | SHA-256 for every evidence file except itself |

No shared PID was touched. No service was restarted after the ASLR-on stack start. No live `LocalSettings.php` or source file was modified; only session files were created by the GET/POST requests.

## Appendix A — exhaustive request list (98 rows)

The table is the human-readable form of `log/matrix.tsv`. `Bytes` is `curl/nginx`; differences are the known 301 redirect-body and chunked-response accounting differences, not content differences. Every request has `req/<label>.hdr` and `req/<label>.body`.

| # | Label | Method | URI | Status | Bytes (curl/nginx) |
|---:|---|---|---|---:|---:|
| 1 | `01_main` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 2 | `02_main_cookie` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 3 | `03_upload_cookie` | POST | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 4 | `04_api_empty` | GET | `/api.php` | 200 | 42920/42920 |
| 5 | `05_siteinfo` | GET | `/api.php?action=query&meta=siteinfo&siprop=general&format=json` | 200 | 2356/2356 |
| 6 | `06_item` | GET | `/wiki/Item:Q1` | 301 | 0/5 |
| 7 | `07_login` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 8 | `08_version` | GET | `/index.php?title=Special:Version` | 200 | 99435/99435 |
| 9 | `09_entitydata_bad` | GET | `/index.php?title=Special:EntityData/NotAValidID` | 400 | 183/194 |
| 10 | `10_entitydata_q1_json` | GET | `/index.php?title=Special:EntityData/Q1.json` | 200 | 312/312 |
| 11 | `11_entitydata_q1` | GET | `/index.php?title=Special:EntityData/Q1` | 303 | 0/5 |
| 12 | `12_entitypage_q1` | GET | `/index.php?title=Special:EntityPage/Q1` | 301 | 0/5 |
| 13 | `13_wbget_bad` | GET | `/api.php?action=wbgetentities&ids=bad&format=json` | 200 | 496/496 |
| 14 | `14_wbget_q1` | GET | `/api.php?action=wbgetentities&ids=Q1&format=json` | 200 | 324/324 |
| 15 | `15_parse_bad_serialized` | GET | `/api.php?action=parse&format=json&contentmodel=wikibase-item&contentformat=application%2fvnd.php.serialized&text=bad` | 200 | 382/382 |
| 16 | `16_parse_obj_serialized` | GET | `/api.php?action=parse&format=json&contentmodel=wikibase-item&contentformat=application%2fvnd.php.serialized&text=a%3a1%3a%7bi%3a0%3bO%3a8%3a%22stdClass%22%3a0%3a%7b%7d%7d` | 200 | 4658/4658 |
| 17 | `17_parse_bad_json` | GET | `/api.php?action=parse&format=json&contentmodel=wikibase-item&contentformat=application%2fjson&text=%7bbad` | 200 | 368/368 |
| 18 | `18_parse_wikitext_bad` | GET | `/api.php?action=parse&format=json&contentmodel=wikitext&text=%7b%7bbad%7d%7d` | 200 | 1310/1310 |
| 19 | `19_delete` | GET | `/index.php?title=Main_Page&action=delete` | 200 | 29126/29126 |
| 20 | `20_edit` | GET | `/index.php?title=Main_Page&action=edit` | 200 | 30654/30654 |
| 21 | `21_protect` | GET | `/index.php?title=Main_Page&action=protect` | 200 | 41118/41118 |
| 22 | `22_oldid` | GET | `/index.php?title=Main_Page&oldid=999999999` | 200 | 29206/29206 |
| 23 | `23_diff` | GET | `/index.php?title=Main_Page&diff=999999999` | 200 | 28879/28879 |
| 24 | `24_upload` | GET | `/index.php?title=Special:Upload` | 200 | 26605/26605 |
| 25 | `25_prefs` | GET | `/index.php?title=Special:Preferences` | 302 | 0/5 |
| 26 | `26_badtitle` | GET | `/index.php?title=Special:Badtitle/ABC` | 404 | 26749/26749 |
| 27 | `27_skin` | GET | `/index.php?title=Main_Page&useskin=NoSuchSkin` | 200 | 35453/35453 |
| 28 | `28_api_titles` | GET | `/api.php?action=query&titles=Main_Page&format=json` | 200 | 137/137 |
| 29 | `29_rest` | GET | `/rest.php/v1/page/Main_Page` | 301 | 0/5 |
| 30 | `30_imgauth` | GET | `/img_auth.php/foo` | 301 | 0/5 |
| 31 | `31_sessions_static` | GET | `/sessions/sess_pt01` | 301 | 0/5 |
| 32 | `32_images_dir` | GET | `/images/` | 403 | 153/153 |
| 33 | `33_images_readme` | GET | `/images/README` | 200 | 84/84 |
| 34 | `34_localsettings` | GET | `/LocalSettings.php` | 200 | 0/5 |
| 35 | `35_localsettings_bak` | GET | `/LocalSettings.php.bak` | 301 | 0/5 |
| 36 | `36_readme_static` | GET | `/README.md` | 200 | 1662/1662 |
| 37 | `37_composer` | GET | `/composer.json` | 200 | 9001/9001 |
| 38 | `38_maintenance_dir` | GET | `/maintenance/` | 403 | 153/153 |
| 39 | `39_phpinfo` | GET | `/phpinfo.php` | 404 | 16/27 |
| 40 | `40_info` | GET | `/info.php` | 404 | 16/27 |
| 41 | `41_git` | GET | `/.git/HEAD` | 301 | 0/5 |
| 42 | `42_server_status` | GET | `/server-status` | 301 | 0/5 |
| 43 | `43_login_cookie` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 44 | `44_login_phpsess` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 45 | `45_main_wikicookie` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 46 | `46_login_post` | POST | `/index.php?title=Special:UserLogin` | 200 | 30222/30222 |
| 47 | `47_parse_item_page` | GET | `/api.php?action=parse&page=Item%3aQ1&prop=text%7crevid%7cdisplaytitle&format=json` | 200 | 2030/2030 |
| 48 | `48_parse_main_page` | GET | `/api.php?action=parse&page=Main_Page&prop=text%7csections%7crevid&format=json` | 200 | 2890/2890 |
| 49 | `49_query_item_rev` | GET | `/api.php?action=query&prop=revisions&rvprop=content%7ctimestamp%7cids&titles=Item%3aQ1&format=json` | 200 | 475/475 |
| 50 | `50_expand` | GET | `/api.php?action=expandtemplates&text=%7b%7bPAGENAME%7d%7d+%7b%7bSITENAME%7d%7d&format=json` | 200 | 456/456 |
| 51 | `51_siteinfo_ext` | GET | `/api.php?action=query&meta=siteinfo&siprop=extensions%7cskins%7cextensiontags%7cfunctionhooks%7cmagicwords%7cinterwikimap&format=json` | 200 | 19686/19686 |
| 52 | `52_tokens` | GET | `/api.php?action=query&meta=tokens&type=csrf%7clogin&format=json` | 200 | 118/118 |
| 53 | `53_userinfo` | GET | `/api.php?action=query&meta=userinfo&uiprop=groups%7crights%7cblockinfo%7chasmsg%7coptions&format=json` | 200 | 2640/2640 |
| 54 | `54_login_api` | GET | `/api.php?action=login&lgname=NoSuchUser&lgpassword=wrongpass&format=json` | 200 | 349/349 |
| 55 | `55_opensearch` | GET | `/api.php?action=opensearch&search=Main&limit=5&format=json` | 200 | 80/80 |
| 56 | `56_parse_error_html` | GET | `/api.php?action=parse&text=a%3a1%3a%7bi%3a0%3bO%3a8%3a%22stdClass%22%3a0%3a%7b%7d%7d&contentmodel=wikibase-item&contentformat=application%2fvnd.php.serialized&errorformat=html&format=json` | 200 | 4667/4667 |
| 57 | `57_parse_error_wikitext` | GET | `/api.php?action=parse&text=a%3a1%3a%7bi%3a0%3bO%3a8%3a%22stdClass%22%3a0%3a%7b%7d%7d&contentmodel=wikibase-item&contentformat=application%2fvnd.php.serialized&errorformat=wikitext&format=json` | 200 | 4667/4667 |
| 58 | `58_parse_error_raw` | GET | `/api.php?action=parse&text=a%3a1%3a%7bi%3a0%3bO%3a8%3a%22stdClass%22%3a0%3a%7b%7d%7d&contentmodel=wikibase-item&contentformat=application%2fvnd.php.serialized&errorformat=raw&format=json` | 200 | 4689/4689 |
| 59 | `59_parse_contentmodel_bad` | GET | `/api.php?action=parse&text=x&contentmodel=no-such-model&format=json` | 200 | 365/365 |
| 60 | `60_debug_main` | GET | `/index.php?title=Main_Page&debug=1` | 200 | 38450/38450 |
| 61 | `61_debug_login` | GET | `/index.php?title=Special:UserLogin&debug=1` | 200 | 32820/32820 |
| 62 | `62_debug_api` | GET | `/api.php?action=query&meta=siteinfo&format=json&debug=1` | 200 | 2415/2415 |
| 63 | `63_uprog_nocookie` | POST | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 64 | `64_uprog_cookie` | POST | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 65 | `65_uprog_ptrcookie` | POST | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 66 | `66_uprog_bodyfield` | POST | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 67 | `67_login_leaked_id` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 68 | `68_login_leaked_phpname` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 69 | `69_login_both_ids` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 70 | `70_main_leaked_id` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 71 | `71_login_bad_short` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 72 | `72_login_bad_long` | GET | `/index.php?title=Special:UserLogin` | 200 | 29912/29912 |
| 73 | `73_reqid_custom` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 74 | `74_reqid_hello` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 75 | `75_reqid_api` | GET | `/api.php?action=query&meta=siteinfo&format=json` | 200 | 2356/2356 |
| 76 | `76_xff` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |
| 77 | `77_sessions_leaked_id` | GET | `/sessions/sess_4f911jbuf5ti0432fpk3b0k6prg97r2t` | 301 | 0/5 |
| 78 | `78_sessions_phpsess` | GET | `/sessions/sess_leakprobe123` | 301 | 0/5 |
| 79 | `79_images_sess` | GET | `/images/sess_leakprobe123` | 301 | 0/5 |
| 80 | `80_sessions_dir` | GET | `/sessions/` | 301 | 0/5 |
| 81 | `81_u_dir` | GET | `/u/` | 301 | 0/5 |
| 82 | `82_images_htaccess` | GET | `/images/.htaccess` | 200 | 735/735 |
| 83 | `83_dir_cache` | GET | `/cache/` | 403 | 153/153 |
| 84 | `83_dir_docs` | GET | `/docs/` | 403 | 153/153 |
| 85 | `83_dir_tests` | GET | `/tests/` | 403 | 153/153 |
| 86 | `83_dir_vendor` | GET | `/vendor/` | 403 | 153/153 |
| 87 | `83_dir_mw-config` | GET | `/mw-config/` | 200 | 59263/59339 |
| 88 | `83_dir_skins` | GET | `/skins/` | 403 | 153/153 |
| 89 | `83_dir_resources` | GET | `/resources/` | 403 | 153/153 |
| 90 | `90_load_debug` | GET | `/load.php?debug=1&lang=en&modules=startup&only=scripts&raw=1&skin=vector-2022` | 200 | 126671/126671 |
| 91 | `91_api_help` | GET | `/api.php?action=help&format=json` | 200 | 41580/41580 |
| 92 | `92_api_paraminfo` | GET | `/api.php?action=paraminfo&modules=parse&format=json` | 200 | 3063/3063 |
| 93 | `93_mwconfig_again` | GET | `/mw-config/` | 200 | 59263/59339 |
| 94 | `94_mwconfig_cookie` | GET | `/mw-config/` | 200 | 59263/59339 |
| 95 | `95_mwconfig_static_sid` | GET | `/sessions/sess_d5fe543299db3b3f7ca24d38ec50ea62` | 301 | 0/5 |
| 96 | `96_mwconfig_invalid` | GET | `/mw-config/?page=NoSuchPage` | 200 | 59263/59339 |
| 97 | `97_mwconfig_index` | GET | `/mw-config/index.php` | 200 | 59317/59393 |
| 98 | `98_final_health` | GET | `/index.php?title=Main_Page` | 200 | 35297/35297 |

