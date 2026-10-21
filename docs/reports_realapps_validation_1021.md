# Real-targets validation: CVE-2026-109618 / 109619 engine, 2026-10-21

Setting: official installers only, **zero modifications to either app tree**.
Runtime php-fpm 8.5.10 from the *same vulnerable php-src tree* (build_plain), extra
standard extensions (mysqli/pdo_mysql/mbstring/intl/libxml/zlib/openssl) for app
compatibility, **stock php.ini** (no admin_value beyond save_path/error_log plumbing).
Infra: nginx 1.30.1 + MariaDB 11.4.5 user-space, everything under /tmp/opencode/realapps.

|  | URL | app | state |
|--|-----|-----|-------|
| MW | http://127.0.0.1:28840 | MediaWiki 1.46.2 | installed, landing 200, anon-edit = ok |
| WP | http://127.0.0.1:28841 | WordPress 7.1.3   | installed, front 200, login 302 |

## Phase 1: engine trigger exists pre-script on stock targets (proven)

Multipart POST to each app's real route with:
- `name="PHPSESSID"` multipart field (service accepts sid only that way; use_only_cookies=1 stock)
- `name="PHP_SESSION_UPLOAD_PROGRESS"` = key
- padded file part, uploaded at `--limit-rate 40k` (stall → snapshot window)
- snapshot of sessions dir every second from outside the process

Observed on BOTH targets:
- t+02 … t+07: `sess_<attacker-sid>` contains machinery-generated
  `upload_progress_<key>|a:5:{s:10:"start_time";…content_length…bytes_processed(5286→41234→107781→174328→240875)…files…}`: GB-serialized, growing each update, standard min_freq=1s, stock `cleanup=On` removes it at end.
- sid is attacker-chosen plain (`mw0day-check-01` / `wp0day-check-01`); engine opens the session pre-script for it.
- no worker crash (panic-free), machinery runs, exits safe: record is a *machinery-shaped* array (no gadget class exists to satisfy the windows our chain uses).

Interpretation: CVE-2026-109618/109619 trigger machinery **is live** on the actual
MediaWiki / WordPress targets; the engine (`PHP_SESSION_UPLOAD_PROGRESS`→ pre-script
session creation + serialized record placed in the session) executes exactly as in lab.

## Phase 2: delivery from the real attacker position (anon), verdict: CLOSED

Attempted through each app's own anonymous-facing endpoints **only**.

### MediaWiki 1.46.2 (stock)
- anon `api.php?action=upload` + anon csrf token → `{"code":"uploaddisabled","info":"Uploads disabled."}`; MW stock gate closes uploads entirely.
- anon **page edit** succeeds (`result:Success`, revid 2), DB only. No filesystem write.
- even the trivially inspectable `images/.htaccess` has `php_flag engine off` (and MW uploads would be there anyway).
⇒ no anon write primitive → `.user.ini` placement (or `.php` drop) not obtainable from outside.

### WordPress 7.1.3 (stock)
- anon `POST /wp-json/wp/v2/media` → 401 `rest_cannot_create`.
- anon `POST /wp-admin/async-upload.php` → 302 (login redirect).
- anon comment POST → 200 (accepted, DB-only). No filesystem write.
⇒ no anon write primitive → delivery lever not obtainable from outside.

### out-of-model FYI (even full admin couldn't)
- MW admin = admin but still `uploaddisabled` (config-level, not a privilege issue).
- (WP admin has media upload but WP's filter blocks `.ini`/`.php` extensions; included only for completeness, not used as attacker model at bera's request.)

## Conclusion for bera's "provala li, a mano, senza cheat"

- Zero-day **engine reachability**: proven on both real targets, 0 modifications, pre-script, with stock ini and stock updater cadence.
- Full RCE chain (needs a session-content lever `O:1:"D"`-shaped + `.user.ini`/class-file write): **NOT achievable unauthenticated on stock MW/WP**: neither app hands an anonymous user any filesystem lever. Delivery layer = boundary confirmed on real targets, consistent with our restricted-environment matrix findings.
- If either app *enables* uploads (sysadmin action, not attacker) or leases an authenticated-contributor session, the same engine re-arms; risk posture note, not a finding of this test.
- Runtime half (php-fpm 8.5.10) is the vulnerable runtime (**patch state**: 8.5.11 advisory rebuild still pending, scheduled for after the 14:00 UTC advisory).

## Phase 3: pointer-lifetime trace + ASAN battery (2026-10-21 11:50-12:12 UTC)

### 3.1 gdb pointer trace (install_plain/php-cgi, -O1 -g; env from shell, breakpoints-only)
- control (no-gdb) verified first: `sess_mach-trace-001` created+emptied, exit 0.
- spec `side/gdb_p4_3.gdb`; body 3 files, 123403 B (`mach-trace-001`, min_freq stock).
- all 10 pins bind on build_plain/session.c (same source as oldsrc/php-8.5.10 ext copy):
  results (log `side/p4_trace_3.log`):
  - 3256 cache: data table rc=1; after first update rc=2 sustained (record shared with `$_SESSION`). Only ONE update fires in the fast body (min_freq=1s throttle).
  - 3268 (file n≥2): previous file's table alive, **rc=1**: `add_next_index_zval` → `zend_hash_next_index_insert_new` takes ownership (two zvals, one refcount).
  - 3282 (file n≥2): cached `current_file_bytes_processed` still points at the previous file's bucket, stale, **but the table stays alive** (owned by `files[]`), so write-through is stale-but-alive, not freed-memory.
  - 3328/3330 (END, stock no-cleanup branch): `SEPARATE_ARRAY(&progress->data)` dup keeps the old table alive as the session copy; the cached `post_bytes_processed` write lands before the forced update releases the old table ⇒ no freed-write in the default flow.
- static source conclusion (session.c 2980-3345): the cached-pointer UAFs (618/619) require an *execution inside the decode window*; stock machine-only shapes cannot free the holding tables before the last cached-pointer write.

### 3.2 ASAN battery (install_asan, -fsanitize=address, same source)
Shapes (`side/gen_shape.py`, all in-session via CGI stdin jig; env from shell):
- S1 control (3-file 123KB, fast) · S2 11-files (forces `files[]` realloc crossing FILE_STARTs) ·
  S3 1.2MB @40k/s paced multi-update · S4 machinery-planted record then replace+flush ·
  S5 filename groom (4-4.5KB names cycling).
**Result: 0 AddressSanitizer reports, all exit 0** (`side/run_asan_battery.sh`, `asan_S*.err`).
Machine-only route for the 618/619 stale-write has **no reachable window in stock default shapes**, consistent with our lab boundary notes (corruption needs a *resolvable userland class* in the decode window).

### 3.3 real-stack revalidation (stock MW/WP, untouched; external unauth HTTP)
- raw multipart (`--data-binary`, machinery field first) works on both targets: `sess_<sid>` created machine-shaped. `-F a=@body` form (machinery field AFTER the file part) creates **no** record; FILE_START events precede sid/key capture ⇒ the machinery prefix-order requirement is now curl-verified.
- paced 1.2MB @40k/s body on both targets:
  - MW `sess_mw0day-b22s3` grows 380→612→1117→1118→1370→1372 B over 28 s (multiple min_freq=1 s updates), emptied at request end (`cleanup` default=1).
  - WP `sess_wp0day-b22s3` identical wave shifted +4 s (378→…→1372→0).
  - 7 php-fpm workers alive; both apps HTTP 200; zero app/config modifications.
⇒ machinery engine **live on the real targets with today's date stamp**; delivery levers still closed (Phase 2 verdict stands).

## Phase 4: community poc replication (staged) + full cached-pointer lifecycle map (2026-10-21 12:30-12:50 UTC)

Context: pre-embargo public research bundle appeared (`jackalsyn.com/php-up-2026` + GitHub clone Zer061/CVE-2026-109618; tarball sha256 `0c254d54…` **≠** page hash `a29d640e…` ⇒ bundle treated as **read-only shape reference, never executed**). We re-implemented both PoC bodies from their documented layout (`side/staged_618.py` = 618 outer shape, `side/build_p1.py` = 619 two-chunk shape, inert forge `call=0`).

### 4.1 their claims vs our build
- mapping: 618 = inner `current_file_bytes_processed` (poc0), 619 = outer `post_bytes_processed` (poc1); caches armed at session.c **3256** (outer) / refreshed per FILE_START at **3282** (inner); `add_next_index_zval` → `zend_hash_next_index_insert_new` **takes ownership, no addref** (two headers, one refcount; matches their claim and our trace).
- multipart field `PHPSESSID` sets `progress->sid` at FORMDATA (session.c:3212) regardless of `use_only_cookies`; `apply_trans_sid` ⇒ 3260-3264 forces `use_trans_sid=1 / use_only_cookies=0` inside the machinery ⇒ their "stock" delivery is real.
- their own VALIDATION.md admits: no local ASAN hit; live RCE "under constraint" = requires origin-shell-derived per-build delta. We confirm the delta concept is real (per-build, see 4.4).

### 4.2 full lifecycle map, gdb 4 hardware watchpoints (`side/run_g618.sh` → `p618_trace.log`)
Staged 618 shape (inert forge, 62 913 B, 1.35 s stall) on install_plain (8.5.10, -O1 -g, not stripped):
- stores go through BOTH cached buckets **every** FILE_DATA: outer `0x7ffff7a638xx-window` addr constant across the whole request;**same live arData** all stores.
- update#2 (post-stall): `php_session_track_init` destroys the previous decoded tree; **the machinery table survives (rc 2→1)**, held by `progress->data`; addref at 3155 restores rc=2 (type_info flips to `0xc0000407` under destruction, non-fatal).
- stores keep landing in the **live** arData after the decode window (val 15596, 15728, 62914) ⇒ **no write to freed memory on stock flow**.
- decay: END (3338) dtor frees the chain (data→files→current_file rc→0), `zend_mm_set_next_free_slot` writes freelist pointers into the freed 64-bin structs, reclaim is LIFO; the **next request's** `$_COOKIE` array takes the same slots (`php_auto_globals_create_cookie`).
- no-validation quirks recorded: inner store runs **backwards** (5284 → 5119, offset+len lower than a previous value); stores were never bounds-checked.

### 4.3 empirical battery on 8.5.10 (both community shapes, staged)
| shape | target | exit | sess | ASAN |
|---|---|---|---|---|
| 618 staged (inert) | plain php-cgi | 0 | 0 (cleanup=1) | clean |
| 618 staged (inert, cleanup=0 observe) | plain php-cgi | 0 | 542 B record, 2 files, bytes_processed=62913 | clean |
| 618 staged (inert) | asan php-cgi | 0 | 0 | clean |
| 619 staged (inert) | plain php-cgi | 0 | 0 | clean |
| 619 staged (inert) | asan php-cgi | 0 | 0 | clean |
| 618 via nginx→fpm (unauth, external) | stock MW :28840 | 200 OK (36 924 B) | `sessions/wiki/sess_poc618mw1` | n/a |
| 618 via nginx→fpm (unauth, external) | stock WP :28841 | 200 OK (70 035 B) | `sessions/wp/sess_poc618wp1` | n/a |
7 php-fpm workers alive, zero crashes, zero victim modifications.⇒ **the community "2nd update frees the pointer target" model does not hold on 8.5.10 machine-only flows**: the only free of the cached-pointer targets happens at END, after the last store. Their chain still needs an early-free lever (what the 14:00 UTC fix diff must reveal, if the UAF is real).

### 4.4 per-build symbol deltas (ours, from our own non-stripped builds)
| build | `zend_call_function` | `zval_ptr_dtor` | delta |
|---|---|---|---|
| install_plain php-cgi (PIE) | 0x5db626 | 0x6965a5 | **0x18AF7F** |
| install_asan php-cgi (PIE) | 0xeafdfa | 0x1173d43 | **0x2C3D49** |
| realapps php-fpm (PIE) | 0x7b03f1 | 0x86775c | **0xB736B** |
| install_plainpie php-cgi (**non-PIE**, ours) | 0x9cfd3f | 0xa88fae | **0xB926F** |
Non-PIE infra builds ready (infra-only lab change, victims untouched): `build_plainpie` (disable-all lab), `build_np` (realapps-class full stack), both `ELF executable` (non-PIE) with deterministic loading addresses, in case a forge phase becomes reachable after the advisory diff analysis.
