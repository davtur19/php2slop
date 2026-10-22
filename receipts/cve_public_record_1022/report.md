# CVE-2026-109618 / CVE-2026-109619 — public-record research report

**Prepared:** 2026-10-22  
**Scope:** desk research (NVD/MITRE, PHP advisories/source, distros, hosting panels, researcher writeups, public PoCs). No exploit was executed in this research pass; the internal receipts cited in §7.4 come from separate lab runs and are labeled as such.  
**Evidence labels:** **Official** (PHP CNA, NVD, MITRE, vendor advisory) · **Vendor** (distro/panel) · **Third-party** (researcher blog/repo) · **Author claim** (not independently verified) · **Project-internal** (local unpublished receipts).

---

## 0. Bottom line first

1. **Both IDs are public.** They were published on **2026-10-21** by the PHP CNA (`security@php.net`), state `PUBLISHED`; MITRE dates are `2026-10-21T13:48:34Z` (618) and `2026-10-21T13:54:43Z` (619). NVD shows `2026-10-21T14:17:09Z` for both. The "not public / not found" branch does **not** apply. [NVD-618], [NVD-619], [MITRE-618], [MITRE-619]

2. **These are not classic "PHP session deserialization" bugs** in the sense of attacker-controlled serialized session data → `__wakeup()`/POP chain → RCE. The CNA assigns **CWE-416 (use-after-free), CWE-755, CWE-824, CWE-1325, CWE-1419** to both; **CWE-502 (deserialization of untrusted data) is not assigned**. The official one-line descriptions are:
   - **618:** "RCE via OOM corruption" — `longjmp()` on out-of-memory aborts a request mid-initialization, leaving request memory invalid; request shutdown then reads/branches on it.
   - **619:** "RCE via stale global state" — worker-retained globals point into freed request memory; a later request consumes the stale state (producer/consumer UAF).

3. **The session upload-progress path is a confirmed vector for 619.** PHP's GHSA-619 explicitly lists "Session upload progress lifecycle: confirmed" and says `session.upload_progress` is enabled by default, no `session_start()` is required, and it can supply the producer, the consumer, or both. php.net's 619 mitigation is to set `session.upload_progress.enabled=0` and restart workers. [GHSA-619], [PHP-NEWS]

4. **There is an attribution conflict worth flagging:** Wiz and Sansec classify the "upload-progress unserializer use-after-free" under **618**, while PHP's GHSA-619 puts the session/decoder lifecycle under **619**. The same patch fixes both; the session chain exercises both the OOM/bailout half and the stale-session/decoder-global half. Defer to PHP for CVE↔GHSA mapping, but do not pretend the community is unanimous.

5. **Affected (CNA):** PHP **8.2 < 8.2.35**, **8.3 < 8.3.36**, **8.4 < 8.4.27**, **8.5 < 8.5.12**. Fixed: **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**, released **2026-10-21**. PHP 8.1 and older are EOL upstream; PHP supplied minimal source backports for **7.4 / 8.0 / 8.1**, and researchers/distros describe branches back to **5.4** as affected. [PHP-NEWS], [GHSA-618], [CALIF]

6. **CVSS:** CNA CVSS 4.0 **9.2 Critical** (`AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`); NVD CVSS 3.1 **9.8 Critical** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`); Red Hat **8.1 Important**; SUSE **8.1 v3 / 9.2 v4**; Ubuntu **Critical**. The CNA/NVD complexity mismatch (`AC:H/AT:P` vs `AC:L`) is real and should be quoted with its source.

7. **Public PoCs exist, but none was independently verified here.** The most concrete is **9bie's** PHP 8.4.26 + Apache prefork + mod_php chain: two `Set-Cookie` OOB leaks, full 8-byte `pDestructor` overwrite to `zif_system`, no `session_start()`, no `save_path`, no session file. The author claims **3/3 one-shot** and **5/5–10/10** ASLR-on lab runs depending on worker rotation; his lab requires `display_errors=1` and `memory_limit=8M`. That maps to the **619 stale-global** mechanism, not to a deserialization gadget. [9BIE]

8. **Default configuration is relevant:** `session.upload_progress.enabled=1`, `session.use_strict_mode=0`, `session.use_cookies=1`, `session.save_handler=files`, `session.serialize_handler=php`, `memory_limit=128M`, `post_max_size=8M`. The official advisory says full RCE was validated over HTTP against mod_php "with default PHP input and memory limits and normal prefork configurations with multiple workers." The 9bie PoC's `8M`/`display_errors=1` are **lab constraints**, not CVE requirements. [GHSA-618], [GHSA-619], [SESSION-C]

9. **Exploitation status is contested:** CISA KEV catalog **2026.10.21** does **not** list either CVE. NCSC NZ (updated **10:20AM, 22 October 2026**; published 9:15AM) says it is "aware of reports of active exploitation." Sansec's timeline says watchTowr confirmed RCE pre-release and Cloudflare reported early attacks. Treat these as reports, not as CISA-confirmed exploitation. [KEV], [NCSC-NZ], [SANSEC]

---

## 1. Publication / identifiers

| Field | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| CNA | PHP (`security@php.net`) | PHP (`security@php.net`) |
| MITRE state | `PUBLISHED` | `PUBLISHED` |
| Reserved | 2026-10-12T21:03:58Z | 2026-10-12T21:04:00Z |
| Published (MITRE) | 2026-10-21T13:48:34Z | 2026-10-21T13:54:43Z |
| Published (NVD) | 2026-10-21T14:17:09Z | 2026-10-21T14:17:09Z |
| NVD status | `Modified` | `Modified` |
| Title | RCE via OOM corruption | RCE via stale global state |
| GHSA | GHSA-w8hw-w9fx-j79w | GHSA-6wmf-4rv5-p3rp |
| CWE | 416, 755, 824, 1325, 1419 (CNA); NVD lists 416 only | same |
| CNA CVSS 4.0 | 9.2 Critical | 9.2 Critical |
| NVD CVSS 3.1 | 9.8 Critical | 9.8 Critical |
| CISA SSVC (at publication) | exploitation `none`, automatable `no`, technical impact `total` | same |

Sources: NVD API records [NVD-618], [NVD-619]; MITRE CVE Services API [MITRE-618], [MITRE-619]; GHSA pages [GHSA-618], [GHSA-619].

> Note: NVD's `vulnStatus` is `Modified`, not `Analyzed`; the NVD CVSS 3.1 vector is NVD's own assessment, not the CNA's. The CNA's 4.0 vector has `AC:H/AT:P`; SUSE's 4.0 vector has `AT:N`; Red Hat's 3.1 vector has `AC:H`. Quote the source.

---

## 2. Affected versions and SAPIs

### 2.1 Versions

| Branch | Vulnerable | First fixed | Notes |
|---|---|---|---|
| 8.5 | < 8.5.12 | **8.5.12** | 8.5.10 / 8.5.11 vulnerable |
| 8.4 | < 8.4.27 | **8.4.27** | 8.4.26 vulnerable |
| 8.3 | < 8.3.36 | **8.3.36** | 8.3.35 vulnerable |
| 8.2 | < 8.2.35 | **8.2.35** | 8.2.34 vulnerable |
| 8.1 / 8.0 / 7.4 | EOL upstream | minimal source backports | distros/panels backported (cPanel: 8.1.34-5, 8.0.30-12, 7.4.33-19) |
| ≤ 8.1 generally | described as affected by researchers | vendor-dependent | Calif/Wiz/Sansec say back to 5.4; CNA affected list is 8.2–8.5, but NVD's `< 8.2.35` CPE has no lower bound |

The CNA's `affected` data lists only 8.2–8.5. NVD's configuration for the 8.2 line, however, is an open-ended `php < 8.2.35` with no lower bound, so NVD formally covers every older branch as well; the 8.3/8.4/8.5 entries have explicit start versions. php.net explicitly says "PHP 8.1 and older no longer receive updates from the PHP project" and provides minimal 7.4/8.0/8.1 backports. cPanel says "All shipped PHP versions are suspected to be vulnerable at this time." [PHP-NEWS], [CPANEL]

### 2.2 SAPIs

php.net's advisory says: "all PHP installations serving web requests, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. We consider the risk highest for mod_php, with a demonstrated exploit where an unauthenticated request can trigger the attack before any application code runs." [PHP-NEWS]

| SAPI | 618 (OOM corruption) | 619 (stale globals) |
|---|---|---|
| **Apache mod_php** | **Confirmed RCE**, pre-application, default input/memory limits, normal multi-worker prefork | **Confirmed RCE** via session lifecycle and fatal-backtrace paths |
| **PHP-FPM** | Source-level susceptible; FPM exits the child when request startup fails, so the exact pre-app startup-failure sequence does not survive; post-startup OOM can still reach shutdown with invalid state (no complete FPM exploit demonstrated for 618) | **Confirmed session-lifecycle RCE** with a suitable application operation; normal dynamic pool; also conditional early-INI consumer via `PHP_VALUE`/`PHP_ADMIN_VALUE` |
| **php-cgi** | Listed by php.net; not separately detailed in GHSA-618 | Listed by php.net; not separately detailed |
| **FrankenPHP** | Source analysis says it likely calls request shutdown unconditionally, analogous to mod_php | No equivalent early configuration consumer established in default config; "does not make this environment immune" |
| **LiteSpeed LSAPI** | Models FPM; application-specific exploits likely but unvalidated | Conditional candidate via early INI values |
| Embedded/firewall/edge PHP | Vendor assessment required (NCSC NZ note) | Vendor assessment required |

Sources: GHSA-618 "Susceptibility" and "Impact and reliability"; GHSA-619 "Reachability"; php.net advisory. [GHSA-618], [GHSA-619], [PHP-NEWS], [NCSC-NZ]

---

## 3. "Class" — vulnerability class vs PHP class

If by **class** you mean the vulnerability class:

- **CWE-416 Use After Free** — the core memory-safety class for both.
- **CWE-755 Improper Handling of Exceptional Conditions** — OOM/fatal paths abandon cleanup.
- **CWE-824 Access of Uninitialized Pointer** — partially initialized request memory is consumed.
- **CWE-1325 Improperly Controlled Sequential Memory Allocation** — attacker-shaped multipart allocations drive the OOM.
- **CWE-1419 Incorrect Initialization of Resource** — the resource/global is used before its initialization completes.
- **Not CWE-502.** The CNA did not assign "Deserialization of Untrusted Data." There is no requirement for an attacker-controlled serialized object graph, no POP chain, and no `unserialize()` of attacker bytes in the confirmed 9bie chain.

> NVD's own `weaknesses` field lists only **CWE-416** for each record; the five-CWE set is the CNA's assignment in the MITRE record. Quote whichever source you use.

If by **class** you mean a PHP class:

- **No PHP class is the vulnerability.** Neither CVE is a `SessionHandler` / `SessionHandlerInterface` bug, and the confirmed public chain does not require an attacker-chosen class. The internal real-app chain uses HexCoupon's `LoyaltyProgramHelpers::start_session()` as a *delivery* primitive, but the affected unit is PHP's decoder/session global state, not that class.
- The only class-like name in the fix is **`__PHP_Incomplete_Class`**: the 8.5.12 upload-progress decoder keeps every object as an incomplete class, resolves no class, runs no autoloader, and runs no `__wakeup()` / `__unserialize()`. This is a hardening of the session-deserialization *surface*, but it is not the CVE's described root cause. [SESSION-C], [TEST-NOUSERCODE]
- The affected units are internal C functions and globals:
  - `php_session_rfc1867_callback()`, `php_session_rfc1867_update()`, `php_session_rfc1867_cleanup()`
  - `php_session_initialize()`, `php_session_track_init()`
  - `php_var_unserialize_init()` / `php_var_unserialize()` (decoder bookkeeping)
  - `zend_handle_delayed_oom()` / `zend_mm_check_limit()` (OOM path)
  - globals `PS(id)`, `PS(http_session_vars)`, `BG(unserialize)`, `EG(last_fatal_error_backtrace)`

---

## 4. Root cause

### 4.1 CVE-2026-109618 — OOM `longjmp()` leaves invalid request state

PHP historically used `longjmp()` (`zend_bailout()`) for OOM. The bailout can fire while C code is mid-way through initializing request-owned structures. The failed allocation does not have to be related to the invalid structure. Request shutdown then reads or branches on that invalid memory, and a crafted heap layout turns it into RCE. [GHSA-618]

GHSA-618 lists several multipart ways to reach OOM while appearing to respect PHP limits:

- a multipart request **without a usable declared Content-Length** can pass the initial `post_max_size` check and keep supplying decoded body data;
- a part can contain an **unrestricted number of headers**, whose in-memory representation costs much more than the wire form;
- **empty file controls** do not count toward `max_file_uploads` but still create metadata arrays;
- nested field names multiply array work;
- application-specific large allocations can also reach OOM.

The confirmed impact is unauthenticated RCE as the web-worker account. GHSA-618 states: "Complete remote code execution was validated over HTTP against mod_php with default PHP input and memory limits and normal prefork configurations with multiple workers." [GHSA-618]

### 4.2 CVE-2026-109619 — stale worker globals point into freed request memory

619 is a **producer/consumer** UAF across requests handled by the same worker:

- **Producer:** a PHP operation stores request-owned state in a global that survives the request. A fatal error (including OOM) abandons the operation before its matching reset; even a nonfatal diagnostic during later shutdown can repopulate error state after it was cleared.
- **Consumer:** a later request runs an operation **before normal initialization** that reads, frees, branches on, or otherwise acts on the stale value.
- Confirmed consumers: (a) INI diagnostics before request initialization; (b) **session upload progress before ordinary session initialization**.
- Confirmed producers/cases: PHP 8.5 fatal-error backtrace (`EG(last_fatal_error_backtrace)`), session upload-progress lifecycle, and other error/exception/object/extension state.

GHSA-619: "Session upload progress is enabled by default, and no application call to `session_start()` is required. It can supply a producer, consumer or both, but exploitation still requires an interruption after state is published and a subsequent request handled by the same worker." [GHSA-619]

### 4.3 The session upload-progress chain (why it looks like "session deserialization")

Request startup order in `main/main.c` is:

```c
PG(modules_activated) = 0;
php_hash_environment();     /* parses request variables and multipart input */
zend_activate_modules();    /* normal module RINIT */
PG(modules_activated) = 1;
```

Multipart parsing therefore reaches the session extension **before** `zend_activate_modules()`. On the first qualifying file part:

```c
case MULTIPART_EVENT_FILE_START:
    php_rinit_session(0);
    PS(id) = zend_string_copy(Z_STR(progress->sid));
    php_session_rfc1867_update(progress, 0);   /* -> php_session_initialize() */
```

`PS(id)` is set just before the update, and `php_session_initialize()` publishes `PS(http_session_vars)`; both point into the current request heap. If an OOM/fatal occurs before the matching `MULTIPART_EVENT_END` cleanup, the request heap is freed while the worker keeps those globals. On mod_php, `PG(modules_activated)` is still false during the failed startup, so session RSHUTDOWN is skipped; request shutdown still frees the heap. [CALIF]

A second multipart request with a `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` field but **no file part** reaches `MULTIPART_EVENT_END` without a `FILE_START`. In the vulnerable 8.5.11 code there is no reset at `MULTIPART_EVENT_START`; the only early initialization is `FILE_START -> php_session_rfc1867_update() -> php_session_initialize()`. Request B therefore reaches cleanup without ever re-initializing the session globals:

```c
php_session_rfc1867_cleanup()
  -> php_session_initialize()
     -> php_session_track_init()
        -> zval_ptr_dtor(&PS(http_session_vars));  /* stale pointer */
```

If attacker-shaped allocations have reclaimed that freed block with a fake `HashTable`, `zend_hash_destroy()` calls the fake `pDestructor`; 9bie sets it to `zif_system`. That is a **fake-destructor** chain, not a PHP object-injection chain. [CALIF], [9BIE]

ASCII summary:

```text
Request A (same worker)                     Request B (same worker)
multipart START                             multipart END, no FILE_START
  FILE_START -> php_session_initialize()      php_session_rfc1867_cleanup()
  PS(id), PS(http_session_vars) -> heap         php_session_initialize()
  OOM/fatal before END                          php_session_track_init()
  modules_activated == 0                        zval_ptr_dtor(PS(http_session_vars))
  session RSHUTDOWN skipped                       -> fake HashTable
  request heap freed; PS globals dangle             -> pDestructor -> zif_system
```

For the **FPM** variant described by Calif/Wiz, the producer is an application-time fatal (e.g. OOM inside `session_start()`/`unserialize()`), which leaves `BG(unserialize).data` and its nesting level dangling; the next upload-progress request's decoder reuses that stale bookkeeping before normal RINIT. This is the closest thing to a literal "session deserialization" bug: the vulnerable object is the **unserializer's global bookkeeping**, not the session payload. [CALIF], [WIZ]

### 4.4 What is *not* involved

- **`session.save_path` is not the root cause of either CVE.** No session file needs to be written, read, or included for the 9bie/mod_php chain or for the FPM startup-failure path; 9bie's exploit code contains no `save_path` and no `session_start()`. The project's internal real-app decoder chain does use a served session file as a *delivery vehicle*, but the file is not the vulnerability. An NVD keyword query for `PHP session save_path` returns **0** records; the nearby `save_path` CVE (CVE-2007-1835) is an `open_basedir` bypass, not RCE. [NVD-QUERY], [NVD-2007-1835]
- **`session.serialize_handler` is not the trigger.** The default is `php`, but the bug is state lifetime; the patch changes decode behavior for the serializers' shared path.
- **`ps_serializers` is not a vulnerability in itself.** It is the static registry `static ps_serializer ps_serializers[MAX_SERIALIZERS + 1]` at `ext/session/session.c:1173`, holding the `php`, `php_binary`, and `php_serialize` function tables. There is no bug in the registry; the project's internal chain overwrites one of its `decode` entries after a UAF, which makes the registry a *target*, not the root cause. [SESSION-C]
- **No PHP object injection / POP chain.** The 9bie chain does not need an application class, `__wakeup`, `__destruct`, or `unserialize_callback_func`. The 8.5.12 `incomplete_classes_only` change removes the ability to run those callbacks during upload-progress decode, which is a separate hardening of the same surface.

---

## 5. CVSS and severity

| Source | Version | Score | Vector / rating |
|---|---|---|---|
| PHP CNA | CVSS 4.0 | **9.2 Critical** | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| NVD | CVSS 3.1 | **9.8 Critical** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Red Hat | CVSS 3.1 | **8.1 Important** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| SUSE | CVSS 3.1 / 4.0 | **8.1 / 9.2** | v3 `AV:N/AC:H/...`; v4 `AV:N/AC:H/AT:N/...` |
| Ubuntu | priority | **Critical** | "This is a remote code execution vulnerability" |

CISA's SSVC at publication: `Exploitation: none`, `Automatable: no`, `Technical Impact: total` (both CVEs). This is an assessment at publication time, not a guarantee that no exploitation exists. [NVD-618], [NVD-619], [RH], [SUSE-618], [SUSE-619], [UBUNTU]

---

## 6. Fixes

### 6.1 Upstream

- **Releases:** PHP **8.5.12**, **8.4.27**, **8.3.36**, **8.2.35**, announced **2026-10-21** (the 8.5.12 changelog header says 22 Oct 2026; the news announcement and downloads metadata say 21 Oct — a one-day header difference that does not affect the fixed-version mapping). [PHP-NEWS]
- **Commit:** `3584a98bda0f2c0d367255b046798b0d3a221a19`, "Avoid state corruption via bailout", authored 2026-10-18, committed 2026-10-21T14:06:22Z. The commit message explicitly says:
  - Replace bailout on OOM with UnwindExit
  - Properly reset various globals that may be accessed during startup
  - Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
  - Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
  - Full diff: **389 files, +10,759 / −988**. [COMMIT]
- **Changelog:** the 8.5.12 "Core" section lists both GHSAs ("Avoid state corruption via bailout"). [PHP-CHANGELOG]

Key code changes:

1. **OOM path (618):** `longjmp()`/`zend_bailout()` on OOM is replaced by a delayed soft OOM (`EG(delayed_oom)` + `EG(vm_interrupt)`, handled at the next VM safe point via `zend_throw_unwind_exit()`), plus a hard limit that calls `_exit(137)` instead of unwinding. See `Zend/zend_alloc.c` (`zend_mm_delayed_verror`, `zend_mm_hard_limit_error`, `zend_handle_delayed_oom`). [ALLOC]
2. **Early global reset (619):** `php_basic_early_rinit()` is called from `php_request_startup()` before request data is processed:
   ```c
   BG(serialize_lock) = 0;
   memset(&BG(serialize), 0, sizeof(BG(serialize)));
   memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
   php_url_scanner_early_rinit();
   ```
3. **Session reset at multipart START (619):** `php_session_rfc1867_callback()` calls `php_rinit_session_globals()` at `MULTIPART_EVENT_START`, then sets `PS(in_rfc1867_update)` around the update/cleanup, so stale `PS(id)`/`PS(http_session_vars)` are cleared before use.
4. **No user code during upload-progress decode (defense-in-depth):** `php_session_unserialize_init()` calls `php_var_unserialize_set_incomplete_classes_only(..., true)` when `PS(in_rfc1867_update)` is true. Objects become `__PHP_Incomplete_Class`; no class lookup, no autoload, no `unserialize_callback_func`, no `__wakeup()`/`__unserialize()`. At `MULTIPART_EVENT_END`, the patch deletes the `$_SESSION` global because it was populated in incomplete-class mode. [SESSION-C], [TEST-NOUSERCODE]
5. **Regression tests:** `ext/session/tests/rfc1867_no_user_code.phpt`, `rfc1867_incomplete_class_reserved_props.phpt`, `rfc1867_sid_invalid.phpt`, and `tests/basic/oom_rfc1867_*.phpt` (including `oom_rfc1867_upload_progress.phpt`). The `no_user_code` test writes a session record containing `__wakeup`, `__unserialize`, `Serializable`, enum, and missing classes, then asserts that the upload-progress update resolves no classes, keeps the session data intact, and leaves no `$_SESSION` behind. [TEST-NOUSERCODE]

### 6.2 Distros / panels

| Vendor | Fixed packages / advisory |
|---|---|
| **Debian** | php8.4 `8.4.27-1~deb13u1` (DSA-6574-1, trixie); php8.2 `8.2.35-1~deb12u1` (DLA-4848-1, bookworm); as of 2026-10-22 the tracker still shows **sid and forky at 8.4.26-1, vulnerable** |
| **Ubuntu** | 24.04 php8.3 `8.3.6-0ubuntu0.24.04.13`; 26.10 php8.5 `8.5.9-0ubuntu2.1`; 26.04 php8.5 `8.5.4-0ubuntu1.5`; 22.04 php8.1 `8.1.2-1ubuntu2.28`; ESM php7.4 `7.4.3-4ubuntu2.29+esm5`; USN-8948-1/-2 |
| **Red Hat** | RHSB-2026-013; RHSA-2026:87070 (RHEL 10.2 `php`), 87071 (`php8.4`), 87080 (RHEL 8 `php:7.4`), 87072 (RHEL 9 `php:8.2`), 87079 (`php:8.3`), 87151 (`php`) |
| **SUSE** | `php8 >= 8.3.36-150700.3.24.1` (SLE 15 SP7); `php8 >= 8.4.27-160000.1.1` (SLE 16.0); TID-PHP-RCE-202610 |
| **cPanel/WHM** | 11.110.0.153, 11.134.0.66, 11.136.0.50, 11.138.0.18; WP Squared 11.138.1.17; EasyApache: ea-php74 7.4.33-19, ea-php80 8.0.30-12, ea-php81 8.1.34-5, ea-php82 8.2.35, ea-php83 8.3.36, ea-php84 8.4.27, ea-php85 8.5.12 |
| **Plesk** | No official advisory located in this pass; only a community forum thread. Treat Plesk guidance as vendor-dependent (system PHP / distro packages). |

Sources: [DSA], [DLA], [UBUNTU], [RH], [SUSE-618], [SUSE-619], [CPANEL], [PLESK].

### 6.3 Mitigations (partial, not substitutes for patching)

From php.net and the GHSAs:

- **Upgrade** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. This is the only complete mitigation.
- **618:** set `memory_limit=-1` administratively (php_admin_value / FPM pool / Apache), and ensure no pool/directory/application setting restores a finite limit; keep `post_max_size` conservative (8M if no uploads, 32M if uploads); enforce decoded request size, part count, header count, nesting depth at the frontend; use a container/cgroup limit as an availability boundary; **do not** use `RLIMIT_AS`/`RLIMIT_DATA` (they can trigger the vulnerable `mmap()` failure). [GHSA-618], [PHP-NEWS]
- **619:** set `session.upload_progress.enabled=0` and restart every worker; on PHP 8.5 set `fatal_error_backtraces=0` and restart; remove invalid/deprecated per-request INI that emits diagnostics before initialization; fix attacker-reachable fatal errors and execution timeouts; consider `pm.max_requests=1`. Hiding diagnostics with `error_reporting`, `display_errors`, or `@` does **not** protect. [GHSA-619], [PHP-NEWS]
- Wiz's detection suggestions: unusual multipart requests followed by memory-limit errors or repeated HTTP 500s; unexpectedly large/malformed `PHPSESSID` response cookies; unexplained PHP worker churn. [WIZ]

---

## 7. Public PoCs and what they actually show

### 7.1 9bie — `php2shell-bypass-aslr-exp`

- **URL:** https://github.com/9bie/php2shell-bypass-aslr-exp
- **Target:** PHP 8.4.26, Apache prefork, mod_php, official `php:8.4.26-apache` image.
- **Claim (author):** fully remote, HTTP-only, no `session_start()` on the target page, no PHP written on the target; one-shot RCE; **3/3** on the official image; ASLR-on lab **5/5** without an initial HTTP worker rotation, **9/10** with rotation, and **10/10** on a fresh worker. Proof `uid=33(www-data)`.
- **Mechanism:** multipart `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS`; OOM in `php_session_initialize()`; dangling `PS(http_session_vars)`; two `Set-Cookie` OOB leaks (Zend MM chunk base, then libphp base via `ZVAL_PTR_DTOR`); fake `HashTable` with `pDestructor = zif_system`; command execution. No ROP, no partial overwrite, no PHP object injection, no served session file, no `session_start()`, no `save_path`.
- **Lab constraints (author):** `display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`, `session.use_cookies=1`, `session.use_strict_mode=0`, single-worker prefork. The README says a `display_errors=0` heap leak works, but the complete RCE "will be committed later" — so the public end-to-end RCE is display_errors-dependent.
- **Mapping:** the cross-request dangling `PS(http_session_vars)`/`PS(id)` mechanism is the **619 stale-global** half. The README does not name a CVE.
- **Status:** **Author claim, not independently reproduced here.** Plausible and technically detailed; treat success rate as author-reported.

### 7.2 ikow — `php2shell-poc`

- **URL:** https://github.com/ikow/php2shell-poc
- **Claim:** "five independent RCE chains" for CVE-2026-109618/619, PHP 5.4.0–8.5.11, pre-auth, "78% of all websites."
- **Chain A (`chain_a_session_lfi.py`):** upload-progress filename → PHP code in session file → LFI includes session file. Its own docstring says: "This does NOT require a memory corruption exploit — the PHP session serializer stores raw filenames from multipart uploads, allowing PHP code injection into session files. Combined with any local file inclusion, this gives pre-auth RCE." Conditions: `session.upload_progress.enabled=On`, an **LFI sink**, known/guessable `save_path`. This is a generic upload-progress + LFI technique, **not** an exploit of the CVE's memory-safety bug.
- **Chain B:** `var_destroy` UAF, requires the application to call `unserialize()`; not pre-auth.
- **Chain C:** handler mismatch → `__destruct`, FPM, requires two directories with different `serialize_handler`.
- **Chains D/E:** 618 OOM → stale `EG()` (mod_php, "any endpoint") and FPM session OOM → stale `BG()`; **paid subscribers only**, no public code.
- **Status:** **Unverified.** Chain A is explicitly not a memory-corruption exploit; B/C are application/config-dependent; D/E are paywalled. Do not cite this repo as proof that the CVE is trivially exploitable.

### 7.3 Official / third-party statements on PoC status

- **Tenable:** "Code claiming to exploit these vulnerabilities is circulating publicly, but we have not verified that any of it works against CVE-2026-109618 or CVE-2026-109619. Unverified exploit code is sometimes laced with malware, so treat it with caution." It also quotes the PHP Foundation: the PHP security team inspected PoCs that appeared after the leak but "did not identify any functional exploits at the time of release/public disclosure." [TENABLE]
- **php2shell.com** (the coordinated-disclosure microsite run by the researchers, not by php.net) describes the family as "memory-safety vulnerabilities in core PHP" and links to the Wiz/Calif/OpenAI/PHP writeups; it does not ship an exploit tool. [PHP2SHELL]
- **Wiz, Calif, and Sansec** describe confirmed RCE against WordPress, Drupal, Joomla, Magento, and other applications. Those are researcher demonstrations, not public PoC code you can run. [WIZ], [CALIF], [SANSEC]

### 7.4 Project-internal evidence (unpublished, separate from the public record)

The local project has its own receipts; treat these as internal and as lab demonstrations, not as part of the public record or as proof against stock deployments:

- `phpshell/receipts/modphp_oompair_1021/findings.md`: **618 OOM-corruption producer shape on mod_php 8.5.10 reproduced** pre-app-code, byte-parity with the FPM receipt; same-worker consumption shown. **619 stale-decoder RCE on mod_php: not proven.**
- `phpshell/receipts/realchain_20261022/REPORT.md` and `wprepeat_1022/REPORT.md`: **619 stale-decoder RCE proven in a private lab** on PHP-FPM 8.5.10 + WordPress 7/WooCommerce/HexCoupon, ASLR on, final request gdb-free. A free plugin (MultiStep Forms for CF7) writes a 388,350-byte native session file through an unauthenticated form; HexCoupon `LoyaltyProgramHelpers::start_session()` OOM leaves `BG(unserialize)` stale; a 1,052,954-byte static leak yields `K_dest`; `ps_serializers[1].decode` is overwritten with `zif_passthru`; marker created, worker alive; two independent repeats with fresh FPM masters. Lab deviations: `session.upload_progress.cleanup=0`, `session.save_path` under the served docroot, one static worker, and lab plant/trigger endpoints.
- `phpshell/receipts/real_target_preconditions_1022/README.md`: **no stock/default Drupal 11, Joomla 5, WordPress 7, or Moodle 4.5 deployment in this matrix serves native `sess_*` files from a web-writable directory.** Drupal/Joomla default to database sessions; WordPress core has no native sessions; Moodle keeps session files outside the docroot. Every positive above required a lab/deployment change (file sessions, `session.save_path` under the docroot, a large plugin write, and a plant endpoint).
- `phpshell/receipts/mw_session_1022/README.md`: MediaWiki 1.46.2 + a Gerrit extension writes session files unauthenticated, but the decode-slot poison was blocked by the fixed top-level key, UTF-8 normalization, and the absence of an in-band ASLR leak; the poisoned-decode negative control executed nothing and left the worker alive.
- `phpshell/receipts/php5exec_1022/README.md` and `verzif_1022/README.md`: private FPM labs exercise the same family on 5.4.45/5.6.40 and on 7.4.33/8.1.34/8.4.25, consistent with the 5.4+ scope claimed by researchers.
- `phpshell/receipts/advisory_1400/attribution_8510_8512.md`: fix-hunk/CVE mapping, the 389-file breadth, and the `ext/session` + `var_unserializer` changes.

These are consistent with the public picture: the **engine trigger** is real; a **full public chain** is build/config-dependent, and the internal 619 chain needs lab/deployment preconditions rather than stock defaults.

---

## 8. Default-config applicability and prerequisites

### 8.1 Defaults that matter

| Setting | Default (PHP 8.5.12 source) | Relevance |
|---|---|---|
| `session.upload_progress.enabled` | **1** (`PHP_INI_PERDIR`) | required for the session vector |
| `session.upload_progress.cleanup` | 1 | default; 9bie's chain works with it |
| `session.upload_progress.name` | `PHP_SESSION_UPLOAD_PROGRESS` | trigger field |
| `session.upload_progress.prefix` | `upload_progress_` | session key prefix |
| `session.use_cookies` | 1 | needed for the `Set-Cookie` leak |
| `session.use_strict_mode` | 0 | attacker-chosen SID accepted |
| `session.save_handler` | `files` | default handler |
| `session.serialize_handler` | `php` | shared decode path |
| `session.save_path` | `""` (distros often set `/var/lib/php/sessions`) | **not** attacker-controlled; not required |
| `memory_limit` | 128M | 618 OOM target; official exploit works with default |
| `post_max_size` | 8M | multipart bypass per GHSA-618 |
| `max_input_vars` | 1000 | 9bie's leak uses 1001 fields |
| `max_file_uploads` | 20 | empty file controls bypass the count |
| `max_input_nesting_level` | 64 | nested field names multiply work |
| `fatal_error_backtraces` (8.5) | 1 (`ZEND_INI_ALL`) | 619 confirmed backtrace path |
| `display_errors` | production `Off`, development `On` | 9bie needs `On`; official 619 path does not require diagnostics |

Sources: `ext/session/session.c` defaults [SESSION-C]; `main/main.c` defaults for `memory_limit`/`post_max_size`/`max_input_vars`/`max_file_uploads`; `Zend/zend.c` for `fatal_error_backtraces`. [ALLOC]

### 8.2 Is default config exploitable?

- **618 / mod_php: yes, per PHP.** GHSA-618 says complete RCE was validated over HTTP against mod_php with default PHP input and memory limits and normal multi-worker prefork. The OOM strategies are multipart-level (no Content-Length, header count, empty file controls, nesting), not application-level. [GHSA-618]
- **619 / session upload-progress: yes, per PHP**, because `session.upload_progress.enabled=1` by default and no `session_start()` is required. The session consumer is application-independent for the upload-progress path; the FPM producer still needs a fatal after state is published (often an application operation). [GHSA-619]
- **Public PoC caveat:** 9bie's exact chain is more constrained than the CVE (`display_errors=1`, `memory_limit=8M`, single worker). Do not infer from his README that default 128M + multi-worker + `display_errors=0` is unexploitable; PHP says the opposite for its own validated chain. The constraints are about *that PoC's* heap layout/leak, not the bug's reachability.

### 8.3 Prerequisites / reliability

- Network access to a PHP SAPI that parses `multipart/form-data`.
- `session.upload_progress.enabled=1` for the session vector; `file_uploads=1` (default).
- A controllable OOM or fatal at the right point (multipart shapes or application allocation).
- Same-worker reuse for 619 (keep-alive or worker recycling); multiple workers reduce per-request success but do not remove the condition.
- Heap grooming for RCE; memory disclosure helps defeat ASLR.
- No authentication, no application code, no `session_start()`, and no `save_path` write for the 9bie-style mod_php chain.
- FPM 619: a suitable application operation that publishes state and then fatals; not fully application-independent.

---

## 9. Closest PHP session / deserialization CVEs

Both requested IDs are public, so the "not public" fallback is moot. The closest historical session/deserialization issues are:

| CVE | What it is | Why it is (or is not) close |
|---|---|---|
| **CVE-2016-7125** | `ext/session/session.c` skips invalid session names in a way that triggers incorrect parsing; remote attackers can inject arbitrary-type session data via a controlled session name, "as demonstrated by object injection." Fixed 5.6.25 / 7.0.10. | Closest to the *concept* of session-data injection/object injection; not a memory-lifetime bug. |
| **CVE-2016-6290** | `ext/session/session.c` fails to maintain a hash data structure; session deserialization can cause a use-after-free (DoS or possibly other impact). Fixed 5.5.38 / 5.6.24 / 7.0.9. | Closest session-specific UAF; same CWE-416 family. |
| **CVE-2007-1701** | With `register_globals` enabled, deserialization of session data can overwrite arbitrary globals and execute code; demonstrated via `session_decode()` on `"_SESSION|s:39:"`. Fixed 4.4.5 / 5.2.1. | Classic "session deserialization → RCE" from the register_globals era; not the same mechanism. |
| **CVE-2014-8142** | UAF in `process_nested_data()` in `ext/standard/var_unserializer.re` via duplicate keys in serialized object properties; RCE. Fixed 5.4.36 / 5.5.20 / 5.6.4. | Generic `unserialize()` UAF, not session-specific; often cited in session-deserialization discussions. |
| **CVE-2020-7062** | With upload progress enabled and `session.upload_progress.cleanup=0`, a failed upload can cause a NULL pointer dereference/crash. Fixed 7.2.28 / 7.3.15 / 7.4.3. | Same `session.upload_progress` feature, but DoS only; not RCE. |
| **CVE-2015-0273** | Multiple UAFs in `ext/date/php_date.c` via crafted serialized `DateTime`/`DateTimeZone` data; RCE. Fixed 5.4.38 / 5.5.22 / 5.6.6. | Often mislisted as a session bug; it is **ext/date**, not session. Do not cite it as a session CVE. |
| **CVE-2007-1835** | Empty `session.save_path` uses the TMPDIR default after checking restrictions, allowing a local `open_basedir` bypass. Fixed 4.4.5 / 5.2.1. | The only nearby `save_path` CVE; privilege/`open_basedir`, not RCE. |

Sources: NVD records for each ID [NVD-2016-7125], [NVD-2016-6290], [NVD-2007-1701], [NVD-2014-8142], [NVD-2020-7062], [NVD-2015-0273], [NVD-2007-1835].

---

## 10. Discrepancies and open questions

1. **618 vs 619 attribution for the upload-progress chain.**
   - PHP: 618 = OOM corruption; 619 = stale global state; GHSA-619 explicitly lists the session upload-progress lifecycle; php.net's 619 mitigation is `session.upload_progress.enabled=0`.
   - Wiz: table maps "Upload-progress unserializer use-after-free" and "Remote process-memory disclosure" to **618**; "Fatal-error backtrace" and "OPcache type confusion" to **619**.
   - Sansec: repeats Wiz's mapping.
   - Tenable: follows PHP's mapping (619 → `session.upload_progress.enabled=0`).
   - **Best reading:** the session chain has two halves — the OOM/bailout (618) and the stale session/decoder globals (619). PHP's CVE split is authoritative for the CVE record; the community's grouping reflects which half each writeup emphasizes. Cite both where relevant; do not claim one side is simply wrong.

2. **"Incomplete fix" claim.** A Fediverse/Mastodon thread claimed the 8.5.12 fix was incomplete; the thread itself (relayed on oss-security by Yves-Alexis Perez) already called the reported follow-on "a *different* vulnerability." Aaron Rainbolt relayed that Canonical asked php.org and was told it was "unrelated and not a real issue." PHP 8.5.10's GH-23043 ("broken session id code can cause zend_mm_heap corrupted") is a separate earlier session fix, not evidence that 8.5.12 is incomplete. [OSS-17], [OSS-23], [PHP-CHANGELOG]

3. **KEV vs active-exploitation reports.** CISA KEV 2026.10.21 has 1,754 entries and neither CVE. NCSC NZ says "aware of reports of active exploitation" (2026-10-22). Sansec's timeline says watchTowr confirmed RCE pre-release and Cloudflare reported early attacks. These are not mutually exclusive: KEV inclusion lags, and "reports" are not the same as confirmed in-the-wild exploitation. State the source for each claim.

4. **EOL scope.** The CNA `affected` list covers 8.2–8.5, but NVD's first CPE is `< 8.2.35` with no lower bound, so NVD formally covers older branches. Researchers say 5.4+; cPanel says all shipped versions are suspected vulnerable; PHP provides 7.4/8.0/8.1 backports. For asset inventories, do not treat "not in the CNA's affected list" as "not affected" for EOL branches.

5. **No public, independently verified 618 PoC found.** 9bie's public chain maps to 619's stale-session-global mechanism. ikow's 618 chain D is paywalled. The project's own mod_php receipt reproduces the 618 **producer**, not full RCE. This is an evidence gap, not proof that 618 is unexploitable; PHP says it validated complete RCE. Separately, the project's FPM real-app receipts do prove a 619 stale-decoder RCE chain, but only with lab/deployment preconditions (see §7.4).

6. **`display_errors` dependence.** 9bie's public chain needs `display_errors=1` for the leak (he says a `display_errors=0` leak exists but the full RCE is not yet committed). PHP's GHSA-619 says diagnostics need not be displayed/logged for the INI-diagnostic consumer, and the session consumer does not require a diagnostic. Do not generalize 9bie's constraint to the CVE.

7. **Sansec vs PHP on FPM and the leak.** Sansec says the upload-progress handler "can return freed worker memory to the client inside a PHPSESSID response cookie" and that "Apache mod_php and PHP-FPM are both affected." PHP's GHSA-618 says no complete FPM exploit has been demonstrated, and GHSA-619 only validates the session-lifecycle RCE on FPM after a successful startup. These are not necessarily contradictory — GHSA-618 allows post-startup FPM susceptibility — but the FPM leak claim is a third-party assertion with no public FPM proof in the CNA record. Treat it as unverified for FPM.

---

## 11. References

**Official / primary**

- [NVD-618] https://nvd.nist.gov/vuln/detail/CVE-2026-109618
- [NVD-619] https://nvd.nist.gov/vuln/detail/CVE-2026-109619
- [MITRE-618] https://cveawg.mitre.org/api/cve/CVE-2026-109618
- [MITRE-619] https://cveawg.mitre.org/api/cve/CVE-2026-109619
- [GHSA-618] https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- [GHSA-619] https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- [PHP-NEWS] https://www.php.net/archive/2026.php#2026-10-21-5
- [PHP-CHANGELOG] https://www.php.net/ChangeLog-8.php
- [COMMIT] https://github.com/php/php-src/commit/3584a98bda0f2c0d367255b046798b0d3a221a19
- [SESSION-C] https://github.com/php/php-src/blob/php-8.5.12/ext/session/session.c
- [ALLOC] https://github.com/php/php-src/blob/php-8.5.12/Zend/zend_alloc.c
- [VAR-UNSER] https://github.com/php/php-src/blob/php-8.5.12/ext/standard/var_unserializer.re
- [TEST-NOUSERCODE] https://github.com/php/php-src/blob/php-8.5.12/ext/session/tests/rfc1867_no_user_code.phpt
- [PHP-MANUAL] https://www.php.net/manual/en/session.upload-progress.php
- [OSS-618] http://www.openwall.com/lists/oss-security/2026/10/21/6
- [OSS-619] http://www.openwall.com/lists/oss-security/2026/10/21/7
- [OSS-17] http://www.openwall.com/lists/oss-security/2026/10/21/17
- [OSS-23] http://www.openwall.com/lists/oss-security/2026/10/21/23

**Vendors**

- [DSA] https://security-tracker.debian.org/tracker/DSA-6574-1
- [DLA] https://security-tracker.debian.org/tracker/DLA-4848-1
- [UBUNTU] https://ubuntu.com/security/CVE-2026-109618 and https://ubuntu.com/security/CVE-2026-109619
- [RH] https://access.redhat.com/security/vulnerabilities/RHSB-2026-013
- [SUSE-618] https://www.suse.com/security/cve/CVE-2026-109618.html
- [SUSE-619] https://www.suse.com/security/cve/CVE-2026-109619.html
- [CPANEL] https://support.cpanel.net/hc/en-us/articles/44397389677335-Critical-PHP-Security-Release-CVE-2026-109618-and-CVE-2026-109619
- [PLESK] https://talk.plesk.com/threads/critical-php-security-updates-cve-2026-109618-cve-2026-109619.395529/
- [KEV] https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- [NCSC-NZ] https://www.ncsc.govt.nz/alerts/cve-2026-109618-and-cve-2026-109619-affecting-php/

**Third-party research / PoCs**

- [WIZ] https://www.wiz.io/blog/php2shell-php-rce
- [CALIF] https://calif.io/php2shell/
- [PHP2SHELL] https://www.php2shell.com/
- [SANSEC] https://sansec.io/research/php2shell
- [TENABLE] https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote
- [9BIE] https://github.com/9bie/php2shell-bypass-aslr-exp
- [IKOW] https://github.com/ikow/php2shell-poc
- [NVD-QUERY] https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=PHP%20session%20save_path

**Closest session CVEs**

- [NVD-2016-7125] https://nvd.nist.gov/vuln/detail/CVE-2016-7125
- [NVD-2016-6290] https://nvd.nist.gov/vuln/detail/CVE-2016-6290
- [NVD-2007-1701] https://nvd.nist.gov/vuln/detail/CVE-2007-1701
- [NVD-2014-8142] https://nvd.nist.gov/vuln/detail/CVE-2014-8142
- [NVD-2020-7062] https://nvd.nist.gov/vuln/detail/CVE-2020-7062
- [NVD-2015-0273] https://nvd.nist.gov/vuln/detail/CVE-2015-0273
- [NVD-2007-1835] https://nvd.nist.gov/vuln/detail/CVE-2007-1835

---

## 12. Bottom line for the project

- If the project is testing **PHP 8.5.10** with `session.upload_progress`, it is in the vulnerable range. For the mod_php upload-progress chain, the relevant public mechanism is **619's stale session/decoder globals**, with **618's OOM bailout** as the enabler. Patching only one half is not the upstream fix: 8.5.12 changes both the OOM unwinding and the early session/decoder resets.
- The project's "session deserialization" framing is accurate only at the level of **the unserializer's global bookkeeping** and **the pre-RINIT session decode window**. It is not a `session_decode()`/POP-chain bug. The public 9bie chain does not need `save_path`, a session file, or an application class; the internal real-app decoder chain does need a served session file and a large session write.
- If the project's chain relies on a userland `__wakeup`/`__unserialize` during upload-progress decode: **8.5.12's `incomplete_classes_only` change kills that**, because no class is resolved and no user code runs. That is a real behavioral break for gadget-based variants, separate from the UAF fix.
- The public 9bie PoC is the best-documented end-to-end 619-style chain, but its `display_errors=1` / `memory_limit=8M` / single-worker constraints are lab-specific. Do not overgeneralize its success rate to default multi-worker production.
- **Internal evidence:** the project's `realchain_20261022` / `wprepeat_1022` receipts prove the **619 stale-decoder → `ps_serializers[].decode` → `zif_passthru`** chain end-to-end on PHP-FPM 8.5.10 with real WordPress/WooCommerce/HexCoupon and ASLR on, without gdb in the final request. But every positive needs a web-served writable session directory, a large unauthenticated session write, and an OOM plant; `real_target_preconditions_1022` shows **no stock Drupal/Joomla/WordPress/Moodle deployment** serves `sess_*` files from a web-writable directory. Treat the internal chain as proof of the primitive, not as a stock-app pre-auth exploit.
- The strongest public evidence for default-config impact is PHP's own GHSA-618 statement (mod_php, default input/memory limits, normal multi-worker prefork) and GHSA-619's session-upload-progress confirmation. The strongest counter-evidence is the absence of a public, independently verified 618 PoC and the FPM startup-failure caveat.

---

## Appendix A — Search coverage and gaps

Both CVEs were researched by ID and by the non-ID keyword set requested. What each keyword surfaced:

| Query (no CVE ID) | What it actually found | Verdict |
|---|---|---|
| `PHP session deserialization RCE 2026` | The 21 Oct 2026 PHP/Wiz/Calif/Sansec material and the GHSA family. "Session deserialization" refers to the upload-progress decoder-global variant; no separate object-injection advisory. | Covered by this report; no extra CVE. |
| `php_session_decode exploit` | Historical CVE-2007-1701 (`register_globals` + `session_decode()`), plus generic `session_decode()` documentation. No 2026 exploit depends on `session_decode()`. | Historical only. |
| `ps_serializers` | The static serializer registry in `ext/session/session.c` (`ps_serializers[MAX_SERIALIZERS + 1]`). No advisory or PoC targets the registry itself. | Source symbol, not a primitive. |
| `PHP 8.5.10 session` | 8.5.10 is inside the vulnerable range (< 8.5.12); the 8.5.10-era session fix GH-23043 ("broken session id code can cause zend_mm_heap corrupted") is a different bug. | No separate advisory. |
| `PHP session save_path RCE` | NVD keyword query returns **0** records; the only adjacent CVE is CVE-2007-1835 (empty `save_path` → `open_basedir` bypass, local, not RCE). | Not involved. |
| `session.upload_progress RCE` | CVE-2020-7062 (upload-progress NULL dereference, DoS) and this 2026 family. No other RCE CVE for the feature. | 2026 family + historical DoS. |

Coverage caveat: the DuckDuckGo HTML endpoint answered with a bot challenge, so no broad web-index sweep was possible. Evidence came instead from the NVD and MITRE APIs, GitHub's API (advisories, commits, repos, issues), GHSA pages, php.net, Debian/Ubuntu/Red Hat/SUSE trackers, cPanel, oss-security, and direct fetches of Wiz/Calif/Sansec/Tenable/NCSC NZ. No official Plesk advisory was located; Plesk appears only in a community forum thread. CISA KEV 2026.10.21 does not list either CVE.

---

*End of report.*
