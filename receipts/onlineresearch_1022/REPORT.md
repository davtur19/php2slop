# PHP session-deserialization memory corruption under PIE + ASLR
## Binary-exploitation technique survey (leaks, gadgets, hijacks) — public sources only

Scratch: `/tmp/opencode/onlineresearch_1792633763/`
Date: 2026-10-22. No lab work, no repo writes, no PHPGGC/POP testing.

---

## 0. Bottom line

1. The bug class is public and current: **CVE-2026-109618 / CVE-2026-109619 ("php2shell")**, fixed 2026-10-21 in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. The session/decoder-specific bug is **CVE-2026-109619** (stale global state, including `BG(unserialize)`), with `PS(id)` and `PS(http_session_vars)` as sibling stale pointers. CVE-2026-109618 is the OOM/longjmp corruption that supplies the fatal interruption.
2. **A served session file is not needed.** The public chains work entirely in memory and in-band over HTTP.
3. The strongest public pattern is: **OOB read through a stale `zend_string`/`PS(id)` → `Set-Cookie` leak of heap + libphp/PIE base → `zif_system` fake HashTable/execute_data** (3em0), or **arbitrary read → ELF scan → `.gnu_hash` → GOT dump → fake `stdClass` handlers → `system`** (calif.io). Wiz confirms the same leak+UAF combination on stock WordPress/Drupal/Joomla.
4. **PHP-FPM**: the vendor says session-lifecycle RCE was validated on FPM, but no public end-to-end FPM + PIE chain with offsets exists. The leak/terminal primitives transfer; the producer differs (FPM kills the child on startup failure, so the fatal/OOM must occur during application execution).
5. **Default-config caveats**: `session.upload_progress.enabled=1`, `session.serialize_handler=php`, `session.use_strict_mode=0`, `session.save_path=""` (not served) — favorable. But the 3em0 pure-HTTP libphp leak was calibrated with `display_errors=On` and `memory_limit=8M`; a `display_errors=Off` OOM-in-cookie variant is published for the heap leak, and the vendor says default input/memory limits are exploitable, but offsets/success rates need recalibration.

---

## 1. Primitive model

| Primitive | Meaning in this bug | Public evidence |
|---|---|---|
| **W** — attacker session write | `session.upload_progress` stores the progress key (attacker `PHP_SESSION_UPLOAD_PROGRESS` value) and the raw upload **filename** into the session record, before app code and without `session_start()`. `PHPSESSID` in the POST body is accepted despite `use_only_cookies=1`, so the attacker also chooses the session id. | Wiz; ikow; 3em0; advisory GHSA-6wmf |
| **D** — decode slot | `BG(unserialize).data` / `.level` in executor globals, and `PS(id)` / `PS(http_session_vars)` in session globals, can outlive the request after a fatal/OOM `longjmp` skips their reset. The next request's pre-RINIT upload-progress decode reuses them. `BG(unserialize).data` is a `php_unserialize_data*` with inline `var_entries` and `last`/`last_dtor` pointers; if its freed block is reclaimed with attacker bytes, the decoder treats attacker memory as live bookkeeping. | Advisory GHSA-6wmf ("session or decoder state"); Wiz ("decoder stores request-owned bookkeeping in `BG(unserialize)`"); `var_unserializer.re` lines 60–93 |
| **F** — served/leaked session file | `save_path` file readable over HTTP or via another read primitive. Not present by default (`save_path=""`, distro dirs are outside webroot, files `0600`). | PHP manual; no public base-leak use |

Key source fact (`ext/standard/var_unserializer.re`, PHP 8.4.26):
- `php_var_unserialize_init()`: if `BG(unserialize).level` is non-zero, it does `d = BG(unserialize).data; ++BG(unserialize).level;` instead of allocating a fresh `php_unserialize_data`.
- `php_var_unserialize_destroy()` only clears `BG(unserialize).data` when the level reaches 0. An OOM `longjmp` that skips destroy leaves `level=1` and `data` pointing at freed request memory.
That is the "decode slot": one stale pointer + attacker-controlled reclaim = controlled `last`, `last_dtor`, `allowed_classes`, `max_depth`.

---

## 2. Technique matrix

Legend — **PIE**: `leak` = obtains a PIE/libphp base; `needs` = requires a base; `n/a`. **save_path**: `irr` = irrelevant (no file needed); `served` = requires served/readable session file. **No app**: `yes` = no application code required; `partial` = stock app path or SAPI-dependent; `no` = needs app sink/class. **Prims**: W/D/F as above. **Result**: what the technique yields.

### 2.1 Leaks and ASLR defeat

| # | Technique | Prerequisite | PIE | save_path | No app | Prims | Result | Source |
|---|---|---|---|---|---|---|---|---|
| L1 | Stale `PS(id)` `zend_string` + `php_url_encode()` OOB read into `Set-Cookie` | upload_progress; OOM/fatal leaving `PS(id)` and `send_cookie=1`; same worker; headers_sent (warning) or OOM-in-cookie variant; reclaim freed id block with a forged `zend_string` header (`len`, `data`) | leak | irr | yes (mod_php); partial (FPM) | W+D | 4–12 KB live heap bytes, 47–98 heap pointers → Zend MM 2 MB chunk base; stage-2 variant makes `len` read a HashTable `nTableSize` and leaks `pDestructor = ZVAL_PTR_DTOR` → **libphp base** | Wiz; 3em0 `HTTP_HEAP_LEAK.md`, `ASLR_PURE_HTTP.md` |
| L2 | ELF-header scan for PIE base (2 MB then 1 MB steps), crash oracle | arbitrary read; worker respawn keeps the same mapping; bad read crashes one worker | leak | irr | yes once read exists | W+D | finds `\x7fELF` → libphp/PHP base in ~50–120 requests | calif.io R-2 |
| L3 | `.gnu_hash` symbol resolution from ELF base | ELF base (L2); parse `PT_DYNAMIC`, `.dynsym`/`.dynstr`/`.gnu_hash` | leak | irr | yes | W+D | `executor_globals`, `PLTGOT` (and any exported symbol) with no symbol table | calif.io R-3 |
| L4 | GOT dump for libc `system()` | ELF base + `.dynamic`; use `DT_PLTRELSZ` `d_val` as a fake `zend_string.len`, base at `&d_val-0x10` | leak | irr | yes | W+D | ~83 KB GOT; cluster pointers → libc base → `system` (~1.5–2 k requests as published) | calif.io R-4 |
| L5 | Leaked `zend_object_handlers*` → scan back to `zend_module_entry` → `zend_function_entry[]` → `zif_system` | arbitrary read; one live built-in object (DateInterval etc.) and its handlers pointer | leak (avoids ELF parsing) | irr | yes once read exists | W+D | `zif_system` handler address from the standard module's static function table; no `system` symbol needed | spyduck CTF; calif.io uses the same module-table walk via `var_dump` |
| L6 | Heap chunk base from any leaked heap pointer (`ptr & ~0x1fffff`) | any disclosure (L1, L7, session_encode) | n/a | irr | yes | W+D/F | 2 MB-aligned Zend MM chunk base; anchor for all heap-relative offsets | 3em0; calif.io; SEC26 §5.2.1 |
| L7 | `session_encode()` + `php_serialize` reentrancy OOB read (775 B / 32 KB) | app calls `session_start()` and defines a class with `__serialize`; `session.serialize_handler=php_serialize` (not default) | leak | irr | no | W+D (app) | heap pointers and a libphp code pointer (`anchor - 0x5b6309` in that build) | 3em0 `NOTES.md` §10.1 |
| L8 | `Serializable::unserialize` var_hash UAF → arbitrary read (`uaf_read`) | app calls `unserialize()` on attacker data; a `Serializable` gadget class; heap leak first | leak | irr | no | W+D (app sink) | arbitrary read of N bytes; then full remote chain (L2–L4) | calif.io ("21-Year-Old Vulnerability") |
| L9 | Served/leaked session file as a leak | `save_path` inside webroot or another file-read primitive; file contains a serialized payload | none | served | yes | W+F | only attacker-known serialized bytes / other users' session data; **no memory addresses** | dead end (see §4) |
| L10 | Format-string leak | app passes attacker data as a format string; PHP engine/session path has static format strings only | n/a | irr | no | — | none in default PHP; `%n` not reachable | dead end (see §4) |

### 2.2 Control-flow hijack / terminal

| # | Technique | Prerequisite | PIE | save_path | No app | Prims | Result | Source |
|---|---|---|---|---|---|---|---|---|
| H1 | `pDestructor = zif_system` + fake `zend_execute_data` (`num_args=1`, arg1 → fake `zend_string` with command) | libphp base (L1/L2); heap base; 167-byte controlled live string; fake HashTable in reclaimed memory | needs base | irr | yes | W+D | `zend_hash_destroy` → `pDestructor(&bucket->val)` → `zif_system(execute_data)` → command; no libc needed; worker may die after proof | 3em0 `ASLR_PURE_HTTP.md` §3 |
| H2 | Fake `zend_object` as `Closure`, `func.handler = zif_system`; call `$obj(cmd)` | arbitrary read; `zend_ce_closure`, `closure_handlers`, `zif_system`; fake object bytes; local dispatch `$obj(...)` | needs base/leaks | irr | no (local chain) | W+D (app) | `ZEND_INIT_DYNAMIC_CALL` → `ZEND_DO_FCALL` → `zif_system(cmd)` | calif.io local; PoC 10/10 ASLR on PHP 8.5.5 |
| H3 | Fake `stdClass` + `handlers->get_properties_for = system` during `serialize()` | libc base (L4); `stdClass` class entry; spray address; app calls `serialize()` after decode | needs base | irr | no (needs serialize sink) | W+D (app) | `serialize()` → `get_properties_for(obj)` → `system(obj)`; command at `obj+0`, first byte adjusted by `GC_ADDREF`; 14 usable bytes | calif.io remote; 3/3 ASLR on php:8.5-apache |
| H4 | Overwrite `zend_internal_function.handler` of `var_dump` with `zif_system`; call `var_dump(cmd)` | arbitrary write (or `/proc/self/mem`) + libphp base + `EG(function_table)` walk | needs base | irr | no (local demo) | W+D | `var_dump('id ...')` dispatches to `zif_system`; local `USE_ZEND_ALLOC=0` + `/proc/self/mem` demo | ikow `chain_b_uaf_rce.php` |
| H5 | `pDestructor = leave; ret` + ROP: `pop rdi; ret`, `pop rsi; ret`, `ret` (align), `popen@plt`, `exit@plt` | libphp base (L1); heap base; 320-byte payload; stack pivot `RBP = arData + nNumUsed*32` | needs base | irr | yes | W+D | stack pivot to payload, `popen("id>/tmp/x","r")`; **ret2plt inside libphp, no libc base** | 3em0 `NOTES.md` §10.2 |
| H6 | `pDestructor = system` with command pointer in fake bucket | libc base (L4 or /proc maps); heap base | needs base | irr | yes | W+D | `system(S+0xa0)`; simplest terminal if libc known | 3em0 `NOTES.md` §3.3 |
| H7 | Partial overwrite of a code pointer (`pDestructor`, saved return address) | byte-granular write into a live libphp/PIE pointer; target within reach of the overwritten bytes | 2-byte: base-free only if target within 64 KB and base alignment leaves bits 0–15 fixed; 3-byte: needs low base bits / ~1/8 brute + crash oracle | irr | yes | W+D | redirect `zval_ptr_dtor` to a nearby gadget or (with 3 bytes) `zif_system` (~1.9 MB away in 3em0's build); **no public PHP PoC** — inference | Nightmare partial overwrite (generic); 3em0 offsets for distance |
| H8 | Partial heap-pointer overwrite to fake object on the same 2 MB chunk | page-level heap fengshui; 1-byte OOB write or UAF; fake `zend_array`/bucket on the target page | n/a (heap only) | irr | yes (built-in objects) | W+D | corrupt `zval.value` low bytes → fake `zend_array` → `pDestructor` called with controlled arg; still needs a code address for `pDestructor` (probe/leak) | SEC26 paper §5.1.2, §6.1, §7.3.3 |
| H9 | Classic `ret2plt` | PIE base + stack pivot/ROP control | needs base | irr | yes | W+D | `popen@plt`/`system@plt`/`exit@plt`; no libc base if PLT import exists | HackTricks ret2plt; 3em0 H5 |
| H10 | `ret2dlresolve` | PIE base (PLT0) + known writable address for fake `Elf64_Rela/Sym` + stack pivot | needs base | irr | yes | W+D | resolves an arbitrary libc symbol without a libc leak; **strictly dominated** by H5/H1 here (PLT already has `popen`, and `zif_system` is in-image) | HackTricks; ir0nstone; mark dominated |
| H11 | GOT overwrite (full or partial) | libc/PIE base + arbitrary write; or partial 2-byte if target in same page | needs base/partial | irr | yes | W+D | redirect a resolved GOT entry to `system`; no public PHP session-bug PoC; dominated by H1/H5 | generic; mark unproven |
| H12 | Heap-only fake object with **no** code pointer (shellcode on heap) | NX; need executable heap or a code pointer | n/a | irr | yes | W+D | **dead end** on default NX; PHP heap is non-executable; opcache JIT executable buffers are not attacker-writable via this primitive | SEC26 (implicit); see §4 |

### 2.3 Session logic, adjacent bugs, dead ends

| # | Technique | Prerequisite | PIE | save_path | No app | Prims | Result | Source |
|---|---|---|---|---|---|---|---|---|
| S1 | `session.save_path` inside webroot, session file served as PHP | misconfigured `save_path`; web server executes session files | n/a | served | yes | W | direct PHP code execution from session filename/value; **fails default** (`save_path=""`, outside webroot, `0600`) | dead end for default |
| S2 | `session.upload_progress` filename/value → PHP code in session file + LFI | an LFI sink in the app; `upload_progress.enabled=1`; `cleanup=Off` or race | n/a | served/read via LFI | no | W+F | include session file → PHP executes; classic pre-auth LFI→RCE, not a binary bug | HackTricks LFI2RCE; cnpanda |
| S3 | Serializer mismatch (`php` vs `php_serialize`) → object injection / `__destruct` on decode failure | two directories with different `session.serialize_handler` (`.user.ini`/`.htaccess`); app `session_start()`; gadget class | n/a | irr | no | W+D | object injection / POP chain; `__destruct` fires even when decode returns FAILURE | ikow Chain C; cnpanda (bug #71101) |
| S4 | Session fixation via POST-body `PHPSESSID` | `session.use_only_cookies=1` (default) but the FORMDATA handler fails to check it; `use_strict_mode=0` (default) | n/a | irr | yes | W | attacker chooses the session id, enabling file/decode targeting | Wiz; ikow; advisory |
| S5 | `session_decode()` / `php_session_decode()` / `ps_serializers[]` | `session_decode()` needs app code; `php_session_decode` is a static C function; `ps_serializers` is a static array of `{name, encode, decode}` function pointers | n/a | irr | no | — | no engine-only entry point; `ps_serializers` is writable `.data` but needs an arbitrary write + base — not a bypass | PHP 8.4.26 source; dead end |
| C1 | Historical `unserialize()` memory-corruption CVEs (CVE-2015-0231 UAF in `process_nested_data`; CVE-2015-0273 DateTime UAF; CVE-2016-7124 magic-method abuse) | app calls `unserialize()` (or session decode on old PHP); crafted object graph | old PHP only | irr | no | W+D | NVD says CVE-2015-0231 "allows remote attackers to execute arbitrary code via crafted unserialize"; modern PHP fixed; useful lineage, not a current chain | NVD |
| C2 | CVE-2019-11043 PHP-FPM buffer underflow | nginx `fastcgi_split_path_info` + `PATH_INFO` config; no `try_files`; specific FPM build | **no PIE bypass needed** | irr | yes | — | writes FCGI env → `PHP_VALUE` → `auto_prepend_file=php://input`; config-dependent, not default, different bug | neex/phuip-fpizdam; Orange Tsai |
| C3 | SEC26 generic PHP heap-hardening bypass (built-in `zend_array`, page fengshui, single-byte OOB) | one-byte OOB write or UAF; page-level grooming; arbitrary increment/decrement or probe | partial (probe, no separate leak) | irr | yes | W+D | fake bucket → `pDestructor` call; ASLR probe via 502/crash; "fully remote without a separate information leak" | SEC26 paper |
| C4 | Check Point PHP-7 unserialize pointer leak → read → ROP | app `unserialize()`; PHP 5/7-era objects (`php_interval_obj`, `timelib`) | leak + ROP | irr | no | W+D (app) | leaks heap and code pointers, then ROP; historical (2016) but directly relevant methodology | Check Point PDF |

---

## 3. Notes on the highest-value rows

### 3.1 L1 — the in-band `Set-Cookie` leak (best fit for W+D, no served file)

This is the only public leak I found that needs **no application code, no file read, and no served session file**. Mechanism (Wiz + 3em0):

1. Request A triggers `session.upload_progress` early (multipart FILE_START) and creates a session id. It then forces `send_cookie=1` to survive (`headers_sent` via a `max_input_vars` warning when `display_errors=On`, or the OOM-in-cookie variant when `display_errors=Off`) and ends in an OOM that skips `php_rshutdown_session_globals()`, leaving `PS(id)` dangling.
2. Request B has no file part; the pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup → php_session_initialize → php_session_reset_id` path calls `php_session_send_cookie()`, which does `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))` on the stale pointer.
3. B's multipart fields reclaim the freed id block with a forged `zend_string` header: `len=0x1000`, `data` at block+0x18. The URL-encoded cookie then contains 4 KB of adjacent heap.
4. Stage 2 places `PS(id)` at a 56-byte `HashTable` page; `ZSTR_LEN` reads `nTableSize|nInternalPointer` (=16), and the data region covers `nNextFreeElement` + `pDestructor`. `pDestructor` is `ZVAL_PTR_DTOR` (`libphp+0x613c50`), giving the libphp base. Validation: `(p - 0x613c50) & 0x1fffff == 0`.

Why it matters for us: the leak is emitted in a **response header**, so it survives `display_errors=Off`, output buffering, and application output. It only needs the session/decode state to be stale and reclaimable — exactly W+D. Default `save_path` is irrelevant.

Caveats:
- 3em0 calibrated on PHP 8.4.26 + Apache prefork/mod_php, `memory_limit=8M`, `display_errors=On`. The `display_errors=Off` OOM-in-cookie variant is published for the heap base; the libphp stage-2 variant was still being calibrated at the time of the doc ("剩余是悬空 id 块的 forge 标定").
- It needs a **fresh worker** per stage; a worker that has served prior requests moves `PS(id)`/reference offsets. The HTTP worker-rotation primitive (`A_bigfields` 3 MB live fields + OOM → next session request → `SIGABRT` → prefork forks a new child) preserves libphp/PIE mappings because children fork from the same master.
- On FPM, the startup-failure child is replaced; the same "new child inherits master mappings" property holds for PIE/libc, but the request/allocator layout must be recalibrated. No public FPM version of stage 1/2.

### 3.2 L2–L4 — post-leak ELF walk (works for `php-fpm` too)

Once you have **any** arbitrary read (calif's `uaf_read`, or a targeted stale-pointer read), you do not need symbols:

- Scan around the heap anchor in 2 MB/1 MB steps for `\x7fELF`; a bad address kills one worker, and the replacement inherits the same map. ~50–120 requests.
- Parse `PT_DYNAMIC`, walk `.dynamic` to `.dynsym`/`.dynstr`/`.gnu_hash`/`.got.plt`, run a standard GNU hash lookup. This yields `executor_globals`, `PLTGOT`, and any exported symbol even in a stripped PIE.
- Dump the GOT by abusing a large `d_val` (`DT_PLTRELSZ`) as a fake string length; cluster pointers to find libc, then `.gnu_hash`-lookup `system`. ~1.5–2 k requests as published, but each is a normal HTTP request.

For our bug, the read primitive is the hard part; the ELF/GOT machinery is generic and directly reusable against `php-fpm` (the binary is PIE, but the same ELF structures exist).

### 3.3 H1 — `zif_system` as a destructor callback (best terminal)

`zend_hash_destroy(fake_ht)` calls `ht->pDestructor(&bucket->val)`. If `pDestructor = zif_system` and `&bucket->val` is shaped as a `zend_execute_data` with `num_args=1` and arg1 a zval pointing to a fake `zend_string` containing the command, then `zif_system` executes it. This needs only:
- libphp/PHP base (for `zif_system`, offset 0x43a870 in 3em0's 8.4.26 build);
- heap base (for the fake structures);
- a controlled live string (the 167-byte payload fits in a session/field string).

No libc, no `system` GOT entry, no `disable_functions` dependency (the `zif_system` symbol remains in the binary even when `system()` is removed from the function table — calif.io and ikow both use this; calif explicitly walks the module's static `zend_function_entry[]`).

The call convention detail that makes it work: `pDestructor(&bucket->val)` gives a deterministic `rdi = &bucket->val`; the fake `execute_data` starts there, `return_value` overlaps `pDestructor`, `num_args` at `E+0x2C`, arg1 at `E+0x50`. `zif_system` may crash on the return-value write (`rsi` uncontrolled) after the command runs — acceptable for one-shot RCE.

### 3.4 H5 — ret2plt inside libphp (no libc)

3em0's `NOTES.md` §10.2 gives a complete ROP chain that uses **only libphp addresses**:
```
pDestructor = libphp + 0x21ef23   (leave; ret)
RBP = end = arData + nNumUsed*32  → pivot to payload
S+0xc8: libphp + 0x15e492  (pop rdi; ret)
S+0xd0: S + 0x120          ("id>/tmp/x")
S+0xd8: libphp + 0x15d1a3  (pop rsi; ret)
S+0xe0: S + 0x130          ("r")
S+0xe8: libphp + 0x15a029  (ret; align)
S+0xf0: libphp + 0x1504d0  (popen@plt)
S+0xf8: libphp + 0x155780  (exit@plt)
```
This is the cleanest demonstration that **ret2plt is sufficient** once a PIE base is leaked; `popen` is resolved by libphp's own PLT, so no libc base and no GOT leak. It does require a stack pivot (`leave; ret`) and a writable payload at a known heap address.

### 3.5 H7 — partial overwrite: what is actually base-free

- PIE mappings are page-aligned. A **1-byte** overwrite changes only the low 8 bits (page offset), so it is always base-independent. A **2-byte** overwrite changes bits 0–15; if the mapping is 2 MB-aligned (as 3em0 observed for `libphp.so`), bits 0–20 are zero in the base, so 2 bytes are fully determined by the target offset and the original pointer's base is preserved — **base-free within 64 KB**. With 4 KB-aligned PIE, bits 12–15 are base bits, giving 4 bits of entropy (1/16).
- A **3-byte** overwrite reaches 16 MB but overwrites bits 21–23 (for 2 MB alignment) or 12–23 (for 4 KB), so it needs base bits or brute force. In 3em0's build, `zif_system - zval_ptr_dtor = 0x1d93e0` (<16 MB), so a 3-byte partial overwrite of a live `zval_ptr_dtor` could reach `zif_system` with ~3 bits of base entropy (8 tries) plus the crash oracle. No public PHP PoC does this; mark as **inference**.
- SEC26's partial overwrite is a **heap pointer** (2 MB chunk, page-level fengshui), not a code pointer; it redirects a `zval.value` to a fake object on the same page. That is base-free for the heap, but the eventual `pDestructor` still needs a code address (leaked or probed).

### 3.6 FPM vs mod_php

- **mod_php / Apache prefork**: the OOM can occur during multipart startup, and shutdown runs unconditionally → the whole chain can be application-independent. 3em0's pure-HTTP chain is mod_php only.
- **FPM**: a startup failure makes the child exit, so the CVE-2026-109618 startup-OOM path does not survive. The validated path is CVE-2026-109619: publish state during **application execution**, hit a fatal/OOM, then consume the stale global in the next request's upload-progress decode. The advisory says this was validated on FPM; Wiz demonstrated stock WordPress/Drupal/Joomla, which supply app-level fatal/OOM paths. A bare `<?php echo "OK"; ?>` page on FPM is not enough for the producer.
- **ASLR stability**: both Apache prefork and FPM fork workers from a master, so a replacement child inherits the same PIE/libc mappings. This is what makes the crash-oracle ELF scan practical (calif.io R-2; SEC26 §5.2.2; 3em0 §5).

### 3.7 Default configuration checklist

| Setting | Default | Effect |
|---|---|---|
| `session.upload_progress.enabled` | `1` | enables the early handler (W/D) |
| `session.upload_progress.cleanup` | `1` | may delete the session file after upload; memory chain does not need it |
| `session.serialize_handler` | `php` | `|` split; mismatch with `php_serialize` enables S3 |
| `session.use_strict_mode` | `0` | attacker-chosen ids accepted (S4) |
| `session.use_cookies` / `use_only_cookies` | `1` / `1` | the FORMDATA handler still accepts POST `PHPSESSID` (the bug) |
| `session.save_path` | `""` | distro default (`/var/lib/php/sessions` or `/tmp`), not web-served, `0600` |
| `display_errors` | `Off` in production | 3em0's classic leak used `On`; OOM-in-cookie variant exists for `Off` |
| `memory_limit` / `post_max_size` | `128M` / `8M` | vendor says default input/memory limits exploitable; 3em0 calibrated at `8M` |

---

## 4. Dead ends (explicit)

1. **Served session file as a base leak (L9)** — a session file contains serialized application data, not engine pointers. Even if served, it gives no PIE/heap address. Only useful for object injection / LFI, which is POP-chain territory (other worker).
2. **`session.save_path` RCE with default config (S1)** — default path is outside the webroot, files are `0600`, and the filename is `sess_<id>` (not `.php`). Without an LFI or a served path, writing a session file is not code execution.
3. **`session.upload_progress` filename + LFI without an LFI (S2)** — the classic HackTricks chain requires an include sink. Under "no custom app code" this is out.
4. **Format-string leak (L10)** — PHP's engine and session paths use static format strings; user data is passed as `%s`, and `%n` is not reachable. No default primitive. Only an application-level `printf($_GET[...])` would qualify, violating (c).
5. **`php_session_decode` (S5)** — it is a `static zend_result php_session_decode(zend_string *data)` in `ext/session/session.c` (line 274), called by `session_decode()`/session startup. There is no userland/engine-only way to invoke it with attacker data absent `session_start()`/`session_decode()`; no public exploit targets the symbol itself.
6. **`ps_serializers[]` (S5)** — a static array of `ps_serializer` structs (`name`, `encode`, `decode`) in `.data`; overwriting its function pointers requires an arbitrary write **and** a base, so it is a target after exploitation, not an ASLR bypass. Also, `PS(serializer)` points at this static array, not at request memory, so a stale `PS(serializer)` is a handler-selection bug, not a UAF.
7. **`ret2dlresolve` (H10)** — needs PLT0 (PIE base) plus a known writable address for fake `Elf64_Rela/Sym`; once you have a PIE base, `popen@plt`/`zif_system` are simpler. Strictly dominated in this bug.
8. **GOT overwrite (H11)** — needs libc/PIE base or a partial overwrite in the same page; no public PHP session-bug PoC. Dominated by H1/H5.
9. **Heap-only shellcode (H12)** — NX; the Zend heap is non-executable. A fake object still needs a code pointer. SEC26's "no separate info leak" still uses probing or a leaked code pointer, not shellcode.
10. **`session.serialize_handler` mismatch alone (S3)** — object injection requires an app `session_start()` and a gadget class; it is a logic/POP primitive, not memory corruption. It can be an *enabler* for W, not a PIE bypass.

---

## 5. Public writeups of PHP session-deserialization RCE on PHP 7/8 with PIE

| Writeup | PHP version | PIE/ASLR? | What it shows | Limits |
|---|---|---|---|---|
| **php2shell / CVE-2026-109619** — Wiz Research, Calif, OpenAI (2026-10-21) | 8.2–8.5 (and EOL 5.4+) | yes, PIE + ASLR; Wiz combined leak + UAF on stock WordPress/Drupal/Joomla | `BG(unserialize)` stale decode slot; `PS(id)` OOB `Set-Cookie` leak; RCE below the app layer | Wiz blog is high-level; no offsets/exploit code |
| **3em0/php2shell** — pure-HTTP ASLR-on chain | 8.4.26 / 8.5 | yes; two `Set-Cookie` leaks (chunk + libphp), `zif_system` | complete leak → fake HashTable/execute_data → RCE; `display_errors=Off` heap variant; worker rotation | mod_php/Apache only; `display_errors=On` for libphp stage; build-specific offsets |
| **calif.io — "21-Year-Old Vulnerability"** | 8.5.5 / 8.5-apache | yes; full ASLR, 10/10 local, 3/3 remote | `Serializable` var_hash UAF → heap leak → `uaf_read` → ELF scan → `.gnu_hash` → GOT dump → fake `stdClass` → `system` | needs an app `unserialize()` sink; not session-specific |
| **ikow/php2shell-poc** | 8.2.34 | local; `/proc/self/mem` for addresses | session handler mismatch → `__destruct`; var_destroy UAF; `var_dump` handler → `zif_system` | RCE demo is local (`/proc/self/mem`), not a remote ASLR bypass |
| **cnpanda — PHP session deserialization** | PHP 5/7 era | no (logic/object injection) | `php`/`php_binary`/`php_serialize` formats, bug #71101, handler mismatch | no binary exploitation; older |
| **0x4148 — "the RCE I couldn't reproduce"** | 8.4.4 FPM/LiteSpeed | yes (skeptical) | failed to reproduce crash/RCE; argues a symbol delta is not an ASLR bypass and the disclosure lacks a general leak | a counterpoint, not a refutation; predates/parallel to 3em0's leak |

No public writeup I found demonstrates a **PHP 7 session-deserialization memory-corruption RCE with a PIE bypass**. PHP 7 session writeups are object-injection/logic; the PIE-level session work is PHP 8 (2026). Historical PHP 7 `unserialize()` UAF exploitation exists (Check Point 2016, Calif 2026), but through an application `unserialize()` sink, not session decode.

---

## 6. Query coverage

| Query | What was found | Status |
|---|---|---|
| PHP session deserialization RCE | cnpanda (PHP 7 logic), php2shell/Wiz/3em0/calif (PHP 8 binary) | covered |
| `php_session_decode` exploit | only CVE pages; symbol is a static C function (`session.c:274`) | dead end |
| `ps_serializers` | static serializer table in `session.c:1159`; no exploit | dead end |
| PHP session `save_path` RCE | manual + php2shell pages; requires served path/LFI | dead end for default |
| `session.upload_progress` RCE | HackTricks LFI chain; Wiz/ikow/3em0 memory bug | covered |
| PHP-FPM PIE bypass | CVE-2019-11043 (no PIE bypass needed); SEC26 ASLR probe; no session-specific FPM chain | partial |
| Partial overwrite PIE | Nightmare/CTF generic; SEC26 heap partial; PHP code-pointer partial is inference | partial |
| ret2plt | HackTricks; 3em0 `popen@plt` chain | covered |
| GOT leak | calif.io R-4; generic HackTricks | covered |
| Format-string leak | generic HackTricks; no PHP engine/session sink | dead end |
| Heap leak | 3em0, Wiz, calif.io, SEC26, CheckPoint | covered |
| ROP gadgets | 3em0 offsets (`pop rdi/rsi`, `leave;ret`, `popen@plt`) | covered |
| ret2dlresolve | HackTricks/ir0nstone; dominated | dead end/dominated |
| `zif_passthru` / `zif_system` / `execute_data` / `zend_function` | 3em0, calif.io, ikow, spyduck | covered (zif_passthru only analogous, no public PoC) |
| PHP 8 session unserialize | Wiz, advisory, calif (Serializable UAF) | covered |

---

## 7. Citations (all fetched; status noted)

**CVE / primary**
1. MITRE CVE-2026-109618 — https://cveawg.mitre.org/api/cve/CVE-2026-109618 (200)
2. MITRE CVE-2026-109619 — https://cveawg.mitre.org/api/cve/CVE-2026-109619 (200)
3. NVD CVE-2026-109618 — https://nvd.nist.gov/vuln/detail/CVE-2026-109618 (200; API 200)
4. PHP GHSA "RCE via OOM corruption" — https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w (200)
5. PHP GHSA "RCE via stale global state" — https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp (200)
6. Wiz Research — https://www.wiz.io/blog/php2shell-php-rce (200)
7. Datadog Security Labs — https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/ (200)
8. Sansec — https://sansec.io/research/php2shell (200)
9. Qi Deng substack — https://qideng.substack.com/p/php2shell-dissecting-phps-critical (200; paywalled after Chain E)
10. ikow/php2shell-poc — https://github.com/ikow/php2shell-poc (200); `docs/ANALYSIS.md` (200); `exploit/chain_b_uaf_rce.php` (200)
11. 3em0/php2shell — https://github.com/3em0/php2shell (200); `docs/ASLR_PURE_HTTP.md`, `docs/HTTP_HEAP_LEAK.md`, `docs/DISPLAY_ERRORS_OFF.md`, `docs/NOTES.md`, `exploit.py` (all 200)
12. calif.io — https://calif.io/research/php-uaf (200)
13. 0x4148 counterpoint — https://0x4148.com/posts/php2shell-php-core-rce-cve-2026-109618-109619/ (200)
14. scallydima/php2shell-poc — https://github.com/scallydima/php2shell-poc (200)
15. FranklinF25/php2shell — https://github.com/FranklinF25/php2shell (200)

**Session internals / logic**
16. PHP manual session config — https://www.php.net/manual/en/session.configuration.php (200)
17. PHP manual upload progress — https://www.php.net/manual/en/session.upload-progress.php (200)
18. php-src 8.4.26 `ext/session/session.c` — https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c (200)
19. php-src 8.4.26 `ext/standard/var_unserializer.re` — https://github.com/php/php-src/blob/php-8.4.26/ext/standard/var_unserializer.re (200)
20. cnpanda session deserialization — https://www.cnpanda.net/en/sec/580.html (200)
21. HackTricks LFI2RCE upload progress — https://hacktricks.wiki/en/pentesting-web/file-inclusion/via-php_session_upload_progress.html (200)

**Binary techniques**
22. Check Point "Exploiting PHP-7 unserialize" (2016) — https://blog.checkpoint.com/wp-content/uploads/2016/08/Exploiting-PHP-7-unserialize-Report-160829.pdf (200; PDF 22 pp., text extracted)
23. "Melting the Flesh of PHP's Memory Hardening" (USENIX Sec '26) — https://www.cs.ucr.edu/~zhiyunq/pub/sec26_php_exploit.pdf (200; PDF, text extracted)
24. Nightmare partial overwrite — https://guyinatuxedo.github.io/15-partial_overwrite/index.html (200)
25. HackTricks PIE — https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/pie/index.html (200)
26. HackTricks ret2plt — https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/aslr/ret2plt.html (200)
27. HackTricks ret2dlresolve — https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2dlresolve.html (200)
28. HackTricks format strings — https://hacktricks.wiki/en/binary-exploitation/format-strings/index.html (200)
29. HackTricks libc leak — https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address/index.html (200)
30. spyduck "Hypertext Preprocessor" (zif_system via module table) — https://spyduck007.github.io/ctf/write-ups/hypertext-preprocessor/ (200)
31. x-c3ll PHP UAF — https://x-c3ll.github.io/posts/UAF-PHP-disable_functions/ (200)
32. neex/phuip-fpizdam (CVE-2019-11043) — https://github.com/neex/phuip-fpizdam (200)
33. NVD CVE-2015-0231 / CVE-2015-0273 / CVE-2016-7124 / CVE-2019-11043 — NVD API (200)

Fetch notes:
- Direct `html.duckduckgo.com` returned a 202/captcha ("anomaly"); searches were executed through `https://r.jina.ai/https://html.duckduckgo.com/html/?q=...`, which returned DDG results. Bing HTML returned generic/degraded results; Mojeek and searx.be returned captchas; grep.app returned 429; searchcode API 404. None of those are cited.
- `github.com/junaire/CVE-2026-109618-exploit` tree API returned 403; its README fetched (200) and describes only the object-injection chain, so it is not cited as binary evidence.
- All URLs in §7 were fetched with HTTP 200 and the cited content was checked; the UCR PDF was additionally validated with `pdftotext` (1,127 lines).

---

## 8. Limitations / open questions

1. **No public full FPM + PIE chain.** The vendor's "validated against FPM" is a statement, not a published exploit. The FPM producer (app-level fatal/OOM) and the exact allocator layout will differ from 3em0's mod_php lab.
2. **Offsets are build-specific.** `zif_system` (0x43a870), `ZVAL_PTR_DTOR` (0x613c50), `popen@plt` (0x1504d0), `leave;ret` (0x21ef23) are for 3em0's PHP 8.4.26 / Debian 12 libphp. The techniques are portable; the constants are not.
3. **`display_errors` and `memory_limit`.** The cleanest libphp leak was calibrated with `display_errors=On` and `memory_limit=8M`; production defaults differ. The OOM-in-cookie variant covers the heap leak with `display_errors=Off`; the libphp stage needs recalibration. The vendor says default limits are exploitable, but I did not find a public default-limit 3em0-style run.
4. **Partial code-pointer overwrite (H7) is inference**, not a public PHP PoC. The distance `zif_system - zval_ptr_dtor = 0x1d93e0` and the 2 MB mapping alignment make it plausible; the base bits/brute-force math is in §3.5.
5. **`zif_passthru`** is not separately documented; it has the same `(zend_execute_data*, zval*)` handler ABI as `zif_system`, so it should be an equivalent terminal, but I found no public PoC. Do not claim it as verified.
6. **0x4148's failed reproduction** is a real counterpoint on reliability. It does not refute the leak (it explicitly says the disclosure lacked a general leak); 3em0 and Wiz supply one. Treat success rates as lab-specific.
