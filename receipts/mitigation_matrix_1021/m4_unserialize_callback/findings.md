# M4 — `php_admin_value[unserialize_callback_func]=""` vs the attacker autoload lever

Date: 2026-10-21 (22:15–22:18 CEST). Work dir: `/tmp/opencode/m4_test_1021/`
(private, loopback only, ports 29030–29036). The INI matrix (`/tmp/opencode/mitigation_1021/`),
the nginx edge run (`/tmp/opencode/nginx_mitigation_1021/`) and all other lab dirs were read
only, never written. No git repo was touched during the run.

Question: **does pinning `unserialize_callback_func` to the empty string (admin scope) stop an
attacker from making PHP autoload a class file during `unserialize()` / session decode**, and
where does that stop?

Short answer (measured): **yes for the callback lever, everywhere the callback would fire —
script-level `unserialize()`, request-startup upload-progress decode, and `session.auto_start`
decode — but only because `php_admin_value` makes the empty default non-overridable. The value
itself is not the protection: the PHP default is already `""` and an unpinned pool accepts
`.user.ini` / `ini_set()` changes.** The pin does **not** block already-defined class gadgets,
and it does **not** touch the multipart OOM.

---

## 1. Stack

| component | value |
|---|---|
| PHP | `/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm` — `PHP 8.5.10 (fpm-fcgi)`, ASAN build (`libasan.so.8`), sha256 `27f32ef946b9ca1f24a0c6f9b6c26528abe8cf9e1ff666e8592c39fe5b5d7fc1` (full value in `results/binary_env.txt`) |
| process model | one private master, 7 pools (`l0`–`l6`), `pm=static`, `pm.max_children=1`, `pm.max_requests=0`, so one worker per pool for the whole run |
| transport | direct FastCGI on loopback (`bin/fcgi.py`, no nginx), `DOCUMENT_ROOT` set per lane so `.user.ini` is active |
| ini | started with `-n` plus pool `php_admin_value` only; no host php.ini |
| user | `davide` (FPM not root; `user`/`group` pool directives are ignored, as logged) |

Pools (`conf/fpm.conf`):

| lane | port | docroot | relevant pool config |
|---:|---|---|---|
| l0 | 29030 | `www/base` (no `.user.ini`) | defaults; `memory_limit=128M` |
| l1 | 29031 | `www/plain` (`.user.ini`: callback + include_path) | no pin |
| l2 | 29032 | `www/plain` | `php_admin_value[unserialize_callback_func] =` (empty) |
| l3 | 29033 | `www/plain` | same + `php_admin_value[include_path] = .` |
| l4 | 29034 | `www/auto` (`.user.ini`: `session.auto_start=1`, callback, include_path) | no pin |
| l5 | 29035 | `www/auto` | `php_admin_value[unserialize_callback_func] =` (empty) |
| l6 | 29036 | `www/plain` | callback pinned empty, `memory_limit=8M` (OOM orthogonality check) |

Docroot-planted `.user.ini` (`www/plain/.user.ini`):

```
unserialize_callback_func=spl_autoload
include_path=/tmp/opencode/m4_test_1021/autoload_plain
```

`www/auto/.user.ini` is the same plus `session.auto_start=1`. The class file
(`autoload_plain/d2.php`, `autoload_auto/d2.php`) is benign:

```php
<?php
class D2 {
    public function __destruct() {
        file_put_contents(__DIR__ . '/marker.txt', 'hit ' . date('c') . "\n", FILE_APPEND);
    }
}
```

No `shell_exec`, no network, no writing outside the work dir.

## 2. Lock semantics (test 1)

`results/effective_ini.txt` (from `probe.php`; `access` is PHP's reported access level for the
entry: 7 = `PHP_INI_ALL`, 4 = `PHP_INI_SYSTEM`):

| lane | `unserialize_callback_func` | access | `ini_set('unserialize_callback_func','strlen')` | after |
|---|---|---|---|---|
| l0 no `.user.ini`, no pin | `''` | 7 | `''` (succeeds) | `strlen` |
| l1 `.user.ini`, no pin | `'spl_autoload'` | 7 | `'spl_autoload'` (succeeds) | `strlen` |
| l2 pool pin `""` | `''` | **4** | **`false`** | `''` |
| l3 pin + include_path pin | `''`; `include_path='.'` | 4; 4 | **`false`** | `''` |
| l4 auto_start, no pin | `'spl_autoload'` | 7 | `'spl_autoload'` (succeeds) | `strlen` |
| l5 auto_start + pin | `''` | **4** | **`false`** | `''` |

Findings:

- The **default is already empty** (l0). Empty is safe against the autoload lever by itself.
- **Unpinned, the attacker controls it.** A writable docroot's `.user.ini` set it to
  `spl_autoload` and `include_path` to the attacker dir (l1/l4); `ini_set()` also succeeded.
  `unserialize_callback_func` is `PHP_INI_ALL` (access 7), so `.user.ini` (PERDIR) applies.
- **Pinned, it cannot be overridden.** `php_admin_value[...] = ` (empty value) yields
  `ini_get() === ''`, `access=4` and `ini_set() === false`. The `.user.ini` line is still in
  the docroot in l2/l3/l5 and is silently ignored; `include_path` from `.user.ini` still
  applies unless separately pinned (l2 shows `include_path` from `.user.ini`; l3 pins it).
- The extra `include_path` pin is **not necessary** for this lever when the callback is empty
  (nothing calls the autoloader), but it closes the second half of the same lever
  (autoloader + search path) and is reported as defense in depth.

`php_admin_value` is non-overridable at the per-dir/user stages — this is exactly the intended
admin lock; no special "empty value" semantics are involved (an empty admin value behaves like
any other admin value).

## 3. Script-level `unserialize()` (tests 2–3)

`d.php` calls `unserialize('O:2:"D2":0:{}')`; D2 is not defined in the script. The driver
deletes the marker before each request and reads it after the response.

| lane | pin | result class | `class D2` defined after | marker |
|---|---|---|---|---|
| l0 | none (no `.user.ini`) | `__PHP_Incomplete_Class` | false | **no** |
| l1 | none (`.user.ini` callback) | `D2` | true | **yes** |
| l2 | callback `""` | `__PHP_Incomplete_Class` | false | **no** |
| l3 | callback `""` + include_path `.` | `__PHP_Incomplete_Class` | false | **no** |

With the pin, PHP produces `__PHP_Incomplete_Class` and **no warning is logged** in this build
(the `php_err_l*.log` files do not exist); the "callback set but did not define the class"
warning path is not reached because the callback is never called when the value is empty.
The positive counterpart is l1: `spl_autoload` loads `d2.php` off `include_path`, the object is
instantiated, and its destructor writes the marker.

Already-defined class control (`dpre.php` defines `class D3` itself, then unserializes
`O:2:"D3":0:{}`): marker **yes in every lane, including l2/l3**. A gadget class that the
application (bootstrap, preload, an earlier include, or an app-level unserialize call) has
already defined is instantiated regardless of the callback pin. This is the main limitation of
M4 and is measured, not inferred.

## 4. Pre-script decode (test 4) — measured, not inferred

Two request-startup paths were exercised on 8.5.10. In both, the script body contains **no**
`session_start()` and no `unserialize()`:

1. **upload-progress startup update.** Session file planted as
   `sess_m4upN = upload_progress_MMM|O:2:"D2":0:{}`; request is a 193-byte multipart POST
   with `PHP_SESSION_UPLOAD_PROGRESS=MMM` + one 8-byte file part, so
   `php_session_rfc1867_update()` decodes the session and replaces the progress key during
   request startup (`main/SAPI.c` `sapi_read_post_data` → `main/rfc1867.c`). The script is
   `index.php`: `SCRIPT_RAN`, `class_exists('D2', false)`, `session_status()`.

   | lane | pin | class D2 at script entry | marker |
   |---|---|---|---|
   | l0 | none (default `""`) | false | **no** |
   | l1 | none (`.user.ini`) | **true** | **yes** |
   | l2 | callback `""` | false | **no** |
   | l3 | callback `""` + include_path `.` | false | **no** |

   l1 output: `SCRIPT_RAN / class_D2_at_script=true / session_status=1`. The class was already
   loaded when the script started and the session was already active although the script never
   called `session_start()`. That is the upload-progress decode path; no script-level
   `unserialize()` is involved. l2's transcript is identical except
   `class_D2_at_script=false`.

2. **`session.auto_start=1` (RINIT decode).** Session file planted as
   `m4key|O:2:"D2":0:{}`; plain GET to `index.php` in `www/auto` (the only place `auto_start`
   is set). The script prints `session_keys=m4key`, `SCRIPT_RAN`, `class_D2_at_script`.

   | lane | pin | `session_keys` | class D2 at script entry | marker |
   |---|---|---|---|---|
   | l4 | none (`.user.ini` callback) | `m4key` | **true** | **yes** |
   | l5 | callback `""` | `m4key` | false | **no** |

So the pre-script equivalence is not an inference for these two mechanisms: the pin changes
observable class loading and destructor execution at request startup on the vulnerable 8.5.10
build. (For completeness: php-src 8.5.12 adds `in_rfc1867_update` + `incomplete_classes_only`
so the upload-progress decode itself no longer autoloads; that is a source-level observation
from the hash-verified 8.5.12 tree, **not runtime-measured here** and not required for M4.)

## 5. Orthogonality: the pin does not stop the OOM (l6)

The same 4,983,495 B stock arm (20 parts, `F`×262144 filenames, progress field, PHPSESSID
cookie) was sent to pool l6 (`memory_limit=8M`, callback pinned empty):

```
Fatal error: Allowed memory size of 8388608 bytes exhausted
(tried to allocate 1052672 bytes) in Unknown on line 0
```

HTTP 200, 139-byte body (`results/m4_oom_arm.json`), no access-log line (pre-RINIT), FPM log:
`child 1066102 exited with code 70 after 10.335758 seconds from start`. M4 is orthogonal to
CVE-2026-109618/109619: the multipart allocation happens before any class/callback logic.

## 6. Verdict

M4 is a **real but narrow hardening**:

- **Blocks**: attacker-controlled autoload during `unserialize()` and during request-startup
  session decode (upload-progress update and `auto_start`), because the admin pin freezes the
  callback at empty and `ini_set`/`.user.ini` cannot restore it.
- **Does not block**: gadgets whose class is already defined by the application; app-level
  `unserialize()` after startup that instantiates an internal/known class; the multipart OOM
  itself; other SAPIs/pools where the admin pin is not set; non-FPM deployments.
- **Value of the pin is the lock, not the value**: the default is already `""`; l0 vs l1 shows
  an unpinned pool is attacker-configurable through a writable docroot.
- **Deployment form**: `php_admin_value[unserialize_callback_func] = ` in every pool
  (empty), optionally `php_admin_value[include_path] = .`. It must be `php_admin_value`
  (or `php_value` at a scope the user cannot override); `php_value`/`.user.ini` alone is not a
  control.

## 7. Reproduction

```bash
cd /tmp/opencode/m4_test_1021
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 USE_ZEND_ALLOC=1 \
  /home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm -n -y conf/fpm.conf -D
python3 bin/run_m4.py            # 22 request rows -> results/m4_results.jsonl
python3 bin/make_summary.py      # results/m4_summary.md
python3 bin/run_oom_arm.py        # l6: stock arm on the pinned pool -> exit 70
kill $(cat run/fpm.pid)
```

## 8. Artifacts

| path | contents |
|---|---|
| `conf/fpm.conf` | exact 7-pool master config, including the two empty admin pins |
| `www/{base,plain,auto}/` | probe, `d.php`, `dpre.php`, `index.php`, and the two `.user.ini` files |
| `autoload_plain/`, `autoload_auto/` | benign `D2` class files used as the autoload target |
| `bin/fcgi.py`, `bin/run_m4.py`, `bin/make_summary.py` | FastCGI client and driver |
| `results/m4_results.jsonl` | 22 rows: status, body, marker before/after, session before/after, access pid |
| `results/m4_summary.md`, `results/effective_ini.txt` | rendered table + raw probe dumps |
| `results/m4_oom_arm.json`, `results/transcripts/l6_oom_arm.http` | l6 orthogonality arm |
| `results/transcripts/<lane>_<step>.http` | raw FastCGI STDOUT per request |
| `results/binary_env.txt` | binary sha256, `php-fpm -v`, ASAN link |
| `logs/fpm-master.log`, `logs/l*.access.log`, `logs/php_err_l6.log` | process and request evidence |

## 9. Services / final state

Started for this work: one private `php-fpm` master **1066095** with workers
l0 1066096, l1 1066097, l2 1066098, l3 1066099, l4 1066100, l5 1066101, l6 1066102
(→ exit 70 → 1066166). All pool listeners are 127.0.0.1:29030–29036. The master and all
workers were stopped after the run (`kill $(cat run/fpm.pid)`); no listener remains on
29030–29036. No other lab service was started, stopped or modified.
