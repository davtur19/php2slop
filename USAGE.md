# USAGE

Install, layout and run one-liners: see `README.md`. This file is the lane matrix, prerequisites and failure diagnosis.

## Lane matrix

| lane | target | producer | consumer | expected receipt | status |
|---|---|---|---|---|---|
| modphp machinery | libphp.so PHP 8.5.10 NTS, httpd prefork | `producer_modphp` filename length N ladder | tiny multipart plus GET arms | HTTP 200, 149 B fatal transcript, worker survives | dry wired, live gated |
| modphp app unserialize | lab unserialize endpoint | `producer_unser` master shape class payload | tiny multipart plus GET arms | HTTP 200, fatal transcript at the class tried alloc, worker survives | dry wired, live gated by `--unser-url` |
| fpm wiki and wp | php-fpm static pool | post startup app level fatal inside the unserialize family | small arm under the pool memory_limit | worker survives an app fatal, machinery fatal exits 70 | prerequisites table below |

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

## Fingerprint and profile pack

| item | behavior | numbers |
|---|---|---|
| `--step recon` | GET the path, record status, server, connection, content type and body bytes | exit 0 alive, exit 2 not alive |
| disclosure gate | 14 B frozen profile disclosure at LEAK_OFFSET inside a main chunk | LEAK_OFFSET 0x57030, main chunk 0x200000 |
| `--step leak` | dry calibration plan, request shapes plus algorithm, no transport | 10 exchanges per stage, 3 stable triples, 4096 B Set-Cookie cap, 98 encoded pointers |
| address profile | `addresses/apache_libphp.json`, per binary offsets and lane | 40492240 B, md5 `92f76e84a77bf8b56c45c3868fa29a6c`, p_align 0x1000 |
| five resolved symbols | `zif_system` 0x40cc80, `zif_passthru` 0x40cc90, `zend_call_function` 0x540500, `zend_llist_remove_tail` 0x5d39a0, `zval_ptr_dtor` 0x5f0980 | deltas 0xb0480 and 0x1c6d10 |
| engine symbols | `php_url_encode` 0x460d70, `ps_globals` 0xa3b020, `basic_globals` 0xa3bdc0, `php_apache_sapi_ub_write` 0x5f7ee0, `zend_rc_dtor_func` 0x96f760 | PS(id) offset 16, PS(http_session_vars) offset 360 |
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
