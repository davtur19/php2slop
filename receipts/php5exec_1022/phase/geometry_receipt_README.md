# PHP 5.x geometry for the G2/G6 chains (5.6.40 and 5.4.45, non-PIE FPM)

- Receipt: `php5geo_20261022_0045`
- Date: 2026-10-22
- Scope: offline build, DWARF, disassembly and source analysis. No service was started and no live exploit was run.
- Question: can the PHP 8.5 G2 (stale `BG(unserialize)` dtor-slot write) and G6 (session decode slot -> `zif_system`) shapes be reused on PHP 5.x?

## Answer

The 5.x **stale chain exists**: `php_hash_environment()` runs before `zend_activate_modules()`, so the rfc1867 session decode in the trigger request consumes the previous request's stale `BG(unserialize)` (`var_hash=P`, `level=1`) before `PHP_RINIT_FUNCTION(basic)` memsets it. This is the same pre-RINIT window as 8.x, and it is single-shot per plant. RINIT is not a blocker.

The 5.x **G2 address geometry transfers** with adjusted constants: the dtor slot is `A = B0 + 8*K`, where `B0 = ((php_unserialize_data*)P)->last_dtor` and `K = *(int64_t*)(B0 + 0x2000)` (`var_entries.used_slots`). `data[0]` is at `B0+0`, each entry is 8 bytes, and the only special-cased index is exactly `K == 1024` (which allocates a fresh block); `K < 0` and `K > 1024` are both accepted.

The 5.x **G2 value does not transfer**. The store is

```
mov (%r12),%rcx
mov %rcx,(%rax,%rdx,8)
```

an 8-byte store of `*rval`, where `rval = &current` and `current` is a separately allocated heap zval (`ALLOC_INIT_ZVAL`). The slot therefore receives a **pointer to a zval**, never the parsed typed zval contents. PHP 8.5 is structurally different: `current = var_tmp_var(&var_hash)` returns the typed 16-byte slot itself, and `php_var_unserialize(current, ...)` writes the parsed zval directly into it, so an `IS_LONG` with an arbitrary 64-bit value (e.g. libc `system`) lands in the slot. That is the G2 value blocker.

The 5.x **G6 does not transfer at all**. The 5.x internal-function ABI is

```c
#define INTERNAL_FUNCTION_PARAMETERS int ht, zval *return_value, zval **return_value_ptr, \
                                     zval *this_ptr, int return_value_used TSRMLS_DC
```

so the decode call `decode(val, vallen)` enters `zif_system` with `ht = (int)val` and `return_value = (zval*)vallen`. `php_exec_ex` passes `num_args = ht` to `zend_parse_parameters`, which rejects the count (`num_args < 1 || num_args > 2`), and the failure path executes `movq $0,(%rbx); movb $3,0x14(%rbx)` with `rbx = return_value = (zval*)vallen`. That writes to the address equal to the session data length, an unmapped low address, and SIGSEGVs **before any exec**. `zif_passthru` (mode 3) is identical. There is no `execute_data` parameter and no attacker-controlled VM frame; the argument zvals come from the real VM stack (`zend_vm_stack_top()-1`).

**Verdict: the 5.x chain can reuse the stale-P primitive but neither the 8.x G2 value write nor the 8.x G6 decode-call shape. Exact blockers in section 7.**

## 1. Build and provenance

Both trees were configured with:

```
CFLAGS='-g -O1 -fno-omit-frame-pointer -fno-pie -fcommon -fgnu89-inline \
  -DHAVE_POSIX_READDIR_R=1 \
  -Wno-error=implicit-function-declaration -Wno-error=int-conversion \
  -Wno-error=incompatible-pointer-types -Wno-error=return-mismatch' \
LDFLAGS='-no-pie' \
./configure --disable-all --enable-fpm --enable-session --without-pear --disable-cgi
```

and built with `make sapi/fpm/php-fpm` (rc=0 for both). The full `make` returns rc=2 on an unrelated link target in both trees; it is not the FPM target.

`-DHAVE_POSIX_READDIR_R=1` is required because configure misdetects glibc's 3-argument `readdir_r` as legacy `HAVE_OLD_READDIR_R`, and the build then fails on the legacy 2-argument call.

| Binary | Size | MD5 | SHA-256 |
|---|---:|---|---|
| `build/php-5.6.40/sapi/fpm/php-fpm` | 14,765,720 | `4e3442202208f8555f8b0cfeb06c0dc4` | `b9261e1cb91672c6a297bde724db3cd26833d329b832bc4bcbe0183af3703723` |
| `build/php-5.4.45/sapi/fpm/php-fpm` | 14,279,328 | `d42eb89c746be77149edc42980b6441b` | `60e225762c90d24912b70b3ef5105db848f57b663182bc8eaee09f567224abaf` |

Both are ELF64 `ET_EXEC` (non-PIE), x86-64, with DWARF debug info. Source tarballs:

| Source | MD5 | SHA-256 |
|---|---|---|
| `src/php56.tar.gz` | `0f0e1372510dbcda1cb671c72d17c009` | `56fb9878d12fdd921f6a0897e919f4e980d930160e154cbde2cc6d9206a27cac` |
| `src/php-5.4.45.tar.gz` | `ba580e774ed1ab256f22d1fa69a59311` | `25bc4723955f4e352935258002af14a14a9810b491a19400d76fcdfa9d04b28f` |

The 5.4.45 source is the `.tar.gz`; the `.tar.xz` URL served an HTML error page.

## 2. Symbols and offsets

### 2.1 PHP 5.6.40

| Symbol | Address |
|---|---|
| `zif_system` | `0x4f195f` |
| `zif_passthru` | `0x4f1970` |
| `php_exec` | `0x4f14ec` |
| `php_exec_ex` | `0x4f17ca` |
| `php_session_decode` | `0x4ace04` |
| `php_session_start` | `0x4b260e` |
| `ps_serializers` | `0x816dc0` |
| `ps_globals` | `0x82e4e0` |
| `basic_globals` | `0x82ef40` |
| `var_push_dtor` | `0x531840` |
| `var_push_dtor_no_addref` | `0x5318e7` |
| `php_var_unserialize` | `0x531b18` |
| `ps_srlzr_encode_php_serialize` | `0x4ac885` |
| `ps_srlzr_decode_php_serialize` | `0x4ac9ab` |
| `ps_srlzr_encode_php` | `0x4affbd` |
| `ps_srlzr_decode_php` | `0x4af726` |
| `ps_srlzr_encode_php_binary` | `0x4afaff` |
| `ps_srlzr_decode_php_binary` | `0x4af399` |

### 2.2 PHP 5.4.45

| Symbol | Address |
|---|---|
| `zif_system` | `0x4edbdb` |
| `zif_passthru` | `0x4edbec` |
| `php_exec` | `0x4ed775` |
| `php_exec_ex` | `0x4eda46` |
| `php_session_decode` | `0x4aad85` |
| `php_session_start` | `0x4af7e2` |
| `ps_serializers` | `0x79eda0` |
| `ps_globals` | `0x7b5f60` |
| `basic_globals` | `0x7b6920` |
| `var_push_dtor` | `0x52bdba` |
| `var_push_dtor_no_addref` | `0x52be5a` |
| `php_var_unserialize` | `0x52bfb2` |
| `ps_srlzr_encode_php` | `0x4aeb05` |
| `ps_srlzr_decode_php` | `0x4ae3ed` |
| `ps_srlzr_encode_php_binary` | `0x4ae6fa` |
| `ps_srlzr_decode_php_binary` | `0x4ae189` |

## 3. Serializer table and dispatch

`struct ps_serializer_struct` is 24 bytes: `name` at +0, `encode` at +8, `decode` at +0x10. Entries are consecutive, terminated by a zeroed entry.

### 3.1 PHP 5.6.40: `php_serialize`, `php`, `php_binary`

| Index | Name | `name` ptr | `encode` | `decode` |
|---:|---|---|---|---|
| 0 | `php_serialize` | `0x65f31e` | `0x4ac885` | `0x4ac9ab` |
| 1 | `php` | `0x65f56c` | `0x4affbd` | `0x4af726` |
| 2 | `php_binary` | `0x65f32c` | `0x4afaff` | `0x4af399` |
| 3 | sentinel | `0x0` | - | - |

The `php_binary` decode slot is `ps_serializers + 2*24 + 0x10 = 0x816e00`. The gdb dump shows the table and the sentinel:

```
0x816dc0 <ps_serializers>:      0x000000000065f31e  0x00000000004ac885
0x816dd0 <ps_serializers+16>:   0x00000000004ac9ab  0x000000000065f56c
0x816de0 <ps_serializers+32>:   0x00000000004affbd  0x00000000004af726
0x816df0 <ps_serializers+48>:   0x000000000065f32c  0x00000000004afaff
0x816e00 <ps_serializers+64>:   0x00000000004af399  0x0000000000000000
```

### 3.2 PHP 5.4.45: `php`, `php_binary` (no `php_serialize`)

| Index | Name | `name` ptr | `encode` | `decode` |
|---:|---|---|---|---|
| 0 | `php` | `0x655c7c` | `0x4aeb05` | `0x4ae3ed` |
| 1 | `php_binary` | `0x655a70` | `0x4ae6fa` | `0x4ae189` |
| 2 | sentinel | `0x0` | - | - |

The `php_binary` decode slot is `0x79eda0 + 1*24 + 0x10 = 0x79edc8`. 5.4 has no `php_serialize`; the `php_binary` index shifts from 2 to 1, which changes the G2/G6 target arithmetic between the two versions.

```
0x79eda0 <ps_serializers>:      0x0000000000655c7c  0x00000000004aeb05
0x79edb0 <ps_serializers+16>:   0x00000000004ae3ed  0x0000000000655a70
0x79edc0 <ps_serializers+32>:   0x00000000004ae6fa  0x00000000004ae189
0x79edd0 <ps_serializers+48>:   0x0000000000000000  0x0000000000000000
```

### 3.3 `PS(serializer)` and the decode call site

`PS(serializer)` is the cached `const struct ps_serializer_struct *` in `php_ps_globals`:

| Version | `ps_globals` | Offset | Address |
|---|---|---:|---|
| 5.6.40 | `0x82e4e0` | `0xe0` | `0x82e5c0` |
| 5.4.45 | `0x7b5f60` | `0xd8` | `0x7b6038` |

`php_session_decode(const char *val, int vallen)` dispatches through `ps_serializers[...].decode`:

PHP 5.6.40:

```
4ace0d: mov 0x3817ac(%rip),%rax   # 82e5c0 <ps_globals+0xe0>
4ace14: test %rax,%rax
4ace17: je   4ace30
4ace19: call *0x10(%rax)
```

PHP 5.4.45:

```
4aad8e: mov 0x30b2a3(%rip),%rax   # 7b6038 <ps_globals+0xd8>
4aad95: test %rax,%rax
4aad98: je   4aadb1
4aad9a: call *0x10(%rax)
```

At the call, `rdi = val` (the session data pointer) and `rsi = vallen` (the session data length, int). This is the argument pair that the G6 analysis in section 6 uses.

## 4. Stale `BG(unserialize)` chain

### 4.1 Layout

`BG(unserialize)` is at `basic_globals + 0xde8` (3560) in both versions:

| Version | `basic_globals` | `BG(unserialize)` | `var_hash` | `level` | Size |
|---|---|---|---|---|---|
| 5.6.40 | `0x82ef40` | `0x82fd28` | `0x82fd28` | `0x82fd30` | `0x10` |
| 5.4.45 | `0x7b6920` | `0x7b7708` | `0x7b7708` | `0x7b7710` | `0x10` |

`struct php_unserialize_data` is 32 bytes: `first` +0, `last` +8, `first_dtor` +0x10, `last_dtor` +0x18. `var_entries` is 0x2010 bytes: `zval *data[1024]` at +0, `long used_slots` at +0x2000, `void *next` at +0x2008.

`PHP_VAR_UNSERIALIZE_INIT` in 5.x reuses the global when `BG(unserialize).level != 0`:

```c
if (BG(serialize_lock) || !BG(unserialize).level) {
    var_hash_ptr = ecalloc(1, sizeof(struct php_unserialize_data));
    if (!BG(serialize_lock)) {
        BG(unserialize).var_hash = (void *)var_hash_ptr;
        BG(unserialize).level = 1;
    }
} else {
    var_hash_ptr = (php_unserialize_data_t)BG(unserialize).var_hash;
    ++BG(unserialize).level;
}
```

`PHP_VAR_UNSERIALIZE_DESTROY` only frees at level 0. A `zend_bailout` (e.g. an `E_USER_ERROR` from the user error handler during `unserialize()`) skips the destroy, leaving `var_hash=P` and `level=1` for the next request.

### 4.2 Request-startup order

`php_hash_environment()` runs before `zend_activate_modules()`:

- 5.6.40: `main/main.c:1685` `php_hash_environment(TSRMLS_C);` then `:1686` `zend_activate_modules(TSRMLS_C);`
- 8.5.10: `main/main.c:1942` `php_hash_environment();` then `:1943` `zend_activate_modules();`
- 5.4.45: same order.

The rfc1867 session decode runs inside `php_hash_environment()`, before `PHP_RINIT_FUNCTION(basic)` memsets the global:

- 5.6.40: RINIT starts at `ext/standard/basic_functions.c:3714`; `memset(&BG(unserialize), 0, ...)` at `:3720`.
- 5.4.45: RINIT starts at `:3685`; memset at `:3691`.
- 8.5.10: RINIT starts at `:387`; memset at `:393`.

Therefore the first decode in the trigger request sees the stale `level=1` and reuses `P`. `php_session_rfc1867_update` then calls `php_session_initialize` and `php_session_flush` on every callback update:

- 5.6.40: initialize at `ext/session/session.c:2645`, flush at `:2651`.
- 5.4.45: initialize at `:2448`, flush at `:2454`.

Each re-initialization decodes again, still before RINIT, so the same-request double-decode shape is preserved. After `php_hash_environment()` returns, the RINIT memset resets `BG(unserialize)`, making the primitive **single-shot per plant**.

## 5. G2: dtor-slot write geometry

### 5.1 Formula

With `P = BG(unserialize).var_hash` (stale, non-NULL, `level != 0`):

- `B0 = *(void**)(P + 0x18)` = `((php_unserialize_data*)P)->last_dtor`
- `K = *(int64_t*)(B0 + 0x2000)` = `var_entries.used_slots`
- slot address `A = B0 + 8*K` (`data[K]`, with `data[0]` at `B0+0`)
- after the store, `used_slots = K + 1`

The bound check is equality, not a range:

```
cmpq $0x400,0x2000(%rax)
je   <allocate new block>
```

`K == 1024` allocates a fresh `var_entries` via `_emalloc(0x2010)` and resets `used_slots=0`, `next=0`. Every other K, including negative K (before `data`) and K > 1024 (past `data`), is used directly as the index. The target must of course be mapped.

### 5.2 Store instructions

PHP 5.6.40, `var_push_dtor_no_addref` at `0x5318e7`:

```
53190e: cmpq $0x400,0x2000(%rax)
531919: je   53193a                 ; _emalloc(0x2010), reset
53191b: mov  0x2000(%rax),%rdx       ; K
531922: lea  0x1(%rdx),%rcx
531926: mov  %rcx,0x2000(%rax)       ; used_slots = K+1
53192d: mov  (%r12),%rcx             ; *rval = current (zval*)
531931: mov  %rcx,(%rax,%rdx,8)      ; *(B0 + 8*K) = current
```

PHP 5.6.40, `var_push_dtor` at `0x531840` (addref variant):

```
531867: cmpq $0x400,0x2000(%rax)
531874: mov  0x2000(%rax),%rdx
53187b: lea  0x1(%rdx),%rcx
53187f: mov  %rcx,0x2000(%rax)
531886: lea  (%rax,%rdx,8),%rbx
53188a: mov  (%r12),%rax
53188e: addl $0x1,0x10(%rax)         ; Z_ADDREF_PP: refcount at zval+0x10
531892: mov  (%r12),%rax
531896: mov  %rax,(%rbx)             ; same 8-byte zval* store
```

PHP 5.4.45, `var_push_dtor_no_addref` at `0x52be5a`:

```
52be81: cmpq $0x400,0x2000(%rax)
52be8c: je   52bead
52be8e: mov  0x2000(%rax),%rdx
52be95: lea  0x1(%rdx),%rcx
52be99: mov  %rcx,0x2000(%rax)
52bea0: mov  (%r12),%rcx
52bea4: mov  %rcx,(%rax,%rdx,8)
```

PHP 5.4.45, `var_push_dtor` at `0x52bdba`:

```
52bde1: cmpq $0x400,0x2000(%rax)
52bdee: mov  (%r12),%rdx
52bdf2: addl $0x1,0x10(%rdx)
52bdf6: mov  0x2000(%rax),%rdx
52bdfd: lea  0x1(%rdx),%rcx
52be01: mov  %rcx,0x2000(%rax)
52be08: mov  (%r12),%rcx
52be0c: mov  %rcx,(%rax,%rdx,8)
```

In both versions the stored value is an 8-byte `zval*`; `var_push_dtor` only adds the refcount increment at `zval+0x10` before the same store.

### 5.3 Where `current` comes from

PHP 5.6.40, `ext/session/session.c` `PS_SERIALIZER_DECODE_FUNC(php_binary)`:

```c
if (has_value) {
    ALLOC_INIT_ZVAL(current);                                  /* separate heap zval */
    if (php_var_unserialize(&current, ..., &var_hash TSRMLS_CC)) {
        if (!skip) {
            php_set_session_var(name, namelen, current, &var_hash TSRMLS_CC);
        }
    } else {
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        return FAILURE;
    }
    var_push_dtor_no_addref(&var_hash, &current);              /* slot <- current */
}
```

PHP 5.4.45 is the same shape (`session.c:856-865`): `ALLOC_INIT_ZVAL(current)` at `:857`, `php_var_unserialize(&current, ...)` at `:858`, `var_push_dtor_no_addref(&var_hash, &current)` at `:864`.

The parser writes the typed zval into the separately allocated `current`; the dtor slot only receives its address. A plain scalar record costs one dtor push. `R:` references add a pre-push inside the parser before the final push, and object property overrides can add more; the slot cursor K accounts for all pushes before the target, so for the first push of a record `K = (A - B0)/8`, and for later pushes the attacker offsets K accordingly.

### 5.4 What this means

The 5.x G2 can write a heap pointer to any mapped 8-byte-aligned address `B0 + 8*K`. If the target is a serializer dispatch field, the field becomes a pointer to a heap zval, and the next `call *0x10(%rax)` jumps to heap memory, which is not executable under the default mappings. The 8.x G2 wrote an arbitrary typed zval into the slot, which is what allowed `IS_LONG = libc system` to become a code pointer. That value transfer is absent in 5.x.

A 5.x-specific adaptation would have to exploit the dereference of the stored pointer (for example, target `PS(serializer)` itself, so that `decode` is read at `zval+0x10`, where the 5.x zval stores refcount/type/is_ref, not a controllable 64-bit code address). That is outside the G2 shape and was not pursued here.

## 6. 8.x vs 5.x: why the G2 value does not transfer

The 8.5.10 php_binary decode hands the parser the typed slot itself:

```c
current = var_tmp_var(&var_hash);     /* &B0->data[used_slots], a 16-byte zval */
if (php_var_unserialize(current, ...)) {
    ZVAL_PTR(&rv, current);
    php_session_var(name, &rv, &var_hash);
}
```

`var_tmp_var` returns `&B0->data[B0->used_slots]` and the parser writes the parsed zval (including `IS_LONG` with an arbitrary 64-bit value) directly into that slot. The 5.x decode allocates `current` separately and stores only the pointer.

| Aspect | PHP 8.5.10 | PHP 5.6.40 / 5.4.45 |
|---|---|---|
| dtor block | `var_dtor_entries { zend_long used_slots; void *next; zval data[255]; }` | `var_entries { zval *data[1024]; long used_slots; void *next; }` |
| data offset | `+0x10` | `+0` |
| element | 16-byte typed `zval` | 8-byte `zval *` |
| slot address | `B0 + 0x10 + 16*K` | `B0 + 8*K` |
| bound | `used_slots + num > 255` | `used_slots == 1024` (equality; negative and >1024 accepted) |
| parser destination | the slot itself (`var_tmp_var`) | separate heap zval (`ALLOC_INIT_ZVAL`) |
| slot receives | parsed typed zval | pointer to the parsed zval |
| arbitrary 64-bit value (e.g. `system`) | yes (`IS_LONG`) | no |

This is the exact G2 value blocker: in 5.x the slot is an 8-byte pointer slot, and the only values the parser can put there are heap zval addresses, not an arbitrary 64-bit value.

## 7. G6: decode -> `zif_system`

### 7.1 ABI

PHP 5.6.40 `Zend/zend.h:290` and PHP 5.4.45 `Zend/zend.h:275`:

```c
#define INTERNAL_FUNCTION_PARAMETERS int ht, zval *return_value, zval **return_value_ptr, \
                                     zval *this_ptr, int return_value_used TSRMLS_DC
```

At the serializer dispatch, `decode(val, vallen)` has only `rdi = val` and `rsi = vallen` defined. In the 5.x handler ABI those registers are:

| Handler parameter | Register | Value from `decode(val, vallen)` |
|---|---|---|
| `int ht` | `edi` | low 32 bits of the session buffer address `val` |
| `zval *return_value` | `rsi` | `(zval*)vallen`, the session data length |
| `zval **return_value_ptr` | `rdx` | caller leftover, not supplied |
| `zval *this_ptr` | `rcx` | caller leftover, not supplied |
| `int return_value_used` | `r8d` | caller leftover, not supplied |

### 7.2 Wrappers

PHP 5.6.40:

```
4f195f <zif_system>:
  4f195f: push %rbp
  4f1960: mov  %rsp,%rbp
  4f1963: mov  $0x1,%r9d              ; mode = 1
  4f1969: call 4f17ca <php_exec_ex>
  4f196e: pop  %rbp
  4f196f: ret

4f1970 <zif_passthru>:
  4f1970: push %rbp
  4f1971: mov  %rsp,%rbp
  4f1974: mov  $0x3,%r9d              ; mode = 3
  4f197a: call 4f17ca <php_exec_ex>
```

PHP 5.4.45:

```
4edbdb <zif_system>:
  4edbdb: push %rbp
  4edbdc: mov  %rsp,%rbp
  4edbdf: mov  $0x1,%r9d
  4edbe5: call 4eda46 <php_exec_ex>

4edbec <zif_passthru>:
  4edbec: push %rbp
  4edbed: mov  %rsp,%rbp
  4edbf1: mov  $0x3,%r9d
  4edbf7: call 4eda46 <php_exec_ex>
```

### 7.3 `php_exec_ex` failure path

PHP 5.6.40, `php_exec_ex` at `0x4f17ca`:

```
4f17d9: mov  %rsi,%rbx               ; rbx = return_value = (zval*)vallen
4f1804: mov  $0x662fee,%esi          ; format "s|z/"
4f1809: mov  $0x0,%eax
4f180e: call 5a563a <zend_parse_parameters>   ; edi = ht (untouched)
4f1813: cmp  $0xffffffff,%eax
4f1816: je   4f1908                 ; parse failure
...
4f1908: movq $0x0,(%rbx)             ; RETURN_FALSE: *(zval*)vallen = 0
4f190f: movb $0x3,0x14(%rbx)         ; (*((zval*)vallen)).type = IS_FALSE
```

PHP 5.4.45, `php_exec_ex` at `0x4eda46`:

```
4eda55: mov  %rsi,%rbx
4eda80: mov  $0x6595e7,%esi
4eda85: mov  $0x0,%eax
4eda8a: call 59c216 <zend_parse_parameters>
4eda8f: cmp  $0xffffffff,%eax
4eda92: je   4edb84
...
4edb84: movq $0x0,(%rbx)
4edb8b: movb $0x3,0x14(%rbx)
```

### 7.4 Why the parse fails

`zend_parse_va_args` (PHP 5.6.40 `Zend/zend_API.c:729`, 5.4.45 `:700`) checks:

```c
if (num_args < min_num_args || (num_args > max_num_args && max_num_args > 0)) {
    ...
    return FAILURE;
}

arg_count = (int)(zend_uintptr_t) *(zend_vm_stack_top(TSRMLS_C) - 1);
if (num_args > arg_count) {
    ...
    return FAILURE;
}
```

For `s|z/`, `min_num_args = 1`, `max_num_args = 2`. `num_args = ht = (int)val`, the low 32 bits of the session buffer address (for example `0xf7a6a000`), which is far outside 1..2. The check fails immediately. Even if the low 32 bits happened to be 1 or 2, the `arg_count` check and the argument reads use the real VM stack (`zend_vm_stack_top()-1`); the serializer dispatch is a plain C call, so there is no matching argument frame.

### 7.5 Crash before exec

The failure branch jumps straight to `RETURN_FALSE`, which dereferences `rbx = (zval*)vallen`. `vallen` is the session data length (a small integer, typically hundreds or thousands of bytes), so the write targets an unmapped low address and SIGSEGVs. No command is executed. `zif_passthru` takes exactly the same path with mode 3.

This differs from the 8.x G6, where the handler receives `execute_data = val` and can be made to read a fake function table from the session buffer, execute the command, and only then crash on the return-value write. PHP 5.x has no `execute_data` parameter and no fake VM frame to shape; the first thing the handler does is the argument-count check, and the failure path writes to `vallen`.

## 8. Verdict

1. **G2 address geometry: transfers.** The 5.x dtor slot is `A = B0 + 8*K` with `B0 = P->last_dtor`, `K = used_slots`, equality check against 1024, and negative/over-1024 K accepted. A fake `php_unserialize_data` at P and a fake `var_entries` at B0 can redirect the write.
2. **G2 value: does not transfer.** The slot store is an 8-byte `zval*` (`mov (%r12),%rcx; mov %rcx,(%rax,%rdx,8)`). The parsed typed zval lives in a separate heap allocation. The 8.x ability to place an arbitrary 64-bit value (an `IS_LONG` equal to `zif_system` or a libc address) into the slot does not exist in 5.x.
3. **G6: does not transfer.** `decode(val, vallen)` enters `zif_system` with `ht=(int)val`, `return_value=(zval*)vallen`. `zend_parse_parameters` rejects the count, and `RETURN_FALSE` writes to address `vallen` and crashes before any exec. `zif_passthru` fails identically. There is no `execute_data`/fake-frame path.
4. **Stale chain: transfers as a primitive.** Pre-RINIT rfc1867 decode consumes `BG(unserialize).level=1`/`P` exactly as in 8.x; the RINIT memset makes it single-shot per plant. This is not a blocker.
5. **Overall:** the 5.x chain cannot reuse the 8.x G2 value write or the 8.x G6 decode-call shape. A 5.x chain needs a different primitive: an arbitrary 8-byte value write (not a pointer), or a dispatch that consumes attacker-controlled zval contents, or a 5.x-compatible call target whose ABI matches `(char *val, int vallen)`.

## 9. Evidence

All dumps are in `phase/`:

| File | Content |
|---|---|
| `build-info.txt` | configure line, CFLAGS, make tails, ELF headers |
| `md5sums.txt`, `sha256sums.txt` | binary and tarball hashes |
| `nm-5.6.40.txt`, `nm-5.4.45.txt` | full `nm -n` |
| `symbols-5.6.40.txt`, `symbols-5.4.45.txt` | filtered symbols |
| `types-5.6.40.txt`, `types-5.4.45.txt` | `ptype /o` of `php_ps_globals`, `php_basic_globals`, `php_unserialize_data`, `var_entries`, `zval`, `ps_serializer_struct` |
| `ps_serializers-5.6.40.txt`, `ps_serializers-5.4.45.txt` | table dump, entry names/pointers, `PS(serializer)`, `BG(unserialize)` addresses |
| `disasm-session_decode-5.6.40.txt`, `disasm-session_decode-5.4.45.txt` | `php_session_decode` dispatch |
| `disasm-zif-5.6.40.txt`, `disasm-zif-5.4.45.txt` | `php_exec_ex`, `zif_system`, `zif_passthru` |
| `disasm-varpush-5.6.40.txt`, `disasm-varpush-5.4.45.txt` | `var_push_dtor`, `var_push_dtor_no_addref` |

Key instruction addresses:

| Fact | 5.6.40 | 5.4.45 |
|---|---|---|
| decode slot (`php_binary`) | `0x816e00` | `0x79edc8` |
| `PS(serializer)` load | `0x4ace0d` | `0x4aad8e` |
| `call *0x10(%rax)` | `0x4ace19` | `0x4aad9a` |
| `used_slots == 1024` check | `0x53190e` (no addref), `0x531867` (addref) | `0x52be81`, `0x52bde1` |
| 8-byte slot store | `0x531931` | `0x52bea4` |
| `RETURN_FALSE` store | `0x4f1908` | `0x4edb84` |

## 10. Reproduction

Build:

```
cd /tmp/opencode/research/php5geo_20261022_0045
./build.sh
```

Dumps (no service; gdb only for static addresses and a stopped loader):

```
gdb -q -batch -ex "file build/php-5.6.40/sapi/fpm/php-fpm" -ex 'starti' \
  -ex 'p/x &ps_serializers' -ex 'x/12gx &ps_serializers' \
  -ex 'p/x &ps_globals.serializer' -ex 'p/x &basic_globals.unserialize'

objdump -d --start-address=0x4f17ca --stop-address=0x4f19a0 \
  build/php-5.6.40/sapi/fpm/php-fpm
```

`starti` stops in the dynamic loader before `main`; it is used only to evaluate the non-PIE absolute addresses. No FPM process was started.

## 11. SHA-256 manifest

| File | SHA-256 |
|---|---|
| `build/php-5.6.40/sapi/fpm/php-fpm` | `b9261e1cb91672c6a297bde724db3cd26833d329b832bc4bcbe0183af3703723` |
| `build/php-5.4.45/sapi/fpm/php-fpm` | `60e225762c90d24912b70b3ef5105db848f57b663182bc8eaee09f567224abaf` |
| `src/php56.tar.gz` | `56fb9878d12fdd921f6a0897e919f4e980d930160e154cbde2cc6d9206a27cac` |
| `src/php-5.4.45.tar.gz` | `25bc4723955f4e352935258002af14a14a9810b491a19400d76fcdfa9d04b28f` |

The top-level `SHA256SUMS` covers the binaries, tarballs, this README, `zifsys5.json` and the `phase/` evidence.

