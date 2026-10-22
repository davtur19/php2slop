# 5.x dtor / decode-slot ABI analysis

This note records what the 5.6.40/5.4.45 live tests and sources prove about
the 5.x session decode slot, the stale `BG(unserialize)` dtor write, and the
difference from the PHP 8.5 G2/G6 shapes.

## 1. `var_entries` and the dtor write are pointer-only

PHP 5.6.40 `ext/standard/var_unserializer.re`:

```c
typedef struct {
    zval *data[VAR_ENTRIES_MAX];   /* VAR_ENTRIES_MAX = 1024 */
    long used_slots;
    void *next;
} var_entries;
```

- `data` is an array of **8-byte `zval *` pointers**, not 16-byte typed zvals.
- `used_slots` is at `+0x2000`; `next` at `+0x2008`.
- `var_push_dtor()` does `Z_ADDREF_PP(rval); *slot = *rval;` — it stores the
  **pointer** to the zval and increments the zval refcount at `(*rval)+0x10`.
- `var_push_dtor_no_addref()` does `data[used_slots++] = *rval;` — again a
  pointer.
- `get_var_push_dtor_slot()` returns `&data[used_slots++]` and only allocates
  a fresh block when `used_slots == 1024` exactly. A forged `used_slots`
  (negative or > 1024) is accepted and produces an out-of-block slot.
- `php_unserialize_data` is `{ first, last, first_dtor, last_dtor }` at
  `+0x00/+0x08/+0x10/+0x18`.

The R: value code (`var_unserializer.re`):

```c
if (*rval != NULL) {
    var_push_dtor_no_addref(var_hash, rval);  /* pre-push of old current */
}
*rval = *rval_ref;                             /* current = referenced zval */
Z_ADDREF_PP(rval);
Z_SET_ISREF_PP(rval);
```

So the dtor sequence for a successful `R:` is:

1. pre-push: old `current` pointer at slot K;
2. top push: referenced zval pointer at slot K+1;
3. string/value top push: that value's zval pointer at slot K+2.

The pointer store is the **5.x G2 blocker**: you cannot make the slot contain
an arbitrary 64-bit value such as libc `system`. PHP 8.5 differs structurally:
there `current = var_tmp_var(&var_hash)` is the typed 16-byte slot itself and
`php_var_unserialize(current, ...)` writes the parsed zval (e.g. an `IS_LONG`
holding `system`) directly into it. That typed store does not exist in 5.x.

## 2. Why a direct `ps_serializers[].decode = system` dtor write fails

If the dtor slot is aimed at `ps_serializers[2].decode` (`0x816e00` on 5.6,
`0x79edc8` on 5.4), the value written is still a **zval pointer**, not
`system`. The engine later calls that heap pointer as a function; it is not
executable code. If one tries to use a fake zval whose value field contains
`system`, the store remains the pointer to the fake zval, and the R: metadata
writes (`Z_ADDREF_PP`, `Z_SET_ISREF_PP`) hit `fake+0x10` and `fake+0x15`,
destroying the fake code-pointer fields. The direct table write is therefore
not available on 5.x.

## 3. The working pivot: write `PS(serializer)`, not the table

`PS(serializer)` is a global `ps_serializer *` (`0x82e5c0` on 5.6,
`0x7b6038` on 5.4). The dtor pointer write can store a pointer to a fake
`ps_serializer` struct there:

```c
struct _ps_serializer {
    const char *name;                 /* +0x00 */
    ps_encode_func encode;            /* +0x08 */
    ps_decode_func decode;            /* +0x10 */
};
```

The fake struct `F1` is placed in the **second** `s_read` buffer at
`X2+0x300`; `F1+0x10` is libc `system`. The first decode's R: addref/is_ref
metadata writes hit `F1+0x10`/`F1+0x15` while `X2` still holds zeroed memory;
the second `s_read` overwrites `X2` with the payload and restores
`F1+0x10 = system`. The second decode then executes:

```c
decode(val, vallen)  ->  system(file_buffer, vallen)
```

Libc `system(const char *)` uses the first argument and ignores the second.
This is the exact shape that produced `/tmp/p5n` and `/tmp/p5r` on 5.6.40 and
`/tmp/php5_system56_marker` / `/tmp/php5_system54_marker` in the gdb-assisted
table tests.

The R: pre-push is at `PS(serializer)-8` (`0x82e5b8` on 5.6), which aliases
`PS(mod_user_implemented)` and `PS(mod_user_is_open)`. The pre-push writes a
real zval pointer there. At RSHUTDOWN the session code sees a nonzero
`mod_user_implemented` and a NULL `mod_data` and calls
`ps_close_files(NULL)`; `ps_files_close` dereferences NULL at
`ext/session/mod_files.c:326`. The 5.6 native chain repairs this with the
non-PIE binary gadget `0x4b4728` as the final encode pointer (see
`native_5.6_chain.md`). The gdb-assisted table-write lever does not corrupt
the flags and survives without the gadget.

## 4. `zif_system` is not the decode ABI; libc `system` is

The 5.x internal function ABI is:

```c
#define INTERNAL_FUNCTION_PARAMETERS int ht, zval *return_value, \
    zval **return_value_ptr, zval *this_ptr, int return_value_used TSRMLS_DC
```

Calling `zif_system` (`0x4f195f` on 5.6, `0x4edbdb` on 5.4) at the decode
slot passes `ht = (int)val` and `return_value = (zval *)vallen`.
`php_exec_ex` calls `zend_parse_parameters` with `num_args = ht`; the failure
path writes `return_value` (the integer `vallen`, e.g. 1024, an unmapped low
address) and SIGSEGVs before any exec. This is the geometry receipt's G6
"does not transfer" result, and it stands.

The live tests deliberately used **libc `system`**, whose signature
`int system(const char *command)` matches the first decode argument. The
second argument (`vallen`) is ignored by `system`. That is why the decode slot
works with libc `system` but not with `zif_system`.

## 5. Binary imports / PLT

`readelf`/`nm` evidence is in `imports_5.6.txt` and `imports_5.4.txt`:

- both binaries are ELF64 `ET_EXEC` (non-PIE), x86-64, with DWARF;
- neither imports `system`, `execve`, `execv`, `execvp`, `execl`, or
  `posix_spawn`;
- both import `popen@GLIBC_2.2.5`:
  - 5.6 `popen@plt = 0x417f30`, GOT slot `0x816780`;
  - 5.4 `popen@plt = 0x417ee0`, GOT slot `0x79e758`;
- both define `zif_system`, `zif_passthru`, `php_exec`, `zend_eval_string`,
  `zend_eval_stringl`.

`popen(const char *command, const char *mode)` receives the integer `vallen`
as `mode`. `mode` is not a valid string pointer, so the decode call cannot
drive `popen` directly. There is no `system`/`execve` PLT or GOT slot to use
without a libc base. A real-world ASLR-on exploit needs a libc leak (or a
separate code-reuse chain); the lab runs with `setarch -R`.

`zend_eval_string` / `zif_system` / `php_exec` / `assert` fallbacks were not
needed because libc `system` worked at the decode slot.

## 6. 5.4 geometry

- `ps_serializers` base `0x79eda0`; the `php` entry is index 0
  (`0x79eda0`: name `0x655c7c`, encode `0x4aeb05`, decode `0x4ae3ed`);
  the `php_binary` entry is index 1 (`0x79edb8`: name `0x655a70`,
  encode `0x4ae6fa`, decode `0x4ae189`).
- The `php_binary` decode slot is `0x79edc8` (not `0x79ede0`; that was the
  earlier index-correction). The 5.4 table has only the two real entries plus
  a NULL terminator, unlike 5.6's `php_serialize` + `php` + `php_binary`.
- `PS(serializer) = 0x7b6038`, `PS(http_session_vars) = 0x7b6040`,
  `ps_globals = 0x7b5f60`.
- The 5.4 gdb-assisted test set `0x79edc8 = system` (`0x7ffff7d1c090`),
  triggered `PHPSESSID=sys54b`, created `/tmp/php5_system54_marker`, and the
  worker 183822 survived. The decode slot was restored to `0x4ae189`.
- A native 5.4 dtor pivot was not executed. The 5.4 source has the same
  pointer-only `var_entries` ABI, so the 5.6 pivot should transfer with 5.4
  offsets, but its `X1`/`X2`/`P`/`F1`/gadget values were not derived.

## 7. Bottom line

- 5.x dtor store = pointer-only; 8.5 G2 typed-value store does not transfer.
- 5.x decode slot = `(char *val, int vallen)`; libc `system` / `passthru`-style
  `(const char *)` functions work, `zif_system` does not.
- Direct `ps_serializers[].decode = system` is not achievable through the
  dtor write. The working native primitive writes a pointer to a fake
  `ps_serializer` struct into `PS(serializer)` and places libc `system` at
  `F1+0x10` in the second `s_read` buffer.
- The R: pre-push corrupts the flags immediately before `PS(serializer)`;
  worker survival requires either the table-write lever or a repair gadget
  (5.6 `0x4b4728`).
- No binary `system`/`execve` import; `popen` is signature-incompatible.
  Native 5.x RCE needs a libc base (ASLR off in this lab) or a leak.
