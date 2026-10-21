# Runtime Address Book — php 8.5.10 bench builds

Measured 2026-10-21 with `readelf -h/-lW` and `nm -n` only. No binary was executed; all
numbers are static ELF facts from the files on disk.

Relevant source trees:

- `/home/davide/ailocal/php/zerodays_1020/` (lab builds: plainpie, plain, default+debug, O0, asan)
- `/tmp/opencode/realapps/` (realapps-class builds: realapps_np non-PIE, realapps PIE)

## 1. Discovery inventory

`find` over both trees returned 42 files; `md5sum` deduplication shows **21 unique binaries**,
each present as exactly one byte-identical in-tree copy (build tree) and one installed copy.
File sizes are in bytes.

| build flavor | SAPI | bytes | dup paths (in-tree ≡ installed) | ELF type | first LOAD p_vaddr | p_align |
|---|---|---|---|---|---|---|
| realapps_np | php-fpm | 67176448 | `realapps/phpb_np/sapi/fpm/php-fpm` ≡ `realapps/install_realapps_np/sbin/php-fpm` | EXEC | 0x400000 | 0x200000 |
| realapps_np | php-cgi | 66785136 | `realapps/phpb_np/sapi/cgi/php-cgi` ≡ `realapps/install_realapps_np/bin/php-cgi` | EXEC | 0x400000 | 0x200000 |
| realapps_np | cli php | 66898984 | `realapps/phpb_np/sapi/cli/php` ≡ `realapps/install_realapps_np/bin/php` | EXEC | 0x400000 | 0x200000 |
| realapps | php-fpm | 67190272 | `realapps/phpb/sapi/fpm/php-fpm` ≡ `realapps/install_realapps/sbin/php-fpm` | DYN (PIE) | 0x0 | 0x200000 |
| realapps | php-cgi | 66799760 | `realapps/phpb/sapi/cgi/php-cgi` ≡ `realapps/install_realapps/bin/php-cgi` | DYN (PIE) | 0x0 | 0x200000 |
| realapps | cli php | 66913760 | `realapps/phpb/sapi/cli/php` ≡ `realapps/install_realapps/bin/php` | DYN (PIE) | 0x0 | 0x200000 |
| plainpie | php-cgi | 42508104 | `zerodays_1020/build_plainpie/sapi/cgi/php-cgi` ≡ `zerodays_1020/install_plainpie/bin/php-cgi` | EXEC | 0x400000 | 0x200000 |
| plainpie | cli php | 42622672 | `.../build_plainpie/sapi/cli/php` ≡ `.../install_plainpie/bin/php` | EXEC | 0x400000 | 0x200000 |
| plainpie | php-fpm | 42900672 | `.../build_plainpie/sapi/fpm/php-fpm` ≡ `.../install_plainpie/sbin/php-fpm` | EXEC | 0x400000 | 0x200000 |
| plain | php-cgi | 42494608 | `.../build_plain/sapi/cgi/php-cgi` ≡ `.../install_plain/bin/php-cgi` | DYN (PIE) | 0x0 | 0x200000 |
| plain | cli php | 42608912 | `.../build_plain/sapi/cli/php` ≡ `.../install_plain/bin/php` | DYN (PIE) | 0x0 | 0x200000 |
| plain | php-fpm | 42886256 | `.../build_plain/sapi/fpm/php-fpm` ≡ `.../install_plain/sbin/php-fpm` | DYN (PIE) | 0x0 | 0x200000 |
| default+debug | php-cgi | 224948776 | `.../build/php-8.5.10/sapi/cgi/php-cgi` ≡ `.../install/bin/php-cgi` | DYN (PIE) | 0x0 | 0x200000 |
| default+debug | cli php | 225483048 | `.../build/php-8.5.10/sapi/cli/php` ≡ `.../install/bin/php` | DYN (PIE) | 0x0 | 0x200000 |
| default+debug | php-fpm | 226199856 | `.../build/php-8.5.10/sapi/fpm/php-fpm` ≡ `.../install/sbin/php-fpm` | DYN (PIE) | 0x0 | 0x200000 |
| O0 | php-cgi | 35204944 | `.../build_O0/sapi/cgi/php-cgi` ≡ `.../install_O0/bin/php-cgi` | DYN (PIE) | 0x0 | 0x200000 |
| O0 | cli php | 35280288 | `.../build_O0/sapi/cli/php` ≡ `.../install_O0/bin/php` | DYN (PIE) | 0x0 | 0x200000 |
| O0 | php-fpm | 35477136 | `.../build_O0/sapi/fpm/php-fpm` ≡ `.../install_O0/sbin/php-fpm` | DYN (PIE) | 0x0 | 0x200000 |
| asan | php-cgi | 68419544 | `.../build_asan/sapi/cgi/php-cgi` ≡ `.../install_asan/bin/php-cgi` | DYN (PIE) | 0x0 | 0x200000 |
| asan | cli php | 68720328 | `.../build_asan/sapi/cli/php` ≡ `.../install_asan/bin/php` | DYN (PIE) | 0x0 | 0x200000 |
| asan | php-fpm | 68940712 | `.../build_asan/sapi/fpm/php-fpm` ≡ `.../install_asan/sbin/php-fpm` | DYN (PIE) | 0x0 | 0x200000 |

The three expected extras beyond the two named targets were all found: plain lab php-cgi
(PIE), ASAN php-cgi (PIE), and the PIE realapps-class php-fpm. Everything not EXEC is PIE.

Sanity-check pass (required values): **all matched on first measurement**
— realapps_np fpm: EXEC, base 0x400000, `zval_ptr_dtor` 0xc53c65, `zend_call_function` 0xb9e26a;
  plainpie cgi: `zval_ptr_dtor` 0xa88fae, `zend_call_function` 0x9cfd3f.

## 2. Profile builds — full detail

Symbols requested for the profile: `zif_passthru`, `zif_system` (added for completeness, it
is the sibling of `zif_passthru` in main.c), `zend_call_function`, `zend_llist_remove_tail`,
`zval_ptr_dtor`. All five are present in every binary (nothing on this bench is stripped).
Binding in `.symtab`: `zif_*` are local (`t`), the three `zend_*` are global (`T`) and are the
only ones of the five also exported in `.dynsym` (`nm -D` verified; dynsym addresses equal
symtab addresses in all 5 profile binaries).

### 2.1 realapps_np_fpm — `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`

| field | value |
|---|---|
| ELF type | EXEC (non-PIE) |
| image base (first LOAD p_vaddr) | 0x400000 |
| p_align | 0x200000 |
| md5 | 4ee099823b75e16ea36f93c71d57bfd8 (≡ `phpb_np/sapi/fpm/php-fpm`) |

| symbol | binding | vaddr | offset from base (vaddr − 0x400000) |
|---|---|---|---|
| zif_system | local t | 0xa3c061 | 0x63c061 |
| zif_passthru | local t | 0xa3c074 | 0x63c074 |
| zend_call_function | global T (+dynsym) | 0xb9e26a | 0x79e26a |
| zend_llist_remove_tail | global T (+dynsym) | 0xc38aeb | 0x838aeb |
| zval_ptr_dtor | global T (+dynsym) | 0xc53c65 | 0x853c65 |

- delta `zval_ptr_dtor − zend_call_function` = **0xb59fb**
- delta `zend_llist_remove_tail − zif_passthru` = **0x1fca77**

### 2.2 plainpie_cgi — `/home/davide/ailocal/php/zerodays_1020/install_plainpie/bin/php-cgi`

| field | value |
|---|---|
| ELF type | EXEC (non-PIE) |
| image base (first LOAD p_vaddr) | 0x400000 |
| p_align | 0x200000 |
| md5 | 629db99d6f3b7e6c78e57b0357f73539 (≡ `build_plainpie/sapi/cgi/php-cgi`) |

| symbol | binding | vaddr | offset from base (vaddr − 0x400000) |
|---|---|---|---|
| zif_system | local t | 0x88f5e7 | 0x48f5e7 |
| zif_passthru | local t | 0x88f5f7 | 0x48f5f7 |
| zend_call_function | global T (+dynsym) | 0x9cfd3f | 0x5cfd3f |
| zend_llist_remove_tail | global T (+dynsym) | 0xa6d6a8 | 0x66d6a8 |
| zval_ptr_dtor | global T (+dynsym) | 0xa88fae | 0x688fae |

- delta `zval_ptr_dtor − zend_call_function` = **0xb926f**
- delta `zend_llist_remove_tail − zif_passthru` = **0x1de0b1**

### 2.3 plain_cgi — `/home/davide/ailocal/php/zerodays_1020/install_plain/bin/php-cgi`

| field | value |
|---|---|
| ELF type | DYN (PIE) |
| image base (first LOAD p_vaddr) | 0x0 — runtime base randomized per exec |
| p_align | 0x200000 |
| md5 | efb420366054f7421b6bee6ede272ce3 (≡ `build_plain/sapi/cgi/php-cgi`) |

| symbol | binding | vaddr (= offset from base, file-relative) |
|---|---|---|
| zif_system | local t | 0x496cc5 |
| zif_passthru | local t | 0x496cd5 |
| zend_call_function | global T (+dynsym) | 0x5db626 |
| zend_llist_remove_tail | global T (+dynsym) | 0x67a768 |
| zval_ptr_dtor | global T (+dynsym) | 0x6965a5 |

- delta `zval_ptr_dtor − zend_call_function` = **0xbaf7f**
- delta `zend_llist_remove_tail − zif_passthru` = **0x1e3a93**

### 2.4 asan_cgi — `/home/davide/ailocal/php/zerodays_1020/install_asan/bin/php-cgi`

| field | value |
|---|---|
| ELF type | DYN (PIE) |
| image base (first LOAD p_vaddr) | 0x0 — runtime base randomized per exec |
| p_align | 0x200000 |
| md5 | c5bd84e2129fcdb96d7ebcaf7fbc82f7 (≡ `build_asan/sapi/cgi/php-cgi`) |

| symbol | binding | vaddr (= offset from base, file-relative) |
|---|---|---|
| zif_system | local t | 0xae7917 |
| zif_passthru | local t | 0xae7927 |
| zend_call_function | global T (+dynsym) | 0xeafdfa |
| zend_llist_remove_tail | global T (+dynsym) | 0x111f167 |
| zval_ptr_dtor | global T (+dynsym) | 0x1173d43 |

- delta `zval_ptr_dtor − zend_call_function` = **0x2c3f49**
- delta `zend_llist_remove_tail − zif_passthru` = **0x637840**

### 2.5 realapps_fpm — `/tmp/opencode/realapps/install_realapps/sbin/php-fpm` (PIE, realapps-class)

| field | value |
|---|---|
| ELF type | DYN (PIE) |
| image base (first LOAD p_vaddr) | 0x0 — runtime base randomized per exec |
| p_align | 0x200000 |
| md5 | 26e4c7c37b8ec17659035052457694d2 (≡ `phpb/sapi/fpm/php-fpm`) |

| symbol | binding | vaddr (= offset from base, file-relative) |
|---|---|---|
| zif_system | local t | 0x6496af |
| zif_passthru | local t | 0x6496c2 |
| zend_call_function | global T (+dynsym) | 0x7b03f1 |
| zend_llist_remove_tail | global T (+dynsym) | 0x84c1ab |
| zval_ptr_dtor | global T (+dynsym) | 0x86775c |

- delta `zval_ptr_dtor − zend_call_function` = **0xb736b**
- delta `zend_llist_remove_tail − zif_passthru` = **0x202ae9**

## 3. Cross-build delta summary

Both deltas are exactly constant per build and were measured identical across all three
SAPI variants (php-fpm / php-cgi / cli) of the same link. All 21 unique binaries agree:

| build | dtor−call (zval_ptr_dtor − zend_call_function) | llist−passthru (zend_llist_remove_tail − zif_passthru) | ELF type |
|---|---|---|---|
| realapps_np (profile fpm + cgi + cli) | 0xb59fb | 0x1fca77 | EXEC |
| plainpie (fpm + cgi + cli) | 0xb926f | 0x1de0b1 | EXEC |
| realapps (fpm + cgi + cli) | 0xb736b | 0x202ae9 | DYN |
| plain (fpm + cgi + cli) | 0xbaf7f | 0x1e3a93 | DYN |
| asan (fpm + cgi + cli) | 0x2c3f49 | 0x637840 | DYN |
| O0 (fpm + cgi + cli) | 0x201e03 | 0x4a516a | DYN |
| default+debug (fpm + cgi + cli) | 0x6ce57b | 0xe862c5 | DYN |

(Profile builds in the JSON artifacts above: realapps_np_fpm, plainpie_cgi, plain_cgi,
asan_cgi, realapps_fpm — deltas quoted from their fpm/cgi member; other SAPI members carry
the same delta, see appendix.)

## 4. Full symbol vaddrs, all unique binaries (appendix)

| binary | zif_passthru | zif_system | zend_call_function | zend_llist_remove_tail | zval_ptr_dtor |
|---|---|---|---|---|---|
| realapps_np fpm | 0xa3c074 | 0xa3c061 | 0xb9e26a | 0xc38aeb | 0xc53c65 |
| realapps_np cgi | 0xa3bfb4 | 0xa3bfa1 | 0xb9e1aa | 0xc38a2b | 0xc53ba5 |
| realapps_np cli | 0xa3bf74 | 0xa3bf61 | 0xb9e16a | 0xc389eb | 0xc53b65 |
| realapps fpm | 0x6496c2 | 0x6496af | 0x7b03f1 | 0x84c1ab | 0x86775c |
| realapps cgi | 0x649602 | 0x6495ef | 0x7b0331 | 0x84c0eb | 0x86769c |
| realapps cli | 0x649602 | 0x6495ef | 0x7b0331 | 0x84c0eb | 0x86769c |
| plainpie cgi | 0x88f5f7 | 0x88f5e7 | 0x9cfd3f | 0xa6d6a8 | 0xa88fae |
| plainpie cli | 0x88f5b7 | 0x88f5a7 | 0x9cfcff | 0xa6d668 | 0xa88f6e |
| plainpie fpm | 0x88f6b7 | 0x88f6a7 | 0x9cfdff | 0xa6d768 | 0xa8906e |
| plain cgi | 0x496cd5 | 0x496cc5 | 0x5db626 | 0x67a768 | 0x6965a5 |
| plain cli | 0x496c95 | 0x496c85 | 0x5db5e6 | 0x67a728 | 0x696565 |
| plain fpm | 0x496d95 | 0x496d85 | 0x5db6e6 | 0x67a828 | 0x696665 |
| default+debug cgi | 0x47e00bb | 0x47e00ab | 0x505fa49 | 0x5666380 | 0x572dfc4 |
| default+debug cli | 0x47e007b | 0x47e006b | 0x505fa09 | 0x5666340 | 0x572df84 |
| default+debug fpm | 0x47e017b | 0x47e016b | 0x505fb09 | 0x5666440 | 0x572e084 |
| O0 cgi | 0x6b5a40 | 0x6b5a15 | 0x995c18 | 0xb5abaa | 0xb97a1b |
| O0 cli | 0x6b5a00 | 0x6b59d5 | 0x995bd8 | 0xb5ab6a | 0xb979db |
| O0 fpm | 0x6b5b00 | 0x6b5ad5 | 0x995cd8 | 0xb5ac6a | 0xb97adb |
| asan cgi | 0xae7927 | 0xae7917 | 0xeafdfa | 0x111f167 | 0x1173d43 |
| asan cli | 0xae78e7 | 0xae78d7 | 0xeafdba | 0x111f127 | 0x1173d03 |
| asan fpm | 0xae79e7 | 0xae79d7 | 0xeafeba | 0x111f227 | 0x1173e03 |

## 5. Mapping to the PROFILE model (leaked vs fixed address)

Factual, derived strictly from the measurements above:

- **EXEC (non-PIE) builds — realapps_np (all 3 SAPIs), plainpie (all 3 SAPIs).** The first
  LOAD segment carries `p_vaddr = 0x400000` with `p_align = 0x200000`; the ELF type is
  EXEC, so the kernel maps this single image at the fixed link address on every exec. For
  these builds, static vaddrs are runtime addresses; a profile (symbol list + deltas) can
  be applied without any attacker-visible address disclosure. The same applies whether a
  symbol is `.dynsym`-exported (`zend_*`) or `.symtab`-local (`zif_*`) — both classes sit
  inside the fixed image, so their runtime addresses are equally constant.
- **DYN (PIE) builds — realapps, plain, default+debug, O0, asan.** First LOAD `p_vaddr = 0x0`;
  runtime address = load base (randomized per exec) + file vaddr. A static vaddr is only a
  relative offset; converting it to a usable runtime address requires observing one
  runtime address of the target image.
- **Deltas.** `zval_ptr_dtor − zend_call_function` and `zend_llist_remove_tail − zif_passthru`
  are per-build constants (identical across SAPI variants of the same build, and — measured —
  different across build flavors: dtor−call ranges from 0xb59fb (realapps_np) to 0x6ce57b
  (default+debug)).

Marked as *hypothesis* (not exercised here; no binary was executed and no runtime leak was
observed):

- That the two deltas suffice as a build-fingerprint for the profile forge to lock onto the
  correct build flavor from a reflected pointer pair. The measured cross-build distinctness
  of the deltas is consistent with it, but no runtime behavior has been tested.
- That on the EXEC builds the profile can be produced entirely offline (this is what the ELF
  facts imply mechanically, but runtime confirmation was out of scope).

## 6. Artifacts

- This file: `/tmp/opencode/realapps/side/runtime_addresses.md`
- JSON per profile build: `/tmp/opencode/realapps/side/addresses/{realapps_np_fpm, plainpie_cgi, plain_cgi, asan_cgi, realapps_fpm}.json`
