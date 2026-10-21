# php2slop

php 8.5 session.upload_progress machinery tooling.
CVE-2026-109618 / CVE-2026-109619: pre-auth cross-request UAF family
(`ext/session/session.c` machinery + ZendMM OOM interruption, window 3129-3338 on 8.5.10).
Fixed 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21). Upstream pattern ≥ 5.4.0.
SAPIs: mod_php, no app cooperation needed. FPM, needs an app-reachable fatal after
successful startup, then the upload-progress consumer on the surviving worker (GHSA-6wmf-4rv5-p3rp).

The confirmed FPM route is G2, a typed zval write that overwrites the `php_binary`
session decode pointer in `.data`. It is measured on one plain non PIE 8.5.10 build
with ASLR off. It is not a universal exploit: heap addresses X, P, B0 and the libc
base are prerequisites, and an ASLR capable heap leak is still open (F14).

## Lanes

| lane | SAPI | shape | state |
|---|---|---|---|
| machinery producer and consumer | mod_php 8.5.10 NTS | producer OOM, then a tiny multipart and GET arms | dry wired, live gated; the worker survives |
| app unserialize OOM | mod_php 8.5.10 NTS | `producer_unser` class ladder | dry wired, `--live` gated by `--unser-url` |
| FPM app fatal | php-fpm 8.5.10 | post startup fatal inside the unserialize family | kills the worker with exit 70, not a route by itself |
| G2 decode hijack | php-fpm 8.5.10 ET_EXEC | plant, stale dtor chain, pre RINIT decode, `.data` write | confirmed lab, ASLR off; offline `--step g2` builder |
| in band heap leak | mod_php 8.5.10 PIE | `sidlen` / `sidhex` overread after the M5 write | measured, `leak_offset` 0x2188 build specific |
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

G3 is closed: `zend_array.pDestructor` is an arbitrary call primitive with `rdi`
pointing at a controlled zval, but neither binary has a usable stack pivot, `rsi`
is uncontrolled at the call, and `system` is not imported. F14 is open: no ASLR
capable heap leak exists. `fpmboot` derives `B0 = K_dest1 - 0x9000` only for a
fixed body layout with ASLR off, so the G2 plan takes X, P and B0 from the
operator.

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
| `tool/modules/g2_chain.py` | G2 FPM chain profile and offline `--step g2` record plan: negative `used_slots`, fake struct placement, record bytes, self-checks |
| `tool/modules/profiles.py` | `BINARY_PROFILES` + `TARGETS` registry |
| `tool/stages/probe.py` | pre-flight fingerprint (GET, status/headers) |
| `addresses/` | per-binary offsets (`g2_fpm_8510.json`, `apache_libphp.json`, FPM/CGI flavors, `generated/`) |
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
| 8.1, 8.0, 7.x, 5.x | EOL, unpatched | none | 7.4.33 write reproduced 4/4; G2 offsets derived for 7.4.33 and 8.1.34 |

Measured span: 7.4.33 to 8.5.11. G2 is live confirmed only on 8.5.10; the
8.4.25, 8.1.34 and 7.4.33 G2 offsets are static derivations on non PIE builds,
not live runs. Do not key offsets on the version alone: `ps_serializers` is
build specific.

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
```

`--step g2` writes `g2-record.bin` and `result.json`. It never opens a socket,
refuses `--live`, and does not guess X, P or B0. The example reproduces the
receipt record byte for byte
(sha256 `373b4bb1dabda7e4417942ef0b1cd75bbe3880f83b4d1b10187cf66708e075e8`).

Not implemented or closed:

| item | state |
|---|---|
| ASLR capable FPM heap leak | open (F14); `fpmboot` needs a fixed body layout and ASLR off |
| G3 `pDestructor` pivot | closed; no pivot, uncontrolled `rsi`, no libc `system` import |
| modphp measured chain constants | `TARGETS["modphp"]` producer and leak wired, chain unproven |

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
| status | run (producer wired) | run | producer wired, leak dry, chain unproven |

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
| g2 | `g2-record.bin`, addresses, geometry, checks, record sha256 |
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
