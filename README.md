Research exploit tooling for the PHP `session.upload_progress` use-after-free
(CVE-2026-109618 / CVE-2026-109619).

**Status: WIP research code.** Not a universal exploit: every chain is build-,
SAPI- and configuration-specific and needs exact per-build offsets, a compatible
worker pool and, in several lanes, the non-default settings named in parentheses
in the tables. `all default config` means the distribution's production INI;
where an official image ships no active INI, the `php.ini-production` mount is
the parenthesized requirement, as in `(php.ini-production; image ships none)` for
8.4.26. Direct Apache prefork mod_php is the only SAPI with verified end-to-end
code execution under all default config for the named builds. FPM Path C is real
but needs the listed non-default changes, and a default nginx front blocks the
large request bodies. Treat every result as build-specific.

## Status: what is verified

RCE end to end with a target-written `uid`, all default config:

- Sury PHP 8.0.28 + WordPress 7.1.3 on Ubuntu 22.04, Apache 2.4.52 prefork mod_php: full chain, worker survives; `zif_passthru` writes the proof because `zif_system` crashes the worker.
- Official `php:8.4.26-apache` (php.ini-production; image ships none) + pristine WordPress 7.1.3, Apache 2.4.69 prefork, default worker cap: full chain; 8.4.27 is fixed.
- Official `php:8.2.34-apache` and `php:8.3.35-apache`, default 150-worker prefork: full chain; 8.2.35, 8.3.36 and 8.5.12 are fixed.
- Debian 13.7 `libapache2-mod-php8.4 8.4.24-1~deb13u1`, Apache 2.4.69 prefork mod_php, default package config: direct chain plus pure-HTTP pool-exhaustion pin.
- Ubuntu 25.04 `8.4.5-1ubuntu1.2` mod_php, package-specific.

Real but not all default config (all required changes are listed in the Path C
table; the INI mount is shown where relevant): Path C on FPM 8.4.26 and
8.2.34/8.3.35, and on mod_php 8.4.26 (php.ini-production; image ships none). The
8.5.11 FPM single-worker (`pm=static`) cell and Path C on mod_php 7.4.32 are in
progress, not RCE claims. Default nginx fronts and the FPM leak stage with a
declared length (`post_max_size`) are blocked.

Not claimed: 8.1.33 and 7.4.32 are ❌ on the stale-session-id chain (Path C on
mod_php 7.4.32 remains in progress); 8.5.11 mod_php is a leak-only ❌ there
(free-slot qwords, no libphp pointer). No FPM cell carries that chain: FPM exits
the worker 70 when `php_request_startup()` fails. No LFI or third-party write;
target-side writes are only the same-chain proof or session file. ASLR is on and
`display_errors` is off in every positive mod_php cell.

## Conventions

Legend: ✅ RCE in that exact cell · ❌ tested negative in that exact cell ·
🚫 patched build (basis stated) · — no qualifying RCE in that cell (untested or
engine-level primitive without execution). ✅ rows are direct Apache prefork
mod_php unless the row names another SAPI. Non-default cells carry the changes
they need in parentheses. Endpoints are a small PHP probe or the named core
silence file.

### mod_php

Official `php:<v>-apache` images with `php.ini-production` (required in the
7.4.33, 8.1.34 and 8.4.26 cells, the only INI used for 8.0.29 and 8.0.30; see
the note below), ASLR on, `display_errors` off, exact per-build offsets and
default prefork sizing, except the 8.0.28 row, which is the exact Sury package.

| PHP build | Branch | Status | Result / qualifier |
|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | no RCE; last 5.6 |
| 7.0.33 | 7.0 | ❌ | no RCE; last 7.0 |
| 7.1.33 | 7.1 | ❌ | no RCE; last 7.1 |
| 7.2.0 | 7.2 | ❌ | no RCE; early 7.2 |
| 7.2.34 | 7.2 | ❌ | no RCE; last 7.2 |
| 7.3.33 | 7.3 | ❌ | no RCE; last 7.3 |
| 7.4.0 | 7.4 | ❌ | no RCE; early 7.4 |
| 7.4.32 | 7.4 | ❌ | no RCE on the stale-session-id route; the stale `PS(id)` is rejected (`The session id is too long or contains illegal characters`); no leak, no write; Path C on this build is in progress (see below) |
| 7.4.33 | 7.4 | ✅ | full chain on the default 150-worker prefork with the 149-held-request pin; the priming OOM in `php_session_reset_id` leaves a stale `PS(id)` in a cached chunk; target-written `uid`; last 7.4; `S=main+0xfd398`, `zif_system=libphp+0x335850`; (php.ini-production, 5/150 prefork) |
| 8.0.28 | 8.0 | ✅ | exact Sury `1:8.0.28-1+ubuntu22.04.1+deb.sury.org+1` with WordPress 7.1.3, all default config: full chain, target-written `uid=33(www-data)`, worker survives; default 150-worker prefork pinned with 149 held slow requests; one child serves every stage; `S=main+0xF7398`, `zif_passthru=libphp+0x1F5640` |
| 8.0.29 | 8.0 | ✅ | full chain on the default 150-worker prefork; the priming OOM in `php_session_reset_id` leaves the stale `PS(id)` and the leak stage recovers `libphp` and `main` from the cookie; target-written `uid`; `zif_system=libphp+0x348eb0`, `zval_ptr_dtor=0x431080` |
| 8.0.30 | 8.0 | ✅ | full chain on the default 150-worker prefork; the same body set as 8.0.29 with this build's offsets; target-written `uid`; last 8.0; `zif_system=libphp+0x3495d0`, `zval_ptr_dtor=0x4319a0` |
| 8.1.33 | 8.1 | ❌ | no RCE; pre-8.1.34; structurally blocked: the second request faults before the header; no cookie, no leak |
| 8.1.34 | 8.1 | ✅ | full chain on the default 150-worker prefork with the 149-held-request pin; the leak stage recovers `libphp` from the `zval_ptr_dtor` qword and `main` from the second 2 MiB cluster; target-written `uid`; last tested 8.1 mod_php; `S=main+0xf9398`, `zif_system=libphp+0x36f470`; (php.ini-production, 5/150 prefork) |
| 8.2.0 | 8.2 | ❌ | no RCE; early 8.2 |
| 8.2.15 | 8.2 | ❌ | no RCE; mid 8.2 |
| 8.2.34 | 8.2 | ✅ | full chain on the default 150-worker prefork; 149 held slow requests pin one child (partial-header holders are reaped by the default `mod_reqtimeout`); target-written `uid`; 149-holder pool exhaustion, no `%P`, no restart, no config change; last vulnerable 8.2; engine-level |
| 8.2.35 | 8.2 | 🚫 | fixed control; priming request returns 200 with no OOM |
| 8.3.0 | 8.3 | ❌ | no RCE; early 8.3 |
| 8.3.10 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.20 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.35 | 8.3 | ✅ | full chain on the default 150-worker prefork with the same held-request pin; target-written `uid`; last vulnerable 8.3; engine-level |
| 8.3.36 | 8.3 | 🚫 | fixed control; priming request returns 200 with no OOM |
| 8.4.0 | 8.4 | — | never released upstream; no official image or release |
| 8.4.1–8.4.7 | 8.4 | ✅ | per-build tested, not a range extrapolation; direct mod_php chain on the WordPress core silence file, target-written `uid`; `S=main+0xED398`; 8.4.7 pure-HTTP 149 half-open pin (no `%P`, no local process control, no fresh-child swap) |
| 8.4.8 | 8.4 | ✅ | pure-HTTP and direct Apache both reproduced; WordPress core silence file, target-written `uid`; `S=main+0xE8398`; engine-level |
| 8.4.9 | 8.4 | — | never released upstream; 8.4.8 to 8.4.10 |
| 8.4.10–8.4.26 | 8.4 | ✅ | per-build tested, not a single-build extrapolation; distinct target-written `uid` proofs; `S=main+0xF8398`; 8.4.26 endpoint-independent; the 8.4.26 re-run on pristine WordPress 7.1.3 with the default 150-worker pool (php.ini-production; image ships none): priming and leak on one pinned child, write stage on a fresh child, target-written `uid`, all default config |
| 8.4.27 | 8.4 | 🚫 | fixed in source; runtime control returns 200 with no leak |
| 8.5.0 | 8.5 | ❌ | leak only; no libphp code pointer |
| 8.5.5 | 8.5 | ❌ | leak only |
| 8.5.10 | 8.5 | ❌ | leak only; no `libphp`/`main` pointer; known offsets `zif_system 0x598d60`, `zval_ptr_dtor 0x7b3860`, `ps_globals 0x1770a40`; no code execution |
| 8.5.11 | 8.5 | ❌ | leak only; free-slot qwords, no libphp pointer, no 8.4-style main-chunk bucket; A2/B2 not reached |
| 8.5.12 | 8.5 | 🚫 | fixed in source; runtime control returns 200 with a normal cookie |

`php.ini-production` sets `output_buffering=4096`, `display_errors=Off`,
`log_errors=On`, `memory_limit=128M`, `post_max_size=8M`,
`session.upload_progress.enabled=On`, `session.sid_length=26` and
`session.sid_bits_per_character=5`. The 7.4.33 and 8.1.34 rows fail at the
priming stage with no active INI; on 8.1.34 a minimal-INI control isolates
`output_buffering=4096`. The 8.4.26 control with no active INI
(`output_buffering=0`, `display_errors=On`, `log_errors=Off`) returns 200 at the
priming stage with the session destroyed, so no stale `PS(id)` exists and the
chain is unreachable.

The 🚫 8.4.27, 8.5.12, 8.3.36 and 8.2.35 rows fix only the 109618/109619
memory-corruption chain. CVE-2026-115560 is conditional serializer confusion
(`php_binary`/`php_serialize` to `php`, app gadget, `upload_progress` on, default
`cleanup=1` race); it is not memory corruption, not an 8.4.27 bypass, and changes
no row status.

The 8.1.34 and 7.4.33 rows use the default 150-worker prefork; a single-worker
container (`MaxRequestWorkers 1`) was an additional control only, not part of
either cell. Offsets are build-specific; do not transplant between builds. The
149-holder pin is a pool-exhaustion primitive that assumes the default
`MaxRequestWorkers=150` and one free child.

### FPM

Official `php:<v>-fpm` images behind nginx, with `php.ini-production` mounted (the
image ships none), `pm=dynamic` with the default child cap. This table covers the
stale-session-id chain; Path C is a separate section. Rows naming a different
build or pool override the generic `php.ini-production` / `pm=dynamic` wording.

| PHP build | Branch | Status | Result / qualifier |
|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | priming OOM/SIGSEGV; no leak, no write stage |
| 7.0.33 | 7.0 | ❌ | leak only |
| 7.1.33 | 7.1 | ❌ | leak only |
| 7.2.34 | 7.2 | ❌ | leak only |
| 7.3.33 | 7.3 | ❌ | leak only |
| 7.4.33 | 7.4 | ❌ | leak only |
| 8.0.29 | 8.0 | ❌ | default nginx cap rejects the priming body; direct FPM runs the priming OOM, the worker exits 70, and no state carries over |
| 8.0.30 | 8.0 | ❌ | second stage 200 under the default limit; the first stage also returns 200 with a lowered limit, no OOM; the 8.0-geometry priming OOM instead exits the worker 70 (see below) |
| 8.1.34 | 8.1 | ❌ | priming request ends in a worker exit; no state carry-over |
| 8.2.34 | 8.2 | ❌ | priming request ends in a worker exit; the mod_php stale-id result does not extend to FPM (Path C does, with non-default settings) |
| 8.2.35 | 8.2 | 🚫 | fixed control; priming requests return 200, no worker exits |
| 8.3.35 | 8.3 | ❌ | structurally blocked, direct FPM and default nginx; see below |
| 8.3.36 | 8.3 | 🚫 | fixed control; priming request returns 200 |
| 8.4.26 | 8.4 | ❌ | chain negative: a sub-cap priming body still OOMs and the worker exits; the leak body is rejected at the default body cap; no surviving child or leak; the 109619 primitive is present but no controlled destructor |
| 8.4.27 | 8.4 | 🚫 | upstream fix; FPM runtime control not run |
| 8.5.11 (non-default: `pm=static`, one worker) | 8.5 | — | in progress (plain full-extension build, `pm=static`, one worker, same-worker known target plus trigger script); the previously reported single-worker shape used blind leak-derived addresses and a fake destructor to `zif_system`, but it is not counted as an RCE claim here |
| 8.5.11 (default `pm=dynamic` pool) | 8.5 | ❌ | leak only |
| 8.5.12 | 8.5 | 🚫 | fixed; plain full-extension build with default nginx |

FPM 5.6.40 produced no leak; the leak-only range is 7.0.33–7.4.33. Large-body
7.4/8.0 FPM leak negatives are invalid: `post_max_size` rejects the body before
session code.

**No FPM cell carries the stale-session-id chain.** FPM converts a failed
`php_request_startup()` into process exit: `fcgi_finish_request()`,
`php_module_shutdown()` and `return FPM_EXIT_SOFTWARE` (70)
(`sapi/fpm/fpm/fpm_main.c:1852-1857`). The priming OOM is raised inside that
startup path, so the worker and its `ps_globals` die before a second request
exists. mod_php keeps the child: `sapi/apache2handler/sapi_apache2.c` catches the
bailout and runs the request destructor, so the child and its `ps_globals` stay
addressable for the next request.

**8.3.35 FPM is structurally blocked.** Canonical and shrunk priming shapes each
OOM at startup and the worker exits, so no process survives to serve the leak
stage with a stale `PS(id)`; the Apache holder pattern is inapplicable because the
state holder would have to survive its own fatal. Default nginx rejects the
canonical bodies, the default `fastcgi_buffer_size` rejects the oversized response
header, and `post_max_size` discards the leak body when a length is declared.
FastCGI has no chunked escape and `S_off` is not calibrated on FPM. No proof file,
no RCE.

### Path C (CVE-2026-109619)

Path C does not use a stale session id. A primed request whose post-RINIT
`session_start()` decode hits the memory limit bails out before
`php_var_unserialize_destroy()`, leaving the process-global `BG(unserialize)` at
`level=1` with pointers into a freed request chunk. The next request's pre-RINIT
upload-progress decode reuses that context; two `var_push()` stores with an
attacker-controlled index overwrite `ps_files.last_key` and `ps_files.basedir`,
and the session writer opens the attacker path. A `.php` file under an executing
docroot then runs. The consumer needs no app-level `session_start()`; the priming
page does.

| Build / SAPI | Status | Required non-default changes | Result |
|---|---|---|---|
| 8.4.26 mod_php | ✅ | reduced `memory_limit`, single worker (`MaxRequestWorkers 1`), writable docroot, pre-seeded prime session, an extra shaping part | target-written PHP file executed over HTTP; the child survives; the same payload is blocked on 8.4.27 (no file, probe 404) |
| 8.4.26 FPM | ✅ | `session.upload_progress.cleanup=Off`, reduced `memory_limit`, raised `max_input_vars`, writable executable docroot, single worker or pool affinity, pre-seeded session, raised `client_max_body_size` (non-default body cap; the nginx location/routing stays default) | target-written shell executed through the default nginx PHP location and routing; the body cap is the non-default change, not a default-cap bypass; repeat runs on the same worker also succeed |
| 8.2.34 FPM | ✅ | reduced `memory_limit`, pre-seeded two-record session, priming page that calls `session_start()` after RINIT, one worker with no intervening request, writable executable docroot | target-written shell executed; same worker serves prime, consumer and shell request |
| 8.3.35 FPM | ✅ | same as 8.2.34 | target-written shell executed, including in a subdirectory of the docroot |
| 8.2.35 FPM | 🚫 | none | early reset plus fallible unserialize; no shell, session file unchanged |
| 8.3.36 FPM | 🚫 | none | same fix; no shell, worker alive |
| 8.4.27 FPM | 🚫 | none | source-level fix only; no FPM binary executed |
| 8.5.12 FPM | 🚫 | none | runtime control: the pre-RINIT decode sees a zeroed context; no shell |
| 8.5.10 FPM | — | n/a | inconclusive; neither fixed nor exploitable is claimed |
| 7.4.32 mod_php | — | in progress | the local shape needs an absolute chunk base and a pre-seeded two-record session; not counted as RCE here |
| 7.4.32 FPM | — | source only | same preconditions by inspection; no runnable 7.4.32 FPM build |
| Default nginx front | ❌ | larger `client_max_body_size` (non-default) | the default cap returns 413 before PHP for the priming and consumer bodies |

Notes on Path C:

- Default `max_multipart_body_parts=-1` resolves to `max_input_vars + max_file_uploads`; raising `max_input_vars` covers the part budget. Other session settings were not required in the measured 8.4.26 shape.
- A writable, executable docroot is required: a read-only docroot reaches the session writer but the open fails. No direct command-execution variant was demonstrated.
- Unpinned requests land on different workers and fail; holding all but one pins the chain. There is no cross-worker state transfer.
- Upload-progress keys cannot inject arbitrary serialized records (`|` is rejected by the `php` serializer), so attacker-controlled session content remains the limitation; no default-application drive-by is claimed.
- Fixed builds zero the serialize state in `php_basic_early_rinit()` before `sapi_activate()` and the fallible unserializer unwinds. Offsets are build-, INI- and request-shape-specific; 7.4.32 additionally needs the chunk base.

### nginx + mod_php

nginx terminates HTTP and proxies to Apache prefork mod_php.

| Build / package | Status | Conditions / result |
|---|---|---|
| 8.4.7 official | ❌ | default nginx body cap rejects both stages; `proxy_request_buffering on` destroys the holder pin (measured on the same 8.4.8 stack); direct Apache chain reproduced |
| 8.4.8 official | ❌ | default cap rejects both stages; holders never reach Apache and Apache sees fewer POSTs; the default response-header buffer returns 502 on the oversized leak header; a size-cap-only control returns a normal response with no session cookie; direct Apache chain reproduced |
| 8.4.24 Debian 13 (`8.4.24-1~deb13u1`) | — | the default nginx cell is not a positive: the leak body would be rejected and buffering re-arms `post_max_size`; the earlier non-default cell is historical, not a default result; the verified path is direct Apache |
| 8.4.26 official | ❌ | default nginx negative: priming and leak bodies rejected; every holder logged with `up="-"`; the probe requests ran on distinct children; the response header exceeds the default `proxy_buffer_size`; no default bypass |
| 8.4.26 official | — | historical non-default only (larger `client_max_body_size`, larger response-header buffers, upstream keepalive); not a default result or default-bypass claim |
| 8.4.27 | 🚫 | fixed; priming and leak probes return 200 with no leak, default and non-default |

The direct Apache 8.4.7/8.4.8/8.4.26 cells remain ✅; the ❌ rows are the
nginx-terminated cells only. Blockers: the default body cap, request buffering
(re-frames chunked bodies, re-arms `post_max_size`) and the default
response-header buffer. The endpoint is not the blocker.

With `proxy_request_buffering on`, every half-open holder is logged `up="-"`, so
no holder reaches Apache and probes run on distinct children; a body-cap sweep
found no functional priming body. The only same-child route without holders is a
non-default request-side relaxation (`proxy_http_version 1.1`, cleared
`Connection`, upstream keepalive); a residual paginated small leak is untested.
The Debian 8.4.24 default-nginx cell is —.

### nginx + FPM

Default nginx front, default FPM pool.

| PHP build | Status | Conditions / result |
|---|---|---|
| 8.0.29 | ❌ | default cap returns 413 for the priming body; with a raised cap the startup OOM exits the worker 70 and the next request lands on a fresh worker |
| 8.0.30 | ❌ | second stage 200; the first stage also 200 with a lowered limit, no OOM |
| 8.1.34 | ❌ | priming request ends in a worker exit; no state carry-over |
| 8.2.34 | ❌ | same worker-exit shape |
| 8.2.35 | 🚫 | fixed control; priming requests return 200, no worker exits |
| 8.3.35 | ❌ | canonical bodies rejected at the default cap; the shrunk priming body returns 502 with a FastCGI stderr record from the dying worker; startup OOM exits the worker; the default `fastcgi_buffer_size` rejects the oversized response header; no chain |
| 8.3.36 | 🚫 | fixed; priming request returns 200 |
| 8.4.26 | ❌ | default cap returns 413; with a raised cap the worker still exits on OOM, so the cap is not the only blocker; the amplification path is insufficient to replace the leak body; no chain |
| 8.4.27 | 🚫 | upstream fix; runtime control missing |
| 8.5.11 | ❌ | leak only under the default `pm=dynamic` pool; the single-worker cell is in progress in the FPM table |
| 8.5.12 | 🚫 | plain full-extension build with default nginx; priming request returns 200 |

**Request amplification cannot replace the leak stage.** A small multipart body
with many zero-length nested file parts amplifies strongly, because
`max_file_uploads` counts only parts with content while `max_input_vars` is the
only cap; through default nginx it still reaches PHP and exhausts memory (500 on
mod_php, 502 with a worker exit on FPM). The leak stage needs a POST field value
at a fixed offset in the freed chunk plus the forged header, and the default
front-end caps are below that minimum; amplification allocates array metadata,
not body-value buffers. No target-written `uid` in this lane.

### OpenLiteSpeed + lsphp (LSAPI)

OpenLiteSpeed 1.9.3 Open, close to default config, PHP's default limits and a
small PHP probe endpoint. `lsphp` is a standalone LSAPI executable, not a shared
module.

| PHP build | LSAPI | Status | Result / qualifier | Basis |
|---|---|---|---|---|
| 8.4.26 (local source build) | V8.3 | ❌ | probes return 200 normally; an instrumented build reproduces the poisoned `$_FILES` bucket and then OOMs; the untouched binary returns 500 with a normal `WIFEXITED` status and no SIGSEGV/SIGABRT/SIGBUS, and the server respawns the worker while health stays 200; alternate carrier shapes also OOM and exit; no RCE | runtime |
| 8.4.27 (`lsphp84 8.4.27-1+trixie`) | V8.3 | 🚫 | fixed control: every probe returns 200, no request-time worker exits or signals, no OOM | runtime |
| 8.5.11 | V8.3 (upstream) | — | no exact local `lsphp` build; upstream `sapi/litespeed/lsapi_main.c` has the same early return, so the expected shape is the same 500/exit, but it was not measured; gap, not a negative | source only |

**Why LSAPI does not reach the destructor.** `lsapi_module_main()` returns `-1`
when `php_request_startup()` fails, so only `php_module_shutdown()` runs and
`main()` returns `-1` (exit 255); `php_request_shutdown()`, where `$_FILES` is
destroyed, is skipped and the poisoned bucket is never destructed. Exit 255 is a
normal failure return, not a crash signal; the server respawns the worker. No
code execution. LSAPI runs its own master/worker tree, so mod_php libphp
addresses and handlers do not apply.

### Distro packages

Tested or package-evidenced rows only, exact package strings.

| Distro / release | Exact package | SAPI | Status | Result / qualifier |
|---|---|---|---|---|
| Debian 13 (trixie) | `8.4.24-1~deb13u1` | mod_php | ✅ | default package, direct Apache mod_php: pure-HTTP 149 half-open pin full chains plus a leak-only run, target-written `uid=33(www-data)` on the first write attempt, no `%P`/`/proc`/gdb/local process control; the earlier capped-pool harness is archived and gone from the execution path; prior multi-worker audit with target-written proofs (blind and pooled series; the pooled series used a worker-count observation); full chain on a cell with no site, config or INI override; package constants `S=main+0xF7398`, `zif_system=0x24cdd0`, `zval_ptr_dtor=0x424ff0`, `PS(id)=ps_globals+0x10`; default nginx blocked |
| Debian 13.7 (trixie) | `8.4.27-1~deb13u1` | mod_php + FPM | 🚫 | changelog names CVE-2026-109618/109619; mod_php priming request 200 with no leak; FPM leak body rejected by the default `post_max_size` (not a valid negative) |
| Debian 12 (bookworm) | `8.2.35-1~deb12u1` | mod_php + FPM | 🚫 | fixed control; priming requests 200, no FPM worker exits; package revision includes the fix |
| Debian 12 (bookworm) | `8.2.32-1~deb12u1` | mod_php + FPM | ❌ | priming parse-OOM 500, second stage 500, FPM workers exit; no leak; crash/DoS only; leak-stage blocker |
| Debian 11.11 (bullseye) | `7.4.33-1+deb11u12` | mod_php + FPM | ❌ | no leak primitive on mod_php; the changelog has no fix entry and the build is not claimed fixed; mod_php priming and second stage return 200; pinned single child no leak; FPM leak body rejected by the default `post_max_size`; 7.4 multipart part cap |
| Ubuntu 25.04 (plucky) | `8.4.5-1ubuntu1.2` | mod_php | ✅ | package-specific; full chain on the WordPress core file; symbol offsets `0x245810`/`0x424fc0`; `fillers=116`; `S=main+0xF7398`; upstream 8.4.5 is inside the verified 8.4.1–8.4.7 range |
| Ubuntu 22.04 LTS | `8.1.2-1ubuntu2.28` | mod_php + FPM | 🚫 | fixed control; priming request 200 with no cookie, second stage 200, no FPM worker exits; package revision carries the branch fix |
| Ubuntu 22.04 LTS | `8.1.2-1ubuntu2` | mod_php + FPM | ❌ | priming parse-OOM 500, second stage 500, FPM workers exit; no leak; crash/DoS only; leak-stage blocker |
| Ubuntu 24.04 LTS | `8.3.6-0maysync1` (release `8.3.6`, pre-update) | mod_php + FPM | ❌ | 109618 Content-Length body: mod_php SIGSEGV from the priming OOM; Apache+FPM returns an empty 200 with a worker exit, no SIGSEGV, next GET 200; no RCE/OOB; crash/DoS only |
| Ubuntu 24.04 LTS | `8.3.6-0ubuntu0.24.04.13` | mod_php + FPM | 🚫 | fixed control; an over-limit chunked body returns 200 `OK` with the length-mismatch warning and no OOM; priming request 200, no FPM worker exits; the fixed write stage was not run |
| Ubuntu 26.04 LTS | `8.5.4-0ubuntu1` (release) | mod_php + FPM | ❌ | same crash/DoS shape as 24.04; a heap leak appears once with no `libphp`/`S` anchor; no ASLR break; no RCE/OOB |
| Ubuntu 26.04 LTS | `8.5.4-0ubuntu1.5` | mod_php + FPM | 🚫 | fixed control; over-limit chunked body returns 200 `OK` with the warning and no OOM; priming request 200, no FPM worker exits |
| Alpine 3.20.10 | `8.3.15-r0` | mod_php (apache2) | ❌ | crash only; priming request 200; a large-part body returns 500 OOM on the pinned single child; no leak, normal cookies; second stage 500 OOM; 8.3 parse-phase OOM only |
| Alpine 3.21.9 | `8.4.27-r0` | mod_php (apache2) | 🚫 | fixed by version; priming and second stage 200, no leak |
| Arch Linux rolling | `8.5.12-1`; `php-legacy 8.3.36-1` | mod_php | 🚫 | fixed metadata only: repos ship 8.5.12/8.3.36 and no 8.4.26; no local image or rootfs, so not package-tested; no Arch package chain |
| `php:8.4.26-apache` + Arch INI (not a package) | Arch `php.ini` on the official image | mod_php | ✅ | INI-compatibility test, not an Arch package result and not an Arch RCE; already counted in the mod_php table |
| Rocky Linux 9.3 | `8.0.30-8.el9_8.1` | FPM only | ❌ | no mod_php; the leak body is rejected by the default `post_max_size` (invalid negative); priming and second stage 200; multipart part cap |
| AlmaLinux 9.8 | `php-fpm 8.0.30-8.el9_8.1` | FPM only | 🚫 | same package and byte-identical `php.ini` as Rocky 9; no mod_php/`libphp`; priming and second stage 200; leak body blocked by the default `post_max_size` (invalid negative); the 109618 header flood does not grow the Zend heap under FPM, so the first stage is unreachable at default limits; the changelog names both CVEs (Red Hat backport) |
| Amazon Linux 2023.12 | `php8.4-modphp 8.4.26-1.amzn2023.0.1` | mod_php + FPM | ❌ | pre-fix row; 8.4.26 installable only when `modphp`, `fpm` and `common` are pinned together; the default SAPI is FPM (MPM `event`; `libphp.so` loads only under prefork), mod_php measured with a declared prefork fixture; the priming OOM is reproduced at a shifted geometry; no leak on the default or pinned single-child pool, all cookies normal; 109618 reaches the first stage and the second stage was not observed over the sweep; no write stage |
| Amazon Linux 2023.12 | `php8.4-modphp 8.4.27-1.amzn2023.0.1` | mod_php + FPM | 🚫 | fixed control on the same package line and INI; priming and 109618 header-flood requests return 200 with no OOM; FPM second stage 200; behaviorally fixed, the Amazon changelog is version-only |
| Fedora 44 | `php-fpm 8.5.12-1.fc44` | FPM only | 🚫 | no mod_php package or Apache DSO (`php-embedded` `libphp.so` has no `apache2handler`); priming requests 200 with a normal cookie; the leak body is blocked by the default `post_max_size`; 8.5.12 is fixed by version; 109618 not run |

**Default distro PHP 8.4.26 is not supported.** No default repository ships
8.4.26 with prefork mod_php; Oracle and Rocky 8/9/10 ship other 8.2/8.3/8.4
builds, mostly FPM-only, and FreeBSD defaults to 8.4.27/8.5.12. No tested distro
8.4.26 package gave a full-chain RCE on the upstream geometry. The only proven
distro full-chain positives are Debian 13 `8.4.24-1~deb13u1` and Ubuntu 25.04
`8.4.5-1ubuntu1.2` (rows above). Only a custom source build of 8.4.26 is a
candidate, unverified.

Debian-family geometry differs from upstream: `fillers=116` and
`S=main+0xF7398` (upstream `fillers=115`, `S=main+0xF8398`), and the symbol
offsets move per build. Do not transplant offsets between builds.

The large leak body is gated by `post_max_size` when a length is supplied, so
FPM leak results on Debian 11.11/13.7, Rocky 9.3, Amazon 8.4.26, Fedora 44 and
Alma 9.8 are transport-gated, not valid negatives. The same gate and the 7.4/8.0
part cap (`Multipart body parts limit exceeded 1020`) truncate the 8.4 reference
geometry, so prior 7.4/8.0 leak negatives are invalid; Debian 11 `7.4.33` remains
a no-primitive result for that geometry, not evidence that 7.4 is fixed.

Amazon 8.4.26 is first-stage only, with no leak on the default or a pinned
single-child pool, so no write stage. Fedora 44 8.5.12 is fixed by version, and
the Alma/Rocky EL9 package carries the Red Hat backport. No tested distro 8.4.26
package reached a full-chain RCE on the upstream geometry. The only proven
distro full-chain positives are Debian 13 `8.4.24-1~deb13u1` and Ubuntu 25.04
`8.4.5-1ubuntu1.2` (rows above). The vulnerable 8.4-derived rows range from
crash/DoS to first-stage-only or no primitive, and a build-specific leak offset
cannot be excluded there. A same-run official 8.4.26 control (php.ini-production;
image ships none) reproduced the full chain.

### WordPress 7.1.3 + Apache prefork mod_php

Direct-Apache cells on a real WordPress 7.1.3 tree: Debian 13.7 Apache 2.4.69
prefork mod_php 8.4.24 (earlier audit plus the pure-HTTP pin), Sury PHP 8.0.28 on
Ubuntu 22.04 Apache 2.4.52 prefork, and official `php:8.4.26-apache`
(php.ini-production; image ships none), all default config. All use the core
silence file and write the proof as the Apache user; none extends to nginx or
FPM.

Sury 8.0.28 runs on Ubuntu 22.04 with
`libapache2-mod-php8.0 1:8.0.28-1+ubuntu22.04.1+deb.sury.org+1` and
`apache2 2.4.52-1ubuntu4.25`; the package `php.ini` is unchanged
(`display_errors=Off`, upload progress on with cleanup,
`session.use_strict_mode=0`), ASLR is on, and the pool is the default 150-worker
prefork. Held connections pin one child, which serves the whole chain
and writes the proof; `zif_passthru` is used because `zif_system` crashes the
worker in `php_exec`. The endpoint is `/wp-content/index.php`; no plugin was
added, core has no executable `session_start()`, and the pre-script
upload-progress handler starts the session. The docroot is read-only; the
harness adds only a holder script and a writable proof path.

Official `php:8.4.26-apache` (php.ini-production; image ships none) with pristine
WordPress 7.1.3, Apache 2.4.69 prefork and the default 150-worker pool:
parked header-only connections leave one free child; priming and leak run on the
same child, then second priming and write run on a fresh child that crashes after
writing the proof. The write stage calls `zif_system`. The same sequence
reproduced on a plain PHP file under the same docroot, so the endpoint is not the
differentiator; default nginx rejects the leak body.

| Condition | Audited value |
|---|---|
| OS / package | Debian 13.7 (trixie); `libapache2-mod-php8.4 8.4.24-1~deb13u1`; `apache2 2.4.69-1~deb13u1` |
| SAPI | `mpm_prefork_module` + `php_module` (mod_php); no FPM, no proxy |
| MPM | default `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0`; no config-level worker pinning, no custom MPM, no `mod_unique_id`, no restart or kill; the pure-HTTP pin uses 149 header-only POST holders |
| php.ini | default package conffile, `dpkg -V` clean: `post_max_size=8M`, `memory_limit=128M`, `display_errors=Off`, `output_buffering=4096`, `expose_php=Off`, `upload_max_filesize=2M` |
| ASLR | `randomize_va_space=2` |
| Endpoint | `/wp-content/index.php`, official core silence file, mode 644; SHA-256 `bd48c24ce4500e60d2524571756787283f0d3fbfa50b116331309c09773f0cd1` |
| Docroot | official WordPress 7.1.3 ZIP with the inactive bundled plugins absent, plus a default `wp-config.php` byte-identical to `wp-config-sample.php`; no uploads, no mu-plugins, no `.htaccess`, no `.user.ini`, no lab endpoints; mounted read-only |
| Integrity | pre/post manifest identical; `docker diff` clean under `/var/www/html`; a read-only `touch` fails; target hash unchanged |

The endpoint is a standalone silence file that loads no `wp-config.php`, plugins
or themes, so these are SAPI/heap results on an official core file, not an
app-level WordPress RCE.

**Request stages.** Priming and leak are chunked (`Transfer-Encoding: chunked`,
no `Content-Length`); second priming and write are plain. `post_max_size` is
driven by a declared length: the same body with a declared length returns 200 and
logs `POST Content-Length ... exceeds the limit`, while the chunked leak reaches
PHP, so the INI is not raised.

**Pure-HTTP pin.** The held sockets use no `%P`, `/proc`, gdb, local process
control or fresh-child swap. A leak-only run reproduced; default nginx rejects
the leak body with 413 and its buffering re-arms `post_max_size`.

**Target-written proofs.** Each proof path contains `uid=33(www-data)` and a
marker; the proof-writing child dies with SIGSEGV and the client sees status 0.
No 200/500, OOM or crash is counted as RCE.

**Rate caveat.** The chain needs priming and leak on the same child. Un-pinned
multi-worker audits were stochastic and low-rate; the pooled series used a
worker-count observation and is not quoted as a blind rate. The pure-HTTP pin
removes that lottery.

**Scope.** Direct Apache mod_php only; default nginx/FPM and MediaWiki remain ❌
or gaps. No application LFI or upload, the docroot is never written; `p2s` is a
logging-only `LogFormat`, not part of the exploit path.

### Applications

| App / version | PHP + SAPI | Endpoint / config | Status | Class / qualifier |
|---|---|---|---|---|
| WordPress 7.1.3 | Ubuntu 22.04 Apache 2.4.52 prefork + Sury mod_php 8.0.28 | `/wp-content/index.php` core silence file; default 150-worker pool | ✅ | all default config; target-written `uid`; WordPress not bootstrapped; no plugin; direct mod_php |
| WordPress 7.1.3 | Apache 2.4.69 prefork + mod_php 8.4.24 (Debian 13.7 `8.4.24-1~deb13u1`) | default prefork; `/wp-content/index.php` core file; official docroot, read-only | ✅ | all default config; core silence file; WordPress not bootstrapped; direct mod_php; target-written proofs; pure-HTTP pin; blind and pooled series (the pooled series used a worker-count observation) |
| WordPress 7.1.3 | 8.4.26 official mod_php (php.ini-production; image ships none) | `/wp-content/index.php` core file; default 150-worker pool | ✅ | all default config; engine-level; target-written `uid`; also reproduced on a plain PHP file under the same docroot |
| WordPress 7.1.3 | Apache 2.4.69 prefork + mod_php 8.4.27 | `/wp-content/index.php` core file, read-only | 🚫 | fixed upstream; priming request 200 with no OOM; no leak; write stage unreachable |
| WordPress 7.1.3 | 8.4.26 nginx+mod_php (non-default) | `/index.php` front controller | — | engine-level OOB; no execution claimed; pre-app (WordPress not installed, `mysqli` missing), HTTP 500 |
| WordPress 7.1.3 | 8.4.26 nginx+mod_php (non-default) | `/wp-content/index.php` | — | engine-level OOB; no execution claimed; larger body cap (non-default); repeated OOB |
| WordPress 7.1.3 | 8.4.26 FPM | `/index.php` | ❌ | multipart OOM only |
| WordPress 7.1.3 | 8.5.11 FPM | `/index.php` | ❌ | OOM only |
| WordPress 7.1.3 | 8.3.35 FPM | `/index.php` | ❌ | OOM only; the 8.3.35 mod_php result does not extend to FPM |
| Roundcube 1.7.5 | 8.4.26 FPM | default DB sessions (`session_storage=db`); nginx caps | ❌ | no chain; DB sessions kept separate from the file-session row; `/static.php` allowlisted but still enters PHP; `PHPSESSID` POST ignored; the priming request exits the worker and leaves no session file; no leak; larger caps still no leak |
| Roundcube 1.7.5 | 8.4.26 nginx+FPM | explicit file sessions (`session_storage=php`) | ❌ | app session exists; priming adds an upload-progress key; the `PHPSESSID` variant merges progress and app keys; leak and write stages return normal pages, including a large static asset; no leak, no auth bypass; leak-stage blocker |
| Nextcloud 35.0.2 | 8.4.26 FPM | documented memory stacks | ❌ | no chain; the larger documented stack removes the OOM; the smaller stack exits the worker and leaves no session file; no leak |
| Drupal 11.4.11 | 8.5.10 FPM (local build) | file sessions + `.user.ini` + lowered limits + static worker | ✅ | app-assisted, not all default config; repeated fresh-ASLR chains |
| Drupal 11.4.11 | 8.4.26 FPM | larger memory limit; default DB sessions | ❌ | no chain; priming exits the worker and leaves no session file; no leak |
| Drupal 10.6.20 | 8.4.26 nginx+FPM | native PHP files | ❌ | no `sessions` table; login writes a native session file; priming and second stage exit the worker once nginx admits them; leak and write stages return normal pages; no leak, no auth bypass; leak-stage blocker |
| Drupal 10.6.20 | 8.3.26 nginx+FPM | native PHP files | ❌ | same priming/second-stage worker exits; no leak; leak-stage blocker |
| Drupal 10.6.20 | 8.4.27 nginx+FPM | native PHP files | 🚫 | fixed control: every stage 200; no OOM, no worker exit, no leak; session file intact |
| Joomla 5.4.10 | 8.5.10 FPM (local build) | file sessions + lowered limits + `cleanup=0` | ✅ | app-assisted, not all default config |
| MediaWiki 1.46.2 | 8.4.26 FPM | `/index.php` | ❌ | OOM only |
| MediaWiki 1.46.2 | 8.5.11 FPM | `/index.php` | ❌ | OOM only |
| MediaWiki 1.46.2 | 8.3.35 FPM | `/index.php` | ❌ | OOM only |
| Moodle 5.0.10 | 8.5.11 FPM | normal request | ❌ | fresh serializer at RINIT |

No authentication bypass was observed: a Drupal wrong password returned the login
page with no redirect or cookie, a valid Drupal login survived the full sequence,
and Roundcube rejected wrong logins with and without a valid CSRF token. 8.4.27
returned 200 for all stages with no OOM or worker exit; disabling
`session.upload_progress` on 8.4.26 moved the priming failure to an app-level 500
with the worker alive, but the second stage still exited the worker and no leak
appeared. The app rows show reachability and availability failures, not memory
corruption.

**Drupal 10.6 file-session root cause.**
`Drupal\Core\Session\SessionHandler` extends `AbstractProxy`, which Symfony does
not wrap, so native `files` stays active and the SQLite database has no `sessions`
table; Drupal 11.4.11 extends `AbstractSessionHandler` and uses the DB.

**Body-limit boundary.** The matrix is complete except one diagnostic case sent
to the wrong document root (excluded); Roundcube on 8.4.27 was untested.

| Stage | Default one-megabyte cap | Mid cap | Large cap |
|---|---|---|---|
| Priming | rejected | worker exits | worker exits (8.4.27: 200) |
| Second priming | worker exits | worker exits | worker exits (8.4.27: 200) |
| Leak | rejected | rejected | normal response |
| Write | normal | normal | normal |

The default cap blocks the priming and leak stages only; the second priming and
write stages fit and still exercise the engine. A mid cap admits everything
except the leak; only the large cap admits all four.

### Other CVEs

| CVE | Builds | Config | Status | Class / result |
|---|---|---|---|---|
| CVE-2026-115560 | 8.4.26 / 8.5.11; mod_php + FPM | `cleanup=0`, app gadget, `php_binary`/`php_serialize` to `php` (non-default) | ✅ | app-gadget RCE; no memory corruption; sanitizer clean |
| CVE-2026-115560 | default `cleanup=1` | default | ❌ | poisoned record deleted before app code |
| CVE-2026-115560 | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | `cleanup=0` (non-default) | ✅ | still reproduces; the 109618/109619 fixes do not address this CVE |
| CVE-2026-6722 | 8.4.20 / 8.5.5; SOAP | mod_php | ❌ | unauthenticated remote DoS, no RCE; handlers call the primitive, no ASLR bypass |
| CVE-2026-6722 | 8.4.21 / 8.5.6 | mod_php | 🚫 | fixed |
| CVE-2019-11043 | 7.1.32 / 7.2.23 / 7.3.10; FPM | nginx with path-info routing (non-default) | ✅ | config-induced RCE |
| CVE-2019-11043 | same | default Debian/WordPress/MediaWiki config | ❌ | blocked |
| CVE-2019-11043 | 7.1.33 / 7.2.24 / 7.3.11; FPM | fixed | 🚫 | fixed |

**Third-party 8.3.35 claim — failed verification.**
`Percivalll/php2shell-wordpress-rce` is an original, non-malicious third-party
repository. Its exact chain was reimplemented on the default
`php:8.3.35-apache` image: no RCE, no marker, no `uid`. The stale-session OOB read
is real with our own priming/leak pair and the libphp base is recoverable, but the
claimed chain fails at its priming geometry, forged header, unvalidated chunk
offset and missing controlled base; the small-leak nginx bypass remains
unverified. The 8.3.35 ✅ row is our chain. Repository claim: ❌ tested, not
reproduced.

### Coverage gaps

Every row is — (no qualifying RCE in that cell), never ❌.

| ID | Status | Lane | Untested cell | Existing evidence / note | Priority |
|---|---|---|---|---|---|
| G01 | — | Distro | Debian 12 `8.2.32` + mod_php (other 8.2.x untested) | tested ❌; priming and second stage parse-OOM, no leak; blocker, not an offset miss | P0 |
| G02 | — | Distro | Debian 12 `8.2.x` + FPM | 8.2.32 FPM: both priming shapes exit the worker, no leak; other 8.2.x untested | P0 |
| G03 | — | Distro | Debian 13 `8.4.24-1~deb13u1` + FPM | mod_php tested, including the default multi-worker WordPress cell; FPM not run | P1 |
| G04 | — | Distro | Ubuntu 20.04 `7.4.3` + mod_php | upstream 7.4.33 | P2 |
| G05 | — | Distro | Ubuntu 20.04 `7.4.3` + FPM | upstream 7.4.33 | P2 |
| G06 | — | Distro | Ubuntu 22.04 pre-update `8.1.2` + mod_php | tested ❌; priming and second stage parse-OOM, no leak; fixed in the later package revision | P0 |
| G07 | — | Distro | Ubuntu 22.04 `8.1.2` + FPM | base FPM: both priming shapes exit the worker, no leak; fixed in the later revision | P0 |
| G08 | — | Distro | Rocky Linux 9.3 `8.0.30-8.el9_8.1` FPM only | tested ❌; no mod_php/`libphp`; priming and second stage 200; the leak body is rejected by the default `post_max_size`, so it is not a valid leak negative | P1 |
| G09 | — | Distro | FPM leak stage on Debian 11.11/13.7, Rocky 9.3, Amazon 2023.12, Fedora 44 and Alma 9.8 | the large body is rejected by the default `post_max_size` before session code; priming-only, not a valid leak negative; needs a smaller leak body or a declared larger limit | P1 |
| G10 | — | Distro | PHP 7.4/8.0 leak negatives (Debian 11, Rocky 9.3) | the multipart part cap truncates the 8.4 reference priming geometry, so prior leak negatives for those builds are invalid; the official-image 7.4.33/8.0.29/8.0.30 cells use the 8.0-geometry priming body and do not validate the distro packages | P0 |
| G11 | — | Distro | Debian 11 `7.4.33` sub-cap priming tuning | a smaller body returned 200 with no OOM; no 7.4-specific priming geometry was searched; no claim of 7.4 safety | P1 |
| G12 | — | Distro | Arch Linux rolling `8.5.12-1` / `php-legacy 8.3.36-1` | fixed metadata only; no local image or rootfs; repos ship 8.5.12/8.3.36 and no 8.4.26; the Arch-INI transplant is not an Arch package result; not package-tested | P2 |
| G13 | — | Distro | Alpine edge | fixed metadata only (8.4.27/8.5.12/8.3.36); no native install or chain test | P3 |
| G14 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` priming onset | onset falls between two neighbouring big-value part counts; the boundary was not bisected | P1 |
| G15 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` leak read spec | no leak on the default pool or on a pinned single-child pool with the 8.4-derived geometry; no write stage | P1 |
| G16 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` second stage and write stage | the second stage was sent on FPM only; the write stage is unreachable without a leak | P1 |
| G17 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` 109618 second band | the first stage is reached; the second band was not observed across the sweep, with no SIGSEGV/AH00052 | P1 |
| G18 | — | Distro | Amazon Linux 2023.12 `php8.3.36` / `8.5.12` live | repo version/file-list metadata only; no chain test | P3 |
| G19 | — | Distro | Fedora 44 `php-fpm 8.5.12-1.fc44` 109618 producer | fixed build, not exercised; priming and second stage 200; the leak body is gated | P3 |
| G20 | — | Distro | write stage on any distro package | needs a leak plus per-build offsets; no write stage attempted on Amazon/Fedora/Alma | P1 |
| G21 | — | Build | FPM `8.2.35` fixed control | runtime: priming requests 200, no worker exits; no qualifying RCE | P0 |
| G22 | — | Build | FPM `8.4.27` fixed control | source only | P1 |
| G23 | — | Build | mod_php `8.4.9` | absent upstream: no release, official image or ChangeLog entry; only an abandoned pre-publication tarball; not a vulnerable or fixed cell | P2 |
| G24 | — | Build | mod_php `8.4.0` | absent upstream: no release, official image or ChangeLog entry; only an abandoned pre-publication tarball; not a vulnerable or fixed cell | P2 |
| G26 | — | Build | 5.6.0 / 7.0.0 / 7.1.0 runtime | tips only | P3 |
| G27 | — | SAPI/OS | nginx+mod_php `8.4.10` | mod_php warm chain | P2 |
| G28 | — | SAPI/OS | nginx+mod_php `8.4.20` | mod_php warm chain | P2 |
| G29 | — | SAPI/OS | nginx+mod_php `8.5.11` | mod_php leak only | P2 |
| G30 | — | SAPI/OS | direct FastCGI full chain `8.4.26` / `8.5.11` | framing tests only | P3 |
| G31 | — | SAPI/OS | FreeBSD 13/14 + Apache + mod_php (ports) | prior inspection found no default 8.4.26 with mod_php and prefork; default 8.4.27/8.5.12 are fixed; a custom old 8.4.26 ports candidate was not proven and produced no target-written proof; not supported/not proven | P2 |
| G32 | — | SAPI/OS | FreeBSD 13/14 + nginx + FPM (ports) | build-specific offsets; no target-written proof; not proven | P2 |
| G33 | — | SAPI/OS | Windows Server + IIS 10 + FastCGI | no Windows host; no supported default-config RCE; the reviewed `p2s-win-test` is a Linux mod_php bundle, not a Windows path; CVE-2024-4577 (Windows CGI BestFit) is patched; not claimed | P2 |
| G34 | — | SAPI/OS | Windows + Apache + mod_php | no Windows host; no supported default-config RCE; not claimed | P3 |
| G35 | — | App | WordPress 7.1.3 installed with `mysqli`/DB | the core-file cell is tested; the installed `/index.php` front controller is pre-app; the tree was not installed | P1 |
| G36 | — | App | WordPress 7.1.3 nginx+FPM full chain | only FPM OOM and worker exits; FPM exits the worker 70 on a failed `php_request_startup()`, and the default nginx cap and `post_max_size` gate both stages; no default nginx+FPM chain | P1 |
| G37 | — | App | WordPress 7.1.3 mod_php 8.3.35 / 8.5.11 | 8.3.35 tested engine-level on the core file; 8.5.11 untested | P2 |
| G38 | — | App | Drupal 11.4.11 default DB sessions | tested ❌ on 8.4.26 FPM; worker exit, no leak; Drupal 10.6 file-session rows are in Applications | P1 |
| G39 | — | App | Joomla 5.4.10 default DB sessions | file-session variant only | P1 |
| G40 | — | App | Joomla 6.2.0 | none | P2 |
| G41 | — | App | MediaWiki 1.46.2 mod_php / other FPM | FPM OOM only | P2 |
| G42 | — | App | Laravel 13 | none | P1 |
| G43 | — | App | Symfony 8.1 | none | P1 |
| G44 | — | App | Roundcube 1.7.4 | 1.7.5 tested ❌ (default DB and explicit file sessions, no leak); 1.7.4 not run | P0 |
| G45 | — | App | Nextcloud 35 | 35.0.2 tested ❌; other versions untested | P1 |
| G46 | — | App | phpMyAdmin 5.2.3 | none | P2 |
| G47 | — | App | Magento 2.4.9 | optional | P3 |
| G48 | — | App | OpenCart 4.x | optional; version unverified | P3 |
| G49 | — | App | Laravel 12 / Symfony 7.x/6.4 / Nextcloud 34/33 | secondary versions | P3 |
| G50 | — | SAPI/OS | OpenLiteSpeed 1.9.3 + lsphp `8.5.11` (LSAPI) | no exact local `lsphp` build or LSAPI-specific trigger; upstream `sapi/litespeed/lsapi_main.c` has the same early return at `php_request_startup()` failure, so the expected shape is 500/exit, not a shutdown crash; not measured; —, not ❌ | P1 |
| G51 | — | App | WordPress 7.1.3 + `php:8.4.26-apache` default multi-worker | 8.4.26 only; the core-file question is resolved by the WordPress 8.4.26 run; WordPress is not bootstrapped, so a full WordPress-bootstrap cell remains untested; no claim for other builds | P1 |

Tested WordPress-on-Apache cells are no longer gaps; remaining items are G35,
G36, G37 and G51 (the 8.4.26 bootstrap sub-question). G25 was retired after the
8.1.34 mod_php test, so its absence from the table is not an omission.

**Closed lanes.** For the official-image FPM rows, the default body-cap/exit-70
lane and the fixed-lifecycle logic lane are closed negatives, not open coverage.

**Windows and BSD — not supported / not proven.** Windows has no default-config
RCE; `p2s-win-test` is a Linux mod_php bundle, not a Windows path, and
CVE-2024-4577 is patched. FreeBSD 13/14 + Apache: no default 8.4.26 with prefork
mod_php, default 8.4.27/8.5.12 are fixed, and a custom old 8.4.26 ports candidate
was not proven. OpenBSD and NetBSD were untested.

No receipts or binaries are shipped; target-written proofs are session-recorded.
The repository ships only the tool, its offset profiles and the documentation
files listed in Layout.

## Layout

| path | contents |
|---|---|
| `tool/php2shell.py` | chain driver (`recon`, `producer`, `write_stage`, `leak`, `g2`, `chain`) |
| `tool/debian8424.py` | standalone Debian 13 `libapache2-mod-php8.4` 8.4.24 four-stage runner (priming, leak, second priming, write); dry by default |
| `tool/phpcheck.py` | passive PHP version/build CVE candidate checker; no exploit traffic |
| `tool/run` | POSIX shell wrapper: `./tool/run --help` |
| `tool/modules/` | request/producer builders, chain stages, per-build profiles (see `tool/modules/README.md`) |
| `tool/stages/` | fingerprint and probe stage |
| `addresses/` | per-build offset profiles loaded by `g2_chain.py` and `leak_stage.py` |
| `README.md` | this document |
| `STATUS.md` | historical research-status snapshot (provenance; not the current matrix) |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | third-party code, PoC and shape-note notices (full text) |
| `requirements.txt` | dependency note: standard library only, Python 3.10+ |
| `LICENSE` | AGPL-3.0 license text |

`addresses/g2_fpm_*.json` are runtime inputs for `--step g2` and
`addresses/apache_libphp.json` for `--step leak`; without them those steps cannot
resolve a build.

## Requirements

- Python 3.10 or newer, standard library only (PEP 604 unions in `php2shell.py`).
- A POSIX shell for `tool/run`.

Nothing to install.

## Usage

```sh
./tool/run --help
./tool/run --target wiki --step recon
./tool/run --target wp --step producer
./tool/run --target modphp --step chain --url http://127.0.0.1/ --command id
./tool/run --step g2 --g2-profile 8.5.10 --g2-decode zif_system --g2-x 0x7f0000000000 --g2-x2 0x7f0000001000 --g2-p 0x7f0000002000 --g2-b0 0x7f0000003000
```

Steps: `recon` (read-only receipt), `producer` (send a payload), `write_stage`
(build the forged multipart, no send), `leak` (mod_php calibration plan), `g2`
(offline FPM record plan), `chain` (mod_php ordered chain; FPM uses blocker-hold,
rearm and forged staged multipart). Constants live in `tool/modules/profiles.py`;
receipts go to `files/io/` and are git-ignored.

### Debian 13 mod_php 8.4.24 four-stage runner

`tool/debian8424.py` is a separate runner for the exact package
`libapache2-mod-php8.4 8.4.24-1~deb13u1`; it is not a `--profile` entry and does
not change `--step chain`. It targets prefork mod_php with default
`output_buffering` and a small PHP probe endpoint, and the package must match
because constants are build-specific.

Dry-run is the default; `--live` sends the four-stage sequence and the bodies are
hash-checked before sending. Success is reported only when the marker is seen
through `--callback`/`--callback-log`, `--proof-file` or `--error-log`; an HTTP
200/500 alone is not success. The leak stage is probabilistic and the write-stage
command must fit the carrier.

```sh
python3 -m tool.debian8424 --url http://127.0.0.1:8080/ --dry-run
python3 -m tool.debian8424 --url http://127.0.0.1:8080/ --command id --lhost 127.0.0.1 --lport 9001 --timeout 180 --output files/io/debian8424-run1 --live
```

### Passive version/build checker

`tool/phpcheck.py` maps a PHP version (optionally with a distro package revision)
and SAPI to CVE-2026-109618/109619 candidate status. It sends no exploit
traffic: offline without `--url`, and `--url` performs one unauthenticated GET
and reads response headers only. Requires Python 3.10 or newer.

```sh
python3 tool/phpcheck.py --version 8.4.24 --sapi mod_php
python3 tool/phpcheck.py --package 'libapache2-mod-php8.4=8.4.24-1~deb13u1' --distro debian13 --sapi mod_php --json
python3 tool/phpcheck.py --list-cves
```

`VULNERABLE-CANDIDATE` is a lead, not proof: pass `--package`/`--distro` for
build identity and verify the listed conditions.

## Scope and authorization

Use only against systems you own or are explicitly authorized to test. The tool
sends malformed multipart bodies that can crash or exhaust PHP workers by design.

## License

AGPL-3.0; see `LICENSE`.

## Third-party code and references

This section is a summary; [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) is the
full notice and records the upstream files, commits and available license terms.

- `tool/modules/producer_flood.py` — the multipart framing and flood arms are taken from `WoYinDao/CVE-2026-109618-CVSS-9.2-Critical`, `tools/exploit_128m.py`, commit `a127f77009ca` (snapshot `99da6fb7dd7ecd4a95cd7188d77bb7e7785012eb`), MIT, Copyright (c) 2026 WoYinDao.
- `tool/modules/producer_618.py` and `tool/modules/producer_619.py` — the CVE-2026-109618/109619 staged producers are taken from `poc0_109618.py` / `poc1_109619.py` in the PHP-UP-2026 bundle by J4ck3LSyN (PoCs by Andrew Dorman / @acd421), <https://jackalsyn.com/posts/php-up-2026.html>, mirror `cereZ23/php-up-2026` commit `c63f145596dbe9cdd437d24ed2418f0c1e59bcc2`. The bundle has no open-source license and is defensive-research/scoped-engagement only; AGPL-3.0 does not relicense those two builders; see `THIRD_PARTY_NOTICES.md`.
- The two reconstructed shape modules in `tool/modules/` — built from Zer061 / PHP-UP-2026 shape notes (repository removed; Wayback snapshot recorded in `THIRD_PARTY_NOTICES.md`); no verbatim code.
- `tool/debian8424.py` 8.4.24 stage layout — follows `9bie/php2shell-bypass-aslr-exp`; the bodies, geometry and offsets are local measurements; code-level reuse is unresolved and no license is asserted.
- Reviewed but not incorporated — `ACD421/PHP` (the repository itself; the acd421 PoCs are credited above), `offline-ant/php2fix`, `Percivalll/php2shell-wordpress-rce`, `kengwang/php2shell-fpm-exp`; `php-src` and the security advisories are used as facts only.
- References — GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, <https://calif.io/php2shell/>.

Not all code here is AGPL-3.0: the original code is offered under AGPL-3.0
(`LICENSE`), while the PHP-UP-2026-derived builders are not relicensed by it and
carry their own upstream terms. The MIT notice for `producer_flood.py` is
retained in `THIRD_PARTY_NOTICES.md`.
