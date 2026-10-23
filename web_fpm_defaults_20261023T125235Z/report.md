# Web-server and PHP-FPM defaults — configuration/source audit

**Date:** 2026-10-23 (UTC)
**Scope:** shipped defaults for Apache (Debian/Ubuntu, RHEL/Rocky/Alma, Alpine, Arch, official
`php:*-apache` images), nginx (upstream, Debian/Ubuntu packaged, `nginx:alpine`, WordPress and
MediaWiki recommended configs) and packaged PHP-FPM (`php-fpm.conf`, `pool.d/www.conf`).
**Method:** read-only configuration and package-source audit. No exploit was run for this report.
**Outputs:** `report.md`, `matrix_apache.csv`, `matrix_fpm.csv`, `matrix_nginx.csv`, `matrix.md`,
`evidence/` (config excerpts, package SHA-256, image runtime dumps).

---

## 0. Bottom line

1. **Debian/Ubuntu Apache defaults to `event`.** The `apache2` postinst runs
   `a2enmod -m -q mpm_event` on a fresh install. Shipped `mpm_event.conf`:
   StartServers 2, MinSpareThreads 25, MaxSpareThreads 75, ThreadLimit 64,
   ThreadsPerChild 25, MaxRequestWorkers 150, MaxConnectionsPerChild 0.
   The prefork block (used when `libapache2-mod-phpX` is installed, whose postinst
   switches MPM to prefork) is 5/5/10/150/0.
2. **RHEL-family defaults to `event` and ships no MPM tuning.** RHEL/Rocky/Alma 8 and 9
   `00-mpm.conf` load only `mpm_event_module`; `httpd.conf` contains no
   `StartServers`/`MaxRequestWorkers` directives, so the compiled defaults apply:
   3 processes / 75 min-spare threads / 250 max-spare / 25 threads per child /
   400 MaxRequestWorkers / 0 MaxConnectionsPerChild. On RHEL 8 `mod_php` is shipped in
   the `php` RPM but is loaded only under `<IfModule prefork.c>`; with the default event
   MPM it is **not** loaded and `php.conf` routes PHP to
   `proxy:unix:/run/php-fpm/www.sock`. RHEL 9's `php` 8.0.30 RPM is a
   metapackage with an empty (44-byte cpio) payload; PHP integration is shipped by
   `php-fpm`.
3. **Alpine Apache defaults to prefork** (5/5/10/**250**/0, not upstream 256), with
   `mod_php83.so` available via `php83-apache2`. **Arch defaults to event**
   (3/75/250/25/400/0) with a prefork block of 5/5/10/**250**/0; `php-apache` ships
   `libphp.so` but its `php_module.conf` is not included by default. **Official
   `php:*-apache` images run prefork** (5/5/10/150/0) with `libphp.so`.
4. **nginx upstream defaults:** `client_max_body_size 1m` (1 MiB),
   `fastcgi_request_buffering on`, no default `fastcgi_split_path_info`, no default
   `try_files`, and `conf/fastcgi_params` contains **neither** `PATH_INFO` **nor**
   `SCRIPT_FILENAME`.
5. **Debian/Ubuntu nginx:** the packaged `snippets/fastcgi-php.conf` does split the URI
   and forwards `PATH_INFO $path_info`, but it first gates with
   `try_files $fastcgi_script_name =404;`. The packaged default site has the PHP block
   commented out and sets neither `client_max_body_size` nor
   `fastcgi_request_buffering` (so 1m / on apply).
6. **PHP-FPM packaged pools differ materially.** Debian/Ubuntu: `dynamic`,
   5/2/1/3, Unix socket, `www-data`, `clear_env` yes, `security.limit_extensions`
   `.php .phar`, `catch_workers_output` no, `listen.backlog` -1 (SOMAXCONN).
   RHEL family: 50/5/5/35, `/run/php-fpm/www.sock`, user `apache`,
   `listen.acl_users = apache,nginx`. Alpine: user `nobody`,
   `listen = 127.0.0.1:9000` (TCP, not a socket). Arch: user `http`,
   `/run/php-fpm/php-fpm.sock`. Official `php:*-fpm`: `www-data`, TCP `9000` (all
   interfaces), `clear_env = no`, `catch_workers_output = yes`,
   `decorate_workers_output = no`, and **no `php.ini` loaded**.
7. **`cgi.fix_pathinfo` is 1 everywhere by default.** Every audited `php.ini` ships
   `;cgi.fix_pathinfo=1` (commented), and the official images load no `php.ini` at all,
   so the compiled default 1 applies.
8. **CVE-2019-11043 is configuration-dependent.** Existing lab evidence
   (`/tmp/opencode/research/fpm_11043_targets_20261023T085412Z/`) shows the stock Debian 10
   PHP 7.3.9 package is vulnerable, but the stock Debian nginx default (with the shipped
   snippet), the WordPress recommended config and the MediaWiki recommended config were
   **not exploitable as published** — `try_files`, absent `PATH_INFO`, and an anchored
   location/404 fallback respectively block the trigger.
9. **FPM 109618/109619:** existing lab evidence
   (`/tmp/opencode/research/fpm_109619_20261023T010421Z/`) reports a measured negative
   against stock nginx + FPM: 1 MiB nginx body cap and `post_max_size=8M` reject the
   known bodies, startup failure exits the worker with code 70, and stock nginx shows no
   upstream affinity. The default values that matter are listed in §7.

---

## 1. Method and provenance

### 1.1 What was inspected

Packages were downloaded from the distribution archives and unpacked with
`dpkg-deb -x` (Debian/Ubuntu), `bsdtar` (RPM/Arch) or `tar` (Alpine APK). No package was
installed on the host and no service was started from these files. Runtime checks were
done with `docker run --rm` on images already present locally (`php:8.3.35-apache`,
`php:8.4.26-apache`, `php:8.5.12-apache`, `php:8.4.26-fpm`, `nginx:alpine`); no existing
container was touched.

| Family | Source | Exact package versions |
|---|---|---|
| Debian 13 (trixie) | `deb.debian.org/debian` | `apache2 2.4.68-1~deb13u1`, `nginx-common 1.26.3-3+deb13u7`, `php8.4-fpm 8.4.24-1~deb13u1`, `php8.4-common 8.4.24-1~deb13u1`, `libapache2-mod-php8.4 8.4.24-1~deb13u1` |
| Debian 12 (bookworm) | `deb.debian.org/debian` | `apache2 2.4.68-1~deb12u1`, `nginx-common 1.22.1-9+deb12u9`, `php8.2-fpm 8.2.32-1~deb12u1` |
| Ubuntu 22.04 (jammy) | `archive.ubuntu.com/ubuntu` | `apache2 2.4.52-1ubuntu4`, `nginx-common 1.18.0-6ubuntu14`, `php8.1-fpm 8.1.2-1ubuntu2` |
| Ubuntu 24.04 (noble) | `archive.ubuntu.com/ubuntu` | `apache2 2.4.58-1ubuntu8`, `nginx-common 1.24.0-2ubuntu7`, `php8.3-fpm 8.3.6-0maysync1` |
| Rocky Linux 8 / AlmaLinux 8 | `dl.rockylinux.org`, `repo.almalinux.org` | `httpd 2.4.37-64.module+el8.10.0+1717+030a9fed`, `php-fpm 7.2.24-1.module+el8.4.0+413+c9202dda`, `php 7.2.24` (mod_php), `php-common 7.2.24` |
| Rocky Linux 9 / AlmaLinux 9 | same | `httpd-core 2.4.62-13.el9` (+ `httpd 2.4.62-13.el9`), `php-fpm 8.0.30-5.el9_7`, `php 8.0.30` (metapackage), `php-common 8.0.30` |
| Alpine 3.22 | `dl-cdn.alpinelinux.org` | `apache2 2.4.69-r0`, `php83-fpm 8.3.36-r0`, `php83-apache2 8.3.36-r0`, `php83-common 8.3.36-r0` |
| Arch Linux (2026-10-23) | `geo.mirror.pkgbuild.com` | `apache 2.4.69-1`, `php 8.5.12-1`, `php-fpm 8.5.12-1`, `php-apache 8.5.12-1` |
| Official images | local Docker images | `php:8.4.26-fpm` (PHP 8.4.26), `php:8.3.35-apache`, `php:8.4.26-apache`, `php:8.5.12-apache` (Apache/2.4.69 Debian), `nginx:alpine` (nginx/1.31.8) |
| Upstream source | GitHub tags | httpd 2.4.62 `server/mpm/{event,prefork}/mpm_default.h`, `server/mpm_common.c`; nginx `release-1.26.3` `ngx_http_core_module.c`, `conf/fastcgi_params`; php-src `php-8.4.26` `sapi/fpm/fpm/{fpm_conf.c,fpm_sockets.h}` |

Rocky and AlmaLinux 8/9 resolve to the same NEVRA for `httpd`, `httpd-core`, `php-fpm`
and `php-common`, so one row covers both. Ubuntu values are from the **release pocket**
(the archive at `dists/<suite>`); `-updates`/`-security` pockets can carry later package
versions, which were not audited.

### 1.2 What was deliberately not done

- No exploit, fuzzing or load test was executed for this report.
- No `apt install`, `dnf install`, `apk add` or service start on the host.
- No existing container was modified; runtime probes used fresh `docker run --rm`.
- No push/commit.

### 1.3 Reading the tables

- **explicit** = directive is present and active in the shipped file.
- **not set ⇒ X** = directive is absent; X is the effective compiled/upstream default.
- **commented** = the template contains the directive only as a comment; the compiled
  default applies.
- `n/a` = the directive does not apply to that MPM.

---

## 2. Apache HTTP Server

### 2.1 How the default MPM is chosen on Debian/Ubuntu

`apache2`'s `DEBIAN/postinst` contains:

```sh
enable_default_mpm()
{
	if is_fresh_install $@ ; then
		a2enmod -m -q mpm_event
	fi
}
```

So a fresh install enables **event**. Installing `libapache2-mod-php8.4` changes it:
the module's postinst (`tmpctrl_modphp/postinst`) checks `a2query -M` and, unless the
MPM is already `prefork`/`itk` or the admin disabled the module, calls
`apache2_switch_mpm prefork`; otherwise it refuses to enable PHP ("Could not switch to
prefork MPM, not enabling PHP 8.4"). `libapache2-mod-php8.2`, `-php8.1` and `-php8.3`
ship the same logic in their respective packages.

### 2.2 Debian 13 / Debian 12 / Ubuntu 22.04 / Ubuntu 24.04

The four families ship identical MPM tuning files:

`/etc/apache2/mods-available/mpm_event.conf`

```apache
StartServers            2
MinSpareThreads         25
MaxSpareThreads         75
ThreadLimit             64
ThreadsPerChild         25
MaxRequestWorkers       150
MaxConnectionsPerChild  0
```

`/etc/apache2/mods-available/mpm_prefork.conf`

```apache
StartServers            5
MinSpareServers         5
MaxSpareServers         10
MaxRequestWorkers       150
MaxConnectionsPerChild  0
```

Note that Debian/Ubuntu lower `MaxRequestWorkers` to **150** in both MPMs (upstream
compiled defaults are 400 for event and 256 for prefork). The `prefork` file is present
but not enabled on a fresh install; it becomes active with `mod_php` (see §2.1).

### 2.3 RHEL / Rocky / AlmaLinux 8 and 9

`/etc/httpd/conf.modules.d/00-mpm.conf` (RHEL 8 and RHEL 9, identical semantics):

```apache
#LoadModule mpm_prefork_module modules/mod_mpm_prefork.so
#LoadModule mpm_worker_module modules/mod_mpm_worker.so
LoadModule mpm_event_module modules/mod_mpm_event.so
```

`/etc/httpd/conf/httpd.conf` contains **no** `StartServers`, `MinSpareThreads`,
`MaxSpareThreads`, `ThreadsPerChild`, `MaxRequestWorkers` or
`MaxConnectionsPerChild` directive (verified by grep on both releases). Therefore the
compiled defaults from httpd 2.4.62 source apply:

- `server/mpm/event/mpm_default.h`: `DEFAULT_START_DAEMON 3`,
  `DEFAULT_MIN_FREE_DAEMON 3`, `DEFAULT_MAX_FREE_DAEMON 10`,
  `DEFAULT_THREADS_PER_CHILD 25`.
- `server/mpm/event/event.c`: `min_spare_threads = DEFAULT_MIN_FREE_DAEMON *
  DEFAULT_THREADS_PER_CHILD` (= 75), `max_spare_threads = DEFAULT_MAX_FREE_DAEMON *
  DEFAULT_THREADS_PER_CHILD` (= 250), `max_workers = active_daemons_limit *
  threads_per_child` (= 16 × 25 = 400).
- `server/mpm_common.c`: `ap_max_requests_per_child = 0` ("unlimited").

The prefork defaults (5/5/10/**256**/0) are compiled in but not used unless an admin
enables `mpm_prefork`.

### 2.4 Alpine 3.22

`/etc/apache2/httpd.conf` loads **prefork**:

```apache
#LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule mpm_prefork_module modules/mod_mpm_prefork.so
#LoadModule mpm_worker_module modules/mod_mpm_worker.so
```

`/etc/apache2/conf.d/mpm.conf` (included via `IncludeOptional /etc/apache2/conf.d/*.conf`):

```apache
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers      250
    MaxConnectionsPerChild   0
</IfModule>
```

Alpine uses **250**, not the upstream 256.

### 2.5 Arch Linux

`/etc/httpd/conf/httpd.conf` loads **event**:

```apache
LoadModule mpm_event_module modules/mod_mpm_event.so
#LoadModule mpm_prefork_module modules/mod_mpm_prefork.so
#LoadModule mpm_worker_module modules/mod_mpm_worker.so
```

`/etc/httpd/conf/extra/httpd-mpm.conf` contains explicit blocks: event
3/75/250/25/400/0 and prefork 5/5/10/**250**/0 (again 250, not 256).

### 2.6 Official `php:*-apache` images

`apache2ctl -V` inside `php:8.3.35-apache`, `php:8.4.26-apache` and
`php:8.5.12-apache` reports `Apache/2.4.69 (Debian)` with **`Server MPM: prefork`**;
`/etc/apache2/mods-enabled/mpm_prefork.conf` is 5/5/10/150/0 and
`/usr/lib/apache2/modules/libphp.so` is present. The images therefore ship the same
prefork profile as a Debian host with `mod_php`.

### 2.7 MPM matrix

See `matrix_apache.csv`. Summary:

| Stack | Default MPM | StartServers | MinSpare | MaxSpare | MaxRequestWorkers | MaxConnPerChild |
|---|---|---|---|---|---|---|
| Debian 12/13, Ubuntu 22.04/24.04 | event | 2 | 25 threads | 75 threads | 150 | 0 |
| same, prefork (mod_php) | prefork | 5 | 5 | 10 | 150 | 0 |
| Rocky/Alma 8, 9 | event (compiled) | 3 | 75 threads | 250 threads | 400 | 0 |
| Alpine 3.22 | prefork | 5 | 5 | 10 | 250 | 0 |
| Arch | event | 3 | 75 threads | 250 threads | 400 | 0 |
| Arch, prefork block | prefork | 5 | 5 | 10 | 250 | 0 |
| php:8.3.35/8.4.26/8.5.12-apache | prefork | 5 | 5 | 10 | 150 | 0 |
| httpd 2.4.62 compiled | event | 3 | 75 threads | 250 threads | 400 | 0 |
| httpd 2.4.62 compiled | prefork | 5 | 5 | 10 | 256 | 0 |

### 2.8 `mod_php` availability

| Distribution | Package | Shipped artifact | Enabled by default? |
|---|---|---|---|
| Debian 12/13, Ubuntu | `libapache2-mod-php8.2/8.3/8.4/8.1` | `/usr/lib/apache2/modules/libphp.so` + `phpX.Y.load/conf` | No; installing it forces prefork |
| RHEL/Rocky/Alma 8 | `php 7.2.24` | `/usr/lib64/httpd/modules/libphp7.so`, `/etc/httpd/conf.modules.d/15-php.conf`, `/etc/httpd/conf.d/php.conf` | No; `15-php.conf` loads it only inside `<IfModule prefork.c>`, default MPM is event |
| RHEL/Rocky/Alma 9 | `php 8.0.30` | **none** (metapackage with an empty payload) | No; `php-fpm` supplies `/etc/httpd/conf.d/php.conf` → `proxy:unix:/run/php-fpm/www.sock` |
| Alpine 3.22 | `php83-apache2 8.3.36-r0` | `/usr/lib/apache2/mod_php83.so`, `/etc/apache2/conf.d/php83-module.conf` | Available, not part of `apache2` |
| Arch | `php-apache 8.5.12-1` | `/usr/lib/httpd/modules/libphp.so`, `/etc/httpd/conf/extra/php_module.conf` | Module not loaded: `httpd.conf` does not include `php_module.conf` |
| Official `php:*-apache` | in image | `libphp.so` | Yes |

RHEL 8 `15-php.conf` is worth quoting because it is the reason the default event MPM
never loads `mod_php`:

```apache
<IfModule !mod_php5.c>
  <IfModule prefork.c>
    LoadModule php7_module modules/libphp7.so
  </IfModule>
</IfModule>
```

With event loaded, `prefork.c` is not present, so the module is skipped and the
`php.conf` `proxy:unix:/run/php-fpm/www.sock|fcgi://localhost` handler serves `.php`.

---

## 3. nginx

### 3.1 Upstream defaults (nginx 1.26.3 source / nginx.org docs)

| Directive | Default | Provenance |
|---|---|---|
| `client_max_body_size` | **1m** (1 MiB) | `src/http/ngx_http_core_module.c:3786-3787` `ngx_conf_merge_off_value(..., 1 * 1024 * 1024)` |
| `fastcgi_request_buffering` | **on** (since 1.7.11) | nginx.org `ngx_http_fastcgi_module` docs: "Default: fastcgi_request_buffering on;" |
| `fastcgi_split_path_info` | none | docs: "Default: —" |
| `try_files` | none | no default value; only acts when configured |
| `fastcgi_param PATH_INFO` | **not set** | `conf/fastcgi_params` (release-1.26.3) contains no `PATH_INFO` line |
| `fastcgi_param SCRIPT_FILENAME` | **not set** in `fastcgi_params` | same file; must be added explicitly or use `fastcgi.conf` |

`conf/fastcgi_params` sets `QUERY_STRING`, `REQUEST_METHOD`, `CONTENT_TYPE`,
`CONTENT_LENGTH`, `SCRIPT_NAME`, `REQUEST_URI`, `DOCUMENT_URI`, `DOCUMENT_ROOT`,
`SERVER_PROTOCOL`, `REQUEST_SCHEME`, `HTTPS`, `GATEWAY_INTERFACE`, `SERVER_SOFTWARE`,
`REMOTE_ADDR`, `REMOTE_PORT`, `SERVER_ADDR`, `SERVER_PORT`, `SERVER_NAME`,
`REDIRECT_STATUS` — and nothing else.

### 3.2 Debian/Ubuntu packaged nginx

`/etc/nginx/snippets/fastcgi-php.conf` (identical in `nginx-common 1.26.3-3+deb13u7`,
`1.22.1-9+deb12u9`, `1.18.0-6ubuntu14`, `1.24.0-2ubuntu7`):

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

`/etc/nginx/fastcgi.conf` supplies `SCRIPT_FILENAME`:

```nginx
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
```

The packaged default site (`sites-available/default`, normally linked into
`sites-enabled`) serves only static content — the PHP block is present but **commented**:

```nginx
	#location ~ \.php$ {
	#	include snippets/fastcgi-php.conf;
	#
	#	# With php-fpm (or other unix sockets):
	#	fastcgi_pass unix:/run/php/php7.4-fpm.sock;
	#	# With php-cgi (or other tcp sockets):
	#	fastcgi_pass 127.0.0.1:9000;
	#}
```

(all four releases still name the stale `php7.4-fpm.sock` path in the comment;
none of them ships PHP 7.4.) Neither `client_max_body_size` nor `fastcgi_request_buffering` appears
anywhere in the packaged `/etc/nginx` tree (the only hits are Vim syntax keywords), so
the effective values are **1m** and **on**. `nginx.conf` sets `worker_connections 768`
and `include /etc/nginx/sites-enabled/*;`.

### 3.3 `nginx:alpine` (nginx 1.31.8)

`/etc/nginx/nginx.conf` sets `worker_connections 1024`, `keepalive_timeout 65`, and
includes `conf.d/*.conf`; `/etc/nginx/conf.d/default.conf` serves
`/usr/share/nginx/html` with no PHP location. Therefore no FastCGI defaults are
configured at all: body limit 1m, request buffering on, no `PATH_INFO`.

### 3.4 WordPress recommended nginx configuration

Source: `https://developer.wordpress.org/advanced-administration/server/web-server/nginx/`
(captured 2026-10-23 as `/tmp/opencode/research/wp_nginx_doc.html`, excerpt in
`evidence/configs/wordpress_nginx_doc_excerpt.txt`). The published server block:

```nginx
http {
    #php max upload limit cannot be larger than this
    client_max_body_size 13m;
    ...
}

server {
    ...
    location / {
        # This is cool because no php is touched for static content.
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        #NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
        include fastcgi.conf;
        fastcgi_intercept_errors on;
        fastcgi_pass php;
    }
}
```

Key points for this audit:
- `client_max_body_size` is explicitly raised to **13m** in the doc's global block.
- The PHP location matches only URIs ending in `.php`; it does **not** set
  `fastcgi_split_path_info` and does **not** set `PATH_INFO`.
- The doc itself tells the reader to set `cgi.fix_pathinfo = 0`.
- A later "cache" variant in the same page uses
  `location ~ [^/]\.php(/|$)` with `fastcgi_split_path_info` and
  `if (!-f $document_root$fastcgi_script_name) { return 404; }` before
  `include fastcgi.conf;` — still no explicit `fastcgi_param PATH_INFO`.
- Multisite variants use `try_files $uri =404;` inside the PHP location and
  `include fastcgi_params;` (which lacks `SCRIPT_FILENAME`; those snippets are
  incomplete without an extra `fastcgi_param`).

### 3.5 MediaWiki recommended nginx configuration

Source: `https://www.mediawiki.org/wiki/Manual:Short_URL/Nginx` (captured as
`/tmp/opencode/research/mw_Manual_Short_URL_Nginx.html`, oldid 8060723; excerpt in
`evidence/configs/mediawiki_nginx_doc_excerpt.txt`):

```nginx
location ~ ^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass 127.0.0.1:9000;
}
...
location / { return 404; }
```

No `PATH_INFO`, no `fastcgi_split_path_info`, no `try_files` in the PHP location, no
`client_max_body_size`. The PHP location is end-anchored to the known entry points, and
every other URI falls through to `return 404`.

---

## 4. PHP-FPM packaged defaults

### 4.1 Debian 12/13 and Ubuntu 22.04/24.04

`/etc/php/<v>/fpm/php-fpm.conf` (Debian 13 example):

```ini
[global]
pid = /run/php/php8.4-fpm.pid
error_log = /var/log/php8.4-fpm.log
include=/etc/php/8.4/fpm/pool.d/*.conf
```

`/etc/php/<v>/fpm/pool.d/www.conf` active directives (identical values in all four):

```ini
[www]
user = www-data
group = www-data
listen = /run/php/php8.4-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

Directives that exist only as comments in the template, with the **effective** value
(compiled default) and the reason:

| Directive | Template line | Effective value |
|---|---|---|
| `listen.backlog` | `;listen.backlog = 511` | **-1 ⇒ SOMAXCONN** on Linux (`fpm_sockets.h:22`); the 511 comment is stale |
| `listen.mode` | `;listen.mode = 0660` | 0660 |
| `catch_workers_output` | `;catch_workers_output = yes` | **no** (struct is zeroed; no init assignment) |
| `decorate_workers_output` | `;decorate_workers_output = no` | **yes** (`fpm_conf.c:640` sets 1); only relevant when catch is on |
| `clear_env` | `;clear_env = no` | **yes** (`fpm_conf.c:639`) |
| `security.limit_extensions` | `;security.limit_extensions = .php .php3 .php4 .php5 .php7` | **`.php .phar`** (`fpm_conf.c:1150`); the longer list is a suggestion, not the default |
| `chdir` | `;chdir = /var/www` | none (cwd = prefix) |
| `request_terminate_timeout` | `;request_terminate_timeout = 0` | 0 (unlimited) |

The `php-fpm` postinst installs `/etc/php/<v>/fpm/php.ini` from
`/usr/lib/php/<v>/php.ini-production` via `ucf` (verified in
`tmpctrl_php84fpm/postinst`), which keeps `;cgi.fix_pathinfo=1` commented.

### 4.2 RHEL / Rocky / AlmaLinux 8 and 9

`/etc/php-fpm.conf`:

```ini
[global]
pid = /run/php-fpm/php-fpm.pid
error_log = /var/log/php-fpm/error.log
daemonize = yes
include=/etc/php-fpm.d/*.conf
```

`/etc/php-fpm.d/www.conf` active directives (identical in 7.2.24 and 8.0.30):

```ini
[www]
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.acl_users = apache,nginx
listen.allowed_clients = 127.0.0.1
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
slowlog = /var/log/php-fpm/www-slow.log
php_admin_value[error_log] = /var/log/php-fpm/www-error.log
php_admin_flag[log_errors] = on
```

`listen.owner`/`listen.group` are not set (they default to the pool user/group
`apache`). The ACL restricts socket access to `apache` and `nginx`; TCP access is
restricted to loopback. `clear_env` yes, `security.limit_extensions` `.php .phar`,
`catch_workers_output` no, `decorate_workers_output` yes, backlog -1 — same compiled
defaults as Debian.

The RHEL `php-fpm` RPM also ships the web-server glue:
`/etc/httpd/conf.d/php.conf` (proxy to `/run/php-fpm/www.sock`) and
`/etc/nginx/conf.d/php-fpm.conf`:

```nginx
upstream php-fpm {
        server unix:/run/php-fpm/www.sock;
}
```

### 4.3 Alpine 3.22

`/etc/php83/php-fpm.conf`:

```ini
[global]
include=/etc/php83/php-fpm.d/*.conf
```

`/etc/php83/php-fpm.d/www.conf` active directives:

```ini
[www]
user = nobody
group = nobody
listen = 127.0.0.1:9000
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

Notable differences: the pool runs as **`nobody`** and listens on **TCP loopback**, not
a Unix socket. `listen.owner`/`listen.group` are commented (`nobody`). All other
compiled defaults match Debian.

### 4.4 Arch Linux

`/etc/php/php-fpm.conf`:

```ini
[global]
error_log = syslog
include=/etc/php/php-fpm.d/*.conf
```

`/etc/php/php-fpm.d/www.conf` active:

```ini
[www]
user = http
group = http
listen = /run/php-fpm/php-fpm.sock
listen.owner = http
listen.group = http
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

### 4.5 Official `php:*-fpm` images

`/usr/local/etc/php-fpm.conf` contains only `[global]` plus
`include=/usr/local/etc/php-fpm.d/*.conf`. The pool file
`/usr/local/etc/php-fpm.d/www.conf` sets:

```ini
[www]
user = www-data
group = www-data
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

No `listen` is set there; the image's `/usr/local/etc/php-fpm.d/docker.conf` adds:

```ini
[global]
error_log = /proc/self/fd/2
log_limit = 8192

[www]
access.log = /proc/self/fd/2
clear_env = no
catch_workers_output = yes
decorate_workers_output = no
listen = 9000
```

and `zz-docker.conf` sets `daemonize = no`. `listen = 9000` means **TCP on all
interfaces** (runtime check: the socket is bound to `[::]:9000`), and `clear_env = no`
means the container environment is visible to PHP.
`php-fpm -tt` confirms the effective pool:
`listen.backlog = -1`, `security.limit_extensions = .php .phar`,
`catch_workers_output = yes`, `decorate_workers_output = no`, `clear_env = no`,
`pm.max_children = 5`.

The image ships `php.ini-production`/`php.ini-development` but **loads no `php.ini`**
(`php --ini` → "Loaded Configuration File: (none)"). Effective values are therefore the
compiled ones: `cgi.fix_pathinfo=1`, `display_errors=1`, `post_max_size=8M`,
`upload_max_filesize=2M`, `memory_limit=128M`, `expose_php=On`,
`max_execution_time=30`. `php-fpm -i` confirms `cgi.fix_pathinfo => On`,
`display_errors => On`, `max_execution_time => 30`.

### 4.6 FPM matrix

See `matrix_fpm.csv`. Condensed:

| Stack | pm | max_children | start | min_spare | max_spare | listen | user/group |
|---|---|---|---|---|---|---|---|
| Debian 12/13, Ubuntu 22.04/24.04 | dynamic | 5 | 2 | 1 | 3 | unix `/run/php/phpX.Y-fpm.sock` | www-data |
| Rocky/Alma 8/9 | dynamic | 50 | 5 | 5 | 35 | unix `/run/php-fpm/www.sock` (acl apache,nginx) | apache |
| Alpine 3.22 | dynamic | 5 | 2 | 1 | 3 | TCP `127.0.0.1:9000` | nobody |
| Arch | dynamic | 5 | 2 | 1 | 3 | unix `/run/php-fpm/php-fpm.sock` | http |
| php:8.4.26-fpm | dynamic | 5 | 2 | 1 | 3 | TCP `9000` (all ifaces, docker.conf) | www-data |

---

## 5. `cgi.fix_pathinfo`

`cgi.fix_pathinfo` is a PHP core INI setting with compiled default **1**. Every audited
distribution ships it only as a comment, so the effective value is 1:

| Source | Line | Content |
|---|---|---|
| Debian 13 `php.ini-production` (installed as FPM php.ini) | 803 | `;cgi.fix_pathinfo=1` |
| Debian 12 `php.ini-production` | (same template) | `;cgi.fix_pathinfo=1` |
| RHEL/Rocky/Alma 8 `/etc/php.ini` | 776 | `;cgi.fix_pathinfo=1` |
| RHEL/Rocky/Alma 9 `/etc/php.ini` | 807 | `;cgi.fix_pathinfo=1` |
| Alpine 3.22 `/etc/php83/php.ini` | 817 | `;cgi.fix_pathinfo=1` |
| Arch `/etc/php/php.ini` | 797 | `;cgi.fix_pathinfo=1` |
| Official `php:*-fpm` / `php:*-apache` | — | no php.ini loaded; compiled default 1 |

The WordPress nginx documentation explicitly recommends changing it to 0; neither the
distribution packages nor the official images do so.

---

## 6. Which defaults matter for CVE-2019-11043

### 6.1 The trigger, in terms of configuration

CVE-2019-11043 is a PHP-FPM bug in the FastCGI `PATH_INFO` handling: a request whose
`PATH_INFO` is present but empty/attacker-shaped underflows an FPM buffer and can lead to
code execution. The public PoC (`neex/phuip-fpizdam`, commit
`86bc456bd5d53c77ad54a2252dcaaf1345b1a483`) needs the front end to:

1. route a path-info URI (e.g. `/index.php/PHP%0A...`) to FPM, and
2. send a `PATH_INFO` FastCGI parameter (empty after a failed split), and
3. have no effective file-existence check in front of FPM, and
4. run an affected PHP version with `cgi.fix_pathinfo=1`.

Defaults therefore matter at three layers: the PHP package version, the
`cgi.fix_pathinfo` INI value, and the nginx location/snippet shape.

### 6.2 Stock distributions

- **PHP package:** Debian 10 shipped `php7.3 7.3.9-1~deb10u1`, which is vulnerable;
  `7.3.11-1~deb10u1` is the fixed package. Upstream fixes: 7.1.33, 7.2.24, 7.3.11.
  Debian 12 (8.2), Debian 13 (8.4), Ubuntu 22.04 (8.1), Ubuntu 24.04 (8.3), RHEL 8
  (7.2.24 default stream) and RHEL 9 (8.0.30) are all at or above fixed versions for
  this CVE.
- **`cgi.fix_pathinfo`:** 1 by default everywhere (§5). This is the attacker-favourable
  setting; only the WordPress documentation recommends 0.
- **Debian/Ubuntu nginx default:** the PHP block is commented out, so a stock install
  does not serve PHP at all. If the block is enabled exactly as shipped (include
  `snippets/fastcgi-php.conf`), the snippet **does** forward
  `fastcgi_param PATH_INFO $path_info`, but it also gates with
  `try_files $fastcgi_script_name =404;` **before** the `fastcgi_param`. With the PoC's
  `%0A` URI the split fails, `$fastcgi_script_name` remains the unsplit non-existent
  path, and nginx returns 404 without contacting FPM.
- **MediaWiki recommended:** the end-anchored PHP location
  (`^/w/...(index|load|api|thumb|...).php$`) does not match `/w/index.php/...`, and the
  final `location / { return 404; }` handles it. The path-info URI never reaches FPM.
- **WordPress recommended:** `location ~ \.php$` does not match a path-info URI, so the
  request falls to `location /` and is handled by WordPress (`try_files ... /index.php`);
  no `PATH_INFO` parameter is sent. The doc also advises `cgi.fix_pathinfo = 0`.

### 6.3 Existing measured evidence (not re-run here)

`/tmp/opencode/research/fpm_11043_targets_20261023T085412Z/report.md`:

| Configuration | Result |
|---|---|
| Debian 10 `php7.3 7.3.9-1~deb10u1` behind the canonical non-stock
  `location ~ [^/]\.php(/|$)` + split + `PATH_INFO` + no `try_files` | **RCE**,
  `uid=33(www-data)` |
| Debian 10 stock nginx default with the PHP block enabled as shipped
  (`nginx-full 1.14.2-2+deb10u4` + snippet) | **Blocked**, HTTP 404 from `try_files`; no
  QSL candidates |
| WordPress 5.3.2 with the official recommended nginx config,
  `cgi.fix_pathinfo=1` | **Blocked**, WordPress 301; no QSL candidates; becomes
  detectable only after non-stock `PATH_INFO` forwarding is added |
| MediaWiki 1.33.1 with the official recommended nginx config | **Blocked**, 404 routing |
| Fixed controls: `7.3.11-1~deb10u1`, 7.2.24, 8.4.26 on the canonical pattern | Clean |

**Answer to "is the stock distro/app config exploitable?":** the *PHP package* on
Debian 10 was vulnerable, but the *stock nginx default* and *both official application
configurations* were **not exploitable as published** in the existing lab. The
configuration features that block it are, in order of strength: no PHP location at all
(stock default), `try_files` before `PATH_INFO` (Debian snippet), no `PATH_INFO`
parameter (WordPress main config), and an end-anchored location with a 404 fallback
(MediaWiki).

---

## 7. Which defaults matter for FPM 109618/109619

### 7.1 Affected/fixed builds and the relevant knobs

The task defines the affected FPM builds as 8.2.34, 8.3.35, 8.4.26, 8.5.11 and the fixed
builds as 8.2.35, 8.3.36, 8.4.27, 8.5.12. The defaults that bound the attack surface are:

| Default | Stock value | Why it matters |
|---|---|---|
| nginx `client_max_body_size` | **1m** | caps any request body before FPM; the known B1 body is 33,128,677 B |
| nginx `fastcgi_request_buffering` | **on** | body is fully read/buffered before FPM; `off` changes `CONTENT_LENGTH`/chunked behaviour |
| PHP `post_max_size` | **8M** | PHP rejects larger POST bodies (`post=0`) even if nginx allows them |
| `pm.max_children` | **5** (Debian/Ubuntu/Alpine/Arch/official) / **50** (RHEL family) | number of workers among which a poisoned worker must be reused |
| `pm` | **dynamic** | workers are forked on demand; start/min/max spare shape reuse |
| `listen.backlog` | **-1 ⇒ SOMAXCONN** on Linux | accept queue depth |
| `catch_workers_output` | **no** (yes in official image's docker.conf) | whether worker stderr reaches the FPM error log |
| `display_errors` | **Off** in distro `php.ini-production`; **On** in official images (no php.ini) | leak channel visibility |
| nginx upstream affinity | none by default | requests are distributed across workers; no keepalive pinning |

### 7.2 Existing measured evidence (not re-run here)

`/tmp/opencode/research/fpm_109619_20261023T010421Z/report.md` reports a **negative**
against stock nginx + FPM (multi-worker, ASLR on, 1 MiB nginx body limit,
`post_max_size=8M`, `display_errors=Off`):

- A1 1,060,211 B → HTTP 413 at stock nginx; the exact B1 33,128,677 B → 413; a 2 MB
  chunked body → 413.
- The only body that fits both gates, A2 279,369 B, kills the worker:
  `php_request_startup()==FAILURE` → `php_module_shutdown()` → `FPM_EXIT_SOFTWARE` (70),
  so the dangling session state dies with the process.
- Six keep-alive requests alternated workers 40/15; same-worker pinning appeared only
  with non-stock `fastcgi_keep_conn on` + upstream keepalive.
- No leak channel under `display_errors=Off`.

**Answer to "is the stock config exploitable?":** per existing evidence, **no** — the
stock nginx + PHP-FPM combination did not yield RCE or a leak. The defaults that carry
the weight are the 1 MiB nginx cap and the 8M `post_max_size`, followed by the
startup-failure exit and the absence of upstream affinity. One untested difference is
the RHEL family's `pm.max_children = 50` (vs 5 elsewhere), which changes worker-reuse
odds; no measurement exists for it in the cited lab.

---

## 8. Unknowns, not-shipped and caveats

1. **Ubuntu release pockets.** Values come from `dists/jammy` and `dists/noble` at the
   time of audit; `-updates`/`-security` package revisions were not downloaded.
   Directive values are unlikely to change in a stable release, but the exact version
   strings may differ on a patched host.
2. **RHEL module streams.** Only the default streams were audited: `php:7.2` on
   RHEL/Rocky 8 and `php:8.0` on RHEL/Rocky 9. Other streams (8.1/8.2/8.3 on 9) were
   not unpacked; `mod_php` availability in those streams is **unknown**. The 8.0
   `php` RPM is a metapackage with an empty payload, so no `mod_php` is shipped there.
3. **Alpine nginx package** was not audited; the `nginx:alpine` official image was used
   for the nginx-on-Alpine data point.
4. **Arch is rolling.** Versions are the 2026-10-23 snapshot (`apache 2.4.69-1`,
   `php 8.5.12-1`); the files can change on any update.
5. **Apache compiled defaults for RHEL** are inferred from the absence of MPM
   directives plus httpd 2.4.62 source. They were not measured by running RHEL's httpd.
6. **FPM compiled defaults** (`catch_workers_output=no`, `decorate_workers_output=yes`,
   `clear_env=yes`, `security.limit_extensions=".php .phar"`, `listen.backlog=-1`) are
   source-verified (`fpm_conf.c`, `fpm_sockets.h`) and, where possible, confirmed with
   `php-fpm -tt` in the official image. Debian's FPM binary was not executed.
7. **`listen.backlog` comment vs effective value.** The shipped template comments say
   `511`; the source and `php-fpm -tt` show `-1` (Linux truncates negative backlog to
   `SOMAXCONN`). Both are recorded.
8. **`security.limit_extensions`.** The Debian/Alpine/Arch templates comment a longer
   list (`.php .php3 .php4 .php5 .php7`); because it is commented, the compiled
   `.php .phar` applies. A reader copying the comment into the config would widen it.
9. **Official image PHP INI.** `php:*-fpm` and `php:*-apache` load no `php.ini`; the
   `display_errors=On` / `cgi.fix_pathinfo=1` values are the compiled defaults, not a
   distro `php.ini-production`.
10. **`php:*-apache` MPM** was verified at runtime for 8.3.35, 8.4.26 and 8.5.12 only;
    older tags were not re-checked.
11. **No exploit was run for this report.** The CVE sections cite existing lab reports
    and their measured artifacts, not new executions.

---

## 9. Evidence index and reproduction

### 9.1 Evidence files

| Path | Content |
|---|---|
| `evidence/package_sha256.txt` | SHA-256 of every downloaded `.deb`/`.rpm`/`.apk`/`.pkg.tar.zst` |
| `evidence/apache_upstream_defaults.txt` | httpd 2.4.62 `mpm_default.h` / `mpm_common.h` grep output |
| `evidence/php8426fpm_effective.txt` | `php-fpm -tt` / `php-fpm -i` effective pool and INI values |
| `evidence/php8426fpm_pool.txt`, `php8426fpm_more.txt` | official image `www.conf`, `docker.conf`, `zz-docker.conf`, `php --ini` |
| `evidence/php8335apache_image.txt`, `php8426apache_image.txt`, `php8512apache_image.txt` | `apache2ctl -V`, mods-enabled MPM, `libphp.so` |
| `evidence/php8335apache_ini.txt` | PHP INI defaults in the official Apache image |
| `evidence/nginx_alpine_conf.txt` | `nginx:alpine` `nginx.conf` + `conf.d/default.conf` |
| `evidence/configs/*.conf` | Debian/RHEL/Alpine/Arch config files as extracted |
| `evidence/configs/wordpress_nginx_doc_excerpt.txt`, `mediawiki_nginx_doc_excerpt.txt` | application doc excerpts with line references |

### 9.2 Reproduction sketch

```bash
# Debian/Ubuntu package configs
curl -sSLO https://deb.debian.org/debian/pool/main/a/apache2/apache2_2.4.68-1~deb13u1_amd64.deb
dpkg-deb -x apache2_2.4.68-1~deb13u1_amd64.deb out/
cat out/etc/apache2/mods-available/mpm_event.conf out/etc/apache2/mods-available/mpm_prefork.conf
dpkg-deb -e apache2_2.4.68-1~deb13u1_amd64.deb ctrl/ && grep -n mpm ctrl/postinst

curl -sSLO https://deb.debian.org/debian/pool/main/n/nginx/nginx-common_1.26.3-3+deb13u7_all.deb
dpkg-deb -x nginx-common_1.26.3-3+deb13u7_all.deb out/
cat out/etc/nginx/snippets/fastcgi-php.conf out/etc/nginx/fastcgi.conf

# PHP-FPM pool
curl -sSLO https://deb.debian.org/debian/pool/main/p/php8.4/php8.4-fpm_8.4.24-1~deb13u1_amd64.deb
dpkg-deb -x php8.4-fpm_8.4.24-1~deb13u1_amd64.deb out/
cat out/etc/php/8.4/fpm/php-fpm.conf out/etc/php/8.4/fpm/pool.d/www.conf

# RHEL family
python3 scripts/resolve_rpm.py https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os httpd-core php-fpm
curl -sSLO <printed URL> && bsdtar -xf httpd-core-*.rpm -C out/
cat out/etc/httpd/conf.modules.d/00-mpm.conf

# Alpine / Arch
curl -sSLO https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/apache2-2.4.69-r0.apk
tar -xzf apache2-2.4.69-r0.apk -C out/ && cat out/etc/apache2/conf.d/mpm.conf

# Official images
docker run --rm --entrypoint sh php:8.4.26-fpm -c 'php-fpm -tt; php -i' 
docker run --rm --entrypoint sh php:8.3.35-apache -c 'apache2ctl -V; ls /etc/apache2/mods-enabled'
```

### 9.3 Machine-readable matrices

- `matrix_apache.csv` — one row per stack/MPM, with `mod_php` availability.
- `matrix_fpm.csv` — one row per packaged pool.
- `matrix_nginx.csv` — one row per stack/config, `client_max_body_size`,
  `fastcgi_request_buffering`, split, `try_files`, `PATH_INFO`, `SCRIPT_FILENAME`,
  `cgi.fix_pathinfo`.
- `matrix.md` — all three rendered as Markdown tables.

### 9.4 Constraint compliance

Read-only package/source audit; no exploit, no service change, no push/commit. The only
processes started were short-lived `docker run --rm` probes of images already present on
the host.
