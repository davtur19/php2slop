# Evidence index — web server + PHP-FPM defaults audit

All files here were produced by read-only inspection of downloaded packages/images on
2026-10-23. Package hashes are in `package_sha256.txt`.

## Runtime dumps

| File | What it records |
|---|---|
| `apache_upstream_defaults.txt` | httpd 2.4.62 compiled MPM defaults (`event`, `prefork`, `mpm_common.h`) |
| `php8426fpm_effective.txt` | `php-fpm -tt` effective global/pool config, `php-fpm -i` INI values |
| `php8426fpm_pool.txt` | official `php:8.4.26-fpm` `www.conf` active directives |
| `php8426fpm_more.txt` | `docker.conf`, `zz-docker.conf`, `php --ini`, INI template values |
| `php8426fpm_ini_extra.txt` | FPM SAPI INI defaults (display_errors, max_execution_time, post_max_size) |
| `php8335apache_image.txt`, `php8426apache_image.txt`, `php8512apache_image.txt` | `apache2ctl -V`, MPM, `libphp.so` in official Apache images |
| `php8335apache_ini.txt` | PHP INI defaults in the official Apache image |
| `nginx_alpine_conf.txt` | `nginx:alpine` `nginx.conf` and `conf.d/default.conf` |

## Shipped config copies

`configs/` holds the exact files extracted from the packages:

- `deb13_fastcgi-php.conf`, `deb13_fastcgi.conf` — Debian 13 nginx snippet and `fastcgi.conf`
- `deb13_mpm_event.conf`, `deb13_mpm_prefork.conf` — Debian 13 MPM tuning
- `deb13_php84_www.conf`, `deb13_php84_php-fpm.conf` — Debian 13 FPM
- `el8_php72_www.conf`, `el9_php80_www.conf` — RHEL-family FPM pools
- `alpine_php83_www.conf`, `arch_php85_www.conf` — Alpine and Arch FPM pools
- `wordpress_nginx_doc_excerpt.txt`, `mediawiki_nginx_doc_excerpt.txt` — application docs

## Package provenance

`package_sha256.txt` lists each downloaded artifact. Versions and archive URLs are in
`../report.md` §1.1.
