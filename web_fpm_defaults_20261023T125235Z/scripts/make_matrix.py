#!/usr/bin/env python3
"""Generate matrix CSV/Markdown for web-server + PHP-FPM defaults.

Every value is taken from a shipped package file or upstream source that was
downloaded and inspected in this session. 'not set' means the key is absent
from the shipped config, so the effective value is the compiled/upstream
default recorded in the 'effective' column or the notes.
"""
import csv, os

OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- Apache
apache_cols = [
    "stack", "release", "package", "version", "default_mpm",
    "StartServers", "MinSpareServers", "MaxSpareServers",
    "MaxRequestWorkers", "MaxConnectionsPerChild",
    "ThreadsPerChild", "MinSpareThreads", "MaxSpareThreads",
    "mod_php_package", "mod_php_note", "source",
]
apache_rows = [
    ["Debian", "13 trixie", "apache2", "2.4.68-1~deb13u1", "event",
     "2", "n/a (threaded)", "n/a (threaded)", "150", "0", "25", "25", "75",
     "libapache2-mod-php8.4 8.4.24-1~deb13u1",
     "mod_php postinst switches MPM to prefork automatically",
     "etc/apache2/mods-available/mpm_event.conf; etc/apache2/mods-available/mpm_prefork.conf; DEBIAN/postinst"],
    ["Debian", "13 trixie (prefork, e.g. with mod_php)", "apache2", "2.4.68-1~deb13u1", "prefork",
     "5", "5", "10", "150", "0", "n/a", "n/a", "n/a",
     "libapache2-mod-php8.4 8.4.24-1~deb13u1",
     "enabled by mod_php postinst (apache2_switch_mpm prefork)",
     "etc/apache2/mods-available/mpm_prefork.conf"],
    ["Debian", "12 bookworm", "apache2", "2.4.68-1~deb12u1", "event",
     "2", "n/a (threaded)", "n/a (threaded)", "150", "0", "25", "25", "75",
     "libapache2-mod-php8.2 8.2.32-1~deb12u1",
     "mod_php postinst switches MPM to prefork automatically",
     "etc/apache2/mods-available/mpm_event.conf"],
    ["Ubuntu", "22.04 jammy (release pocket)", "apache2", "2.4.52-1ubuntu4", "event",
     "2", "n/a (threaded)", "n/a (threaded)", "150", "0", "25", "25", "75",
     "libapache2-mod-php8.1 8.1.2-1ubuntu2",
     "mod_php postinst switches MPM to prefork automatically",
     "etc/apache2/mods-available/mpm_event.conf; postinst"],
    ["Ubuntu", "24.04 noble (release pocket)", "apache2", "2.4.58-1ubuntu8", "event",
     "2", "n/a (threaded)", "n/a (threaded)", "150", "0", "25", "25", "75",
     "libapache2-mod-php8.3 8.3.6-0maysync1",
     "mod_php postinst switches MPM to prefork automatically",
     "etc/apache2/mods-available/mpm_event.conf; postinst"],
    ["Rocky/Alma", "8 (module stream 8.10)", "httpd", "2.4.37-64.module+el8.10.0+1717+030a9fed", "event",
     "3 (compiled)", "n/a (threaded)", "n/a (threaded)", "400 (compiled)", "0 (compiled)",
     "25 (compiled)", "75 (compiled: 3x25)", "250 (compiled: 10x25)",
     "php 7.2.24 (libphp7.so)",
     "mod_php loaded only inside <IfModule prefork.c>; default event => NOT loaded; php.conf proxies to php-fpm socket",
     "etc/httpd/conf.modules.d/00-mpm.conf; etc/httpd/conf/httpd.conf (no MPM tuning); etc/httpd/conf.modules.d/15-php.conf"],
    ["Rocky/Alma", "9", "httpd-core", "2.4.62-13.el9", "event",
     "3 (compiled)", "n/a (threaded)", "n/a (threaded)", "400 (compiled)", "0 (compiled)",
     "25 (compiled)", "75 (compiled: 3x25)", "250 (compiled: 10x25)",
     "not shipped (php 8.0.30 is a 44-byte metapackage)",
     "php-fpm RPM ships /etc/httpd/conf.d/php.conf -> proxy:unix:/run/php-fpm/www.sock",
     "etc/httpd/conf.modules.d/00-mpm.conf; etc/httpd/conf/httpd.conf (no MPM tuning)"],
    ["Alpine", "3.22", "apache2", "2.4.69-r0", "prefork",
     "5", "5", "10", "250", "0", "n/a", "n/a", "n/a",
     "php83-apache2 8.3.36-r0 (mod_php83.so)",
     "mod_php shipped as shared module + /etc/apache2/conf.d/php83-module.conf",
     "etc/apache2/httpd.conf; etc/apache2/conf.d/mpm.conf"],
    ["Arch", "rolling (2026-10-23)", "apache", "2.4.69-1", "event",
     "3", "n/a (threaded)", "n/a (threaded)", "400", "0", "25", "75", "250",
     "php-apache 8.5.12-1 (libphp.so)",
     "module shipped but /etc/httpd/conf/extra/php_module.conf is NOT included by default",
     "etc/httpd/conf/httpd.conf; etc/httpd/conf/extra/httpd-mpm.conf"],
    ["Arch", "rolling (prefork block, if enabled)", "apache", "2.4.69-1", "prefork",
     "5", "5", "10", "250", "0", "n/a", "n/a", "n/a", "php-apache 8.5.12-1",
     "block present in httpd-mpm.conf but mpm_prefork not loaded by default",
     "etc/httpd/conf/extra/httpd-mpm.conf"],
    ["Official php image", "php:8.3.35-apache", "apache2 (Debian build)", "Apache/2.4.69 (Debian)", "prefork",
     "5", "5", "10", "150", "0", "n/a", "n/a", "n/a",
     "libphp.so (in image)",
     "mod_php loaded; a2dismod mpm_event / a2enmod mpm_prefork at build",
     "apache2ctl -V; /etc/apache2/mods-enabled/mpm_prefork.conf"],
    ["Official php image", "php:8.4.26-apache", "apache2 (Debian build)", "Apache/2.4.69 (Debian)", "prefork",
     "5", "5", "10", "150", "0", "n/a", "n/a", "n/a", "libphp.so (in image)",
     "mod_php loaded", "apache2ctl -V; /etc/apache2/mods-enabled/mpm_prefork.conf"],
    ["Official php image", "php:8.5.12-apache", "apache2 (Debian build)", "Apache/2.4.69 (Debian)", "prefork",
     "5", "5", "10", "150", "0", "n/a", "n/a", "n/a", "libphp.so (in image)",
     "mod_php loaded", "apache2ctl -V; /etc/apache2/mods-enabled/mpm_prefork.conf"],
    ["Apache upstream", "2.4.62 source", "httpd", "2.4.62", "event (compiled)",
     "3", "n/a (threaded)", "n/a (threaded)", "400", "0", "25", "75", "250",
     "n/a", "compiled-in values used when no MPM directives are present",
     "server/mpm/event/mpm_default.h; server/mpm_common.c"],
    ["Apache upstream", "2.4.62 source", "httpd", "2.4.62", "prefork (compiled)",
     "5", "5", "10", "256", "0", "n/a", "n/a", "n/a",
     "n/a", "compiled-in values used when no MPM directives are present",
     "server/mpm/prefork/mpm_default.h; server/mpm_common.c"],
]

# ---------------------------------------------------------------- FPM
fpm_cols = [
    "stack", "package", "version", "pm", "pm.max_children",
    "pm.start_servers", "pm.min_spare_servers", "pm.max_spare_servers",
    "listen", "listen.owner", "listen.group", "user", "group",
    "clear_env", "security.limit_extensions", "catch_workers_output",
    "decorate_workers_output", "listen.backlog", "source",
]
fpm_rows = [
    ["Debian 13 trixie", "php8.4-fpm", "8.4.24-1~deb13u1",
     "dynamic", "5", "2", "1", "3", "unix:/run/php/php8.4-fpm.sock",
     "www-data", "www-data", "www-data", "www-data",
     "yes (compiled; template only has ;clear_env = no)",
     ".php .phar (compiled; template comment lists .php .php3 .php4 .php5 .php7)",
     "no (compiled; template comment ;catch_workers_output = yes)",
     "yes (compiled default; template comment ;decorate_workers_output = no)",
     "-1 on Linux => SOMAXCONN (template comment says 511)",
     "etc/php/8.4/fpm/php-fpm.conf; etc/php/8.4/fpm/pool.d/www.conf"],
    ["Debian 12 bookworm", "php8.2-fpm", "8.2.32-1~deb12u1",
     "dynamic", "5", "2", "1", "3", "unix:/run/php/php8.2-fpm.sock",
     "www-data", "www-data", "www-data", "www-data",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN", "etc/php/8.2/fpm/php-fpm.conf; pool.d/www.conf"],
    ["Ubuntu 22.04 jammy", "php8.1-fpm", "8.1.2-1ubuntu2",
     "dynamic", "5", "2", "1", "3", "unix:/run/php/php8.1-fpm.sock",
     "www-data", "www-data", "www-data", "www-data",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN", "etc/php/8.1/fpm/php-fpm.conf; pool.d/www.conf"],
    ["Ubuntu 24.04 noble", "php8.3-fpm", "8.3.6-0maysync1",
     "dynamic", "5", "2", "1", "3", "unix:/run/php/php8.3-fpm.sock",
     "www-data", "www-data", "www-data", "www-data",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN", "etc/php/8.3/fpm/php-fpm.conf; pool.d/www.conf"],
    ["Rocky/Alma 8", "php-fpm", "7.2.24-1.module+el8.4.0+413+c9202dda",
     "dynamic", "50", "5", "5", "35", "unix:/run/php-fpm/www.sock",
     "not set (defaults to user)", "not set (defaults to group)", "apache", "apache",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN",
     "etc/php-fpm.conf; etc/php-fpm.d/www.conf (listen.acl_users=apache,nginx; listen.allowed_clients=127.0.0.1)"],
    ["Rocky/Alma 9", "php-fpm", "8.0.30-5.el9_7",
     "dynamic", "50", "5", "5", "35", "unix:/run/php-fpm/www.sock",
     "not set (defaults to user)", "not set (defaults to group)", "apache", "apache",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN",
     "etc/php-fpm.conf; etc/php-fpm.d/www.conf (listen.acl_users=apache,nginx; listen.allowed_clients=127.0.0.1)"],
    ["Alpine 3.22", "php83-fpm", "8.3.36-r0",
     "dynamic", "5", "2", "1", "3", "127.0.0.1:9000 (TCP loopback)",
     "not set (comment ;listen.owner = nobody)", "not set (comment ;listen.group = nobody)",
     "nobody", "nobody",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN", "etc/php83/php-fpm.conf; etc/php83/php-fpm.d/www.conf"],
    ["Arch rolling", "php-fpm", "8.5.12-1",
     "dynamic", "5", "2", "1", "3", "unix:/run/php-fpm/php-fpm.sock",
     "http", "http", "http", "http",
     "yes (compiled)", ".php .phar (compiled)", "no (compiled)", "yes (compiled)",
     "-1 on Linux => SOMAXCONN", "etc/php/php-fpm.conf; etc/php/php-fpm.d/www.conf"],
    ["Official php image", "php:8.4.26-fpm", "PHP 8.4.26",
     "dynamic", "5", "2", "1", "3", "9000 (TCP, all interfaces; set in docker.conf; bound to [::]:9000)",
     "not set", "not set", "www-data", "www-data",
     "no (docker.conf sets clear_env = no)",
     ".php .phar (compiled)",
     "yes (docker.conf sets catch_workers_output = yes)",
     "no (docker.conf sets decorate_workers_output = no)",
     "-1 on Linux => SOMAXCONN",
     "usr/local/etc/php-fpm.conf; php-fpm.d/www.conf; php-fpm.d/docker.conf; php-fpm.d/zz-docker.conf"],
]

# ---------------------------------------------------------------- nginx
ng_cols = [
    "stack", "package/version", "client_max_body_size",
    "fastcgi_request_buffering", "fastcgi_split_path_info", "try_files",
    "fastcgi_param PATH_INFO", "SCRIPT_FILENAME", "cgi.fix_pathinfo",
    "php location", "source",
]
ng_rows = [
    ["nginx upstream default", "nginx 1.26.3 source", "1m (1 MiB; compiled default)",
     "on (default since 1.7.11)", "none (no default)", "none (no default)",
     "not set", "not set in conf/fastcgi_params",
     "n/a", "n/a",
     "src/http/ngx_http_core_module.c:3786; nginx.org docs; conf/fastcgi_params"],
    ["Debian 13 trixie", "nginx-common 1.26.3-3+deb13u7", "not set => 1m",
     "not set => on", "^(.+?\\.php)(/.*)$ (snippet)", "try_files $fastcgi_script_name =404; (snippet)",
     "$path_info (snippet, after try_files)", "$document_root$fastcgi_script_name (fastcgi.conf)",
     "1 (commented in php.ini)", "commented out in sites-available/default",
     "etc/nginx/snippets/fastcgi-php.conf; etc/nginx/sites-available/default; etc/nginx/fastcgi.conf"],
    ["Debian 12 bookworm", "nginx-common 1.22.1-9+deb12u9", "not set => 1m",
     "not set => on", "^(.+?\\.php)(/.*)$ (snippet)", "try_files $fastcgi_script_name =404; (snippet)",
     "$path_info (snippet)", "$document_root$fastcgi_script_name (fastcgi.conf)",
     "1 (commented)", "commented out in sites-available/default",
     "etc/nginx/snippets/fastcgi-php.conf; etc/nginx/sites-available/default"],
    ["Ubuntu 22.04 jammy", "nginx-common 1.18.0-6ubuntu14", "not set => 1m",
     "not set => on", "^(.+?\\.php)(/.*)$ (snippet)", "try_files $fastcgi_script_name =404; (snippet)",
     "$path_info (snippet)", "$document_root$fastcgi_script_name (fastcgi.conf)",
     "1 (commented)", "commented out (stale php7.4 socket comment)",
     "etc/nginx/snippets/fastcgi-php.conf; etc/nginx/sites-available/default"],
    ["Ubuntu 24.04 noble", "nginx-common 1.24.0-2ubuntu7", "not set => 1m",
     "not set => on", "^(.+?\\.php)(/.*)$ (snippet)", "try_files $fastcgi_script_name =404; (snippet)",
     "$path_info (snippet)", "$document_root$fastcgi_script_name (fastcgi.conf)",
     "1 (commented)", "commented out (stale php7.4 socket comment)",
     "etc/nginx/snippets/fastcgi-php.conf; etc/nginx/sites-available/default"],
    ["nginx:alpine image", "nginx 1.31.8", "not set => 1m", "not set => on",
     "none", "not set (no PHP location)", "not set", "not set",
     "n/a", "no PHP location at all", "/etc/nginx/nginx.conf; /etc/nginx/conf.d/default.conf"],
    ["WordPress recommended (main)", "developer.wordpress.org nginx doc", "13m (explicit)",
     "not set => on", "none", "try_files $uri $uri/ /index.php?$args; (location /)",
     "not set", "$document_root$fastcgi_script_name (include fastcgi.conf)",
     "doc says set 0", "location ~ \\.php$ { include fastcgi.conf; fastcgi_pass php; }",
     "wp_nginx_doc.html lines 457,551-562"],
    ["WordPress recommended (cache variant)", "developer.wordpress.org nginx doc", "13m (global)",
     "not set => on", "^(.+?\\.php)(/.*)$", "if (!-f $document_root$fastcgi_script_name) return 404;",
     "not set", "$document_root$fastcgi_script_name",
     "doc says set 0", "location ~ [^/]\\.php(/|$)",
     "wp_nginx_doc.html lines 906-916"],
    ["MediaWiki recommended", "mediawiki.org Manual:Short_URL/Nginx", "not set => 1m",
     "not set => on", "none", "not set in PHP location (fallback location / { return 404; })",
     "not set", "explicit fastcgi_param SCRIPT_FILENAME",
     "1 (not addressed)", "location ~ ^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\\.php$",
     "mw_Manual_Short_URL_Nginx.html lines 612-616, 668"],
]

def write_csv(name, cols, rows):
    path = os.path.join(OUT, name)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)

write_csv("matrix_apache.csv", apache_cols, apache_rows)
write_csv("matrix_fpm.csv", fpm_cols, fpm_rows)
write_csv("matrix_nginx.csv", ng_cols, ng_rows)

def md_table(cols, rows):
    out = ["| " + " | ".join(cols) + " |",
           "|" + "|".join(["---"] * len(cols)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    return "\n".join(out)

with open(os.path.join(OUT, "matrix.md"), "w", encoding="utf-8") as f:
    f.write("# Defaults matrix — web server + PHP-FPM\n\n")
    f.write("Generated from shipped package files and upstream source (see report.md).\n\n")
    f.write("## Apache MPM\n\n")
    f.write(md_table(apache_cols, apache_rows) + "\n\n")
    f.write("## PHP-FPM pools\n\n")
    f.write(md_table(fpm_cols, fpm_rows) + "\n\n")
    f.write("## nginx / FastCGI\n\n")
    f.write(md_table(ng_cols, ng_rows) + "\n")
print("written")
