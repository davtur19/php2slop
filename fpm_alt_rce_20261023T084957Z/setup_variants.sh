#!/bin/bash
set -u
R=/tmp/opencode/research/fpm_alt_rce_20261023T084957Z
NET=fpmalt_net

# FPM with cgi.fix_pathinfo=0
mkdir -p $R/conf/php-nofix
cat > $R/conf/php-nofix/zz-lab.ini <<'INI'
cgi.fix_pathinfo=0
expose_php=On
INI
docker rm -f fpmalt-7223-nofix >/dev/null 2>&1
docker run -d --name fpmalt-7223-nofix --network $NET --network-alias fpmalt-7223-nofix \
  -v $R/docroot/7223:/var/www/html:ro \
  -v $R/docroot/7223:/srv/www/7223:ro \
  -v $R/conf/php-nofix/zz-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro \
  php:7.2.23-fpm >/dev/null

cat > $R/conf/nginxE.conf <<'CONF'
# E1: fix_pathinfo=0 backend, otherwise identical to variant B
server {
    listen 8121;
    server_name _;
    root /srv/www/7223;
    index index.php;
    location ~ [^/]\.php(/|$) {
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_pass fpmalt-7223-nofix:9000;
    }
}
# E2: PATH_TRANSLATED instead of PATH_INFO (split still present)
server {
    listen 8122;
    server_name _;
    root /srv/www/7223;
    index index.php;
    location ~ [^/]\.php(/|$) {
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_TRANSLATED $document_root$fastcgi_path_info;
        fastcgi_pass fpmalt-7223:9000;
    }
}
# E3: PATH_INFO from $fastcgi_path_info but no split_path_info (value always empty)
server {
    listen 8123;
    server_name _;
    root /srv/www/7223;
    index index.php;
    location ~ [^/]\.php(/|$) {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_pass fpmalt-7223:9000;
    }
}
CONF

docker rm -f fpmalt-nginx-e >/dev/null 2>&1
docker run -d --name fpmalt-nginx-e --network $NET \
  -p 127.0.0.1:29461:8121 -p 127.0.0.1:29462:8122 -p 127.0.0.1:29463:8123 \
  -v $R/conf/nginxE.conf:/etc/nginx/conf.d/default.conf:ro \
  -v $R/docroot:/srv/www:ro nginx:alpine >/dev/null
sleep 2
docker ps --filter name=fpmalt-nginx-e --format '{{.Names}} {{.Status}}'
for p in 29461 29462 29463; do echo -n "$p baseline: "; curl -s --max-time 5 -o /tmp/o -w '%{http_code} ' http://127.0.0.1:$p/index.php; head -c 40 /tmp/o; echo; done
