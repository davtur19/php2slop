#!/bin/bash
# CVE-2019-11043 lab: isolated network fpmalt_net, ports 294xx.
set -u
R=/tmp/opencode/research/fpm_alt_rce_20261023T084957Z
NET=fpmalt_net
declare -A VER=( [7123]=7.1.32 [7223]=7.2.23 [7224]=7.2.24 [7310]=7.3.10 [7311]=7.3.11 [7433]=7.4.33 [8426]=8.4.26 )

docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.88.88.0/24 $NET

for tag in "${!VER[@]}"; do
  mkdir -p $R/docroot/$tag
  cat > $R/docroot/$tag/index.php <<'PHP'
<?php
header('X-Lab: fpmalt');
echo "FPMALT-OK ".PHP_VERSION."\n";
PHP
done
mkdir -p $R/conf/php
cat > $R/conf/php/zz-lab.ini <<'INI'
cgi.fix_pathinfo=1
expose_php=On
INI

for tag in "${!VER[@]}"; do
  name=fpmalt-$tag
  docker rm -f $name >/dev/null 2>&1
  docker run -d --name $name --network $NET --network-alias $name \
    -v $R/docroot/$tag:/var/www/html:ro \
    -v $R/docroot/$tag:/srv/www/$tag:ro \
    -v $R/conf/php/zz-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro \
    php:${VER[$tag]}-fpm >/dev/null || echo "FAILED start $name"
done

python3 - "$R" <<'PY'
import sys, os
R = sys.argv[1]
vers = [("7123","7.1.32"),("7223","7.2.23"),("7224","7.2.24"),("7310","7.3.10"),
        ("7311","7.3.11"),("7433","7.4.33"),("8426","8.4.26")]

def blk(port, tag, *, try_files, path_info, split=True):
    loc = []
    if split:
        loc.append("        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;")
    if try_files:
        loc.append("        try_files $fastcgi_script_name =404;")
    loc.append("        include fastcgi_params;")
    loc.append("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;")
    if path_info:
        loc.append("        fastcgi_param PATH_INFO $fastcgi_path_info;")
    loc.append(f"        fastcgi_pass fpmalt-{tag}:9000;")
    return "\nserver {\n    listen %d;\n    server_name _;\n    root /srv/www/%s;\n    index index.php;\n    location ~ [^/]\\.php(/|$) {\n%s\n    }\n}\n" % (
        port, tag, "\n".join(loc))

A = "".join(blk(8081+i, t, try_files=True, path_info=True) for i,(t,_) in enumerate(vers))
B = "".join(blk(8091+i, t, try_files=False, path_info=True) for i,(t,_) in enumerate(vers))
open(os.path.join(R,"conf","nginxA.conf"),"w").write(A)
open(os.path.join(R,"conf","nginxB.conf"),"w").write(B)

C = """
server { listen 8101; server_name _; root /srv/stock; index index.html index.htm; location / { } }
"""
C += """
server {
    listen 8102; server_name _; root /srv/www/7223; index index.php;
    location ~ \\.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass fpmalt-7223:9000;
    }
}
"""
C += "".join("""
server {
    listen %d; server_name _; root /srv/www/%s; index index.php;
    location ~ [^/]\\.php(/|$) {
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        try_files $fastcgi_script_name =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass fpmalt-%s:9000;
    }
}
""" % (8103+i, t, t) for i,(t,_) in enumerate([vers[0],vers[1],vers[3]]))
open(os.path.join(R,"conf","nginxC.conf"),"w").write(C)

D = "".join(blk(8111+i, t, try_files=False, path_info=True) for i,(t,_) in enumerate([vers[0],vers[1],vers[3]]))
open(os.path.join(R,"conf","nginxD.conf"),"w").write(D)
PY

mkdir -p $R/docroot/stock
echo "STOCK-NGINX-DEFAULT" > $R/docroot/stock/index.html

start_nginx() {
  local name=$1 conf=$2 image=$3; shift 3
  docker rm -f $name >/dev/null 2>&1
  local args=""
  for pair in "$@"; do args="$args -p 127.0.0.1:${pair}"; done
  docker run -d --name $name --network $NET $args \
    -v $R/conf/$conf:/etc/nginx/conf.d/default.conf:ro \
    -v $R/docroot:/srv/www:ro \
    -v $R/docroot/stock:/srv/stock:ro \
    $image >/dev/null || echo "FAILED nginx $name"
}
start_nginx fpmalt-nginx-a nginxA.conf nginx:alpine \
  29451:8081 29452:8082 29453:8083 29454:8084 29455:8085 29456:8086 29457:8087
start_nginx fpmalt-nginx-b nginxB.conf nginx:alpine \
  29421:8091 29422:8092 29423:8093 29424:8094 29425:8095 29426:8096 29427:8097
start_nginx fpmalt-nginx-c nginxC.conf nginx:alpine \
  29431:8101 29432:8102 29433:8103 29434:8104 29435:8105
start_nginx fpmalt-nginx-d nginxD.conf nginx:1.17.10-alpine \
  29441:8111 29442:8112 29443:8113

sleep 3
docker ps --filter name=fpmalt --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
