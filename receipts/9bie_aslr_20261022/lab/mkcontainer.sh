#!/bin/bash
# usage: mkcontainer.sh <name> <port> <image> <ini|stock> 
set -e
name=$1; port=$2; image=$3; ini=$4
D=/tmp/opencode/research/9bie_aslr_20261022T095015Z/lab
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p 127.0.0.1:$port:80 "$image" >/dev/null
docker cp "$D/configs/index.php" "$name:/var/www/html/index.php"
docker cp "$D/configs/mpm_prefork.conf" "$name:/etc/apache2/mods-enabled/mpm_prefork.conf"
docker cp "$D/configs/apache-single.conf" "$name:/etc/apache2/conf-enabled/zz-single.conf"
if [ "$ini" != "stock" ]; then docker cp "$D/configs/$ini" "$name:/usr/local/etc/php/conf.d/zz-lab.ini"; fi
docker exec "$name" apache2ctl -k restart >/dev/null 2>&1 || docker restart "$name" >/dev/null
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/index.php" || true)
echo "$name port=$port image=$image ini=$ini http=$code"
