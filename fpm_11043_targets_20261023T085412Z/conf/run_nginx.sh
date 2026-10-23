#!/bin/bash
# Start the lab nginx container (Debian 10 nginx 1.14.2-2+deb10u4) with all vhosts.
set -e
D=/tmp/opencode/research/fpm_11043_targets_20261023T085412Z
P=""
for p in $(grep -oE '^\s*listen [0-9]+;' "$D/conf/nginx/t11043.conf" | grep -oE '[0-9]+' | sort -un); do
  P="$P -p 127.0.0.1:$((p+11100)):$p"
done
docker rm -f t11043-nginx >/dev/null 2>&1 || true
# shellcheck disable=SC2086
docker run -d --name t11043-nginx --network t11043net $P \
  -v "$D/apps:/var/www:ro" \
  -v "$D/apps/wordpress:/var/www/html:ro" \
  -v "$D/conf/nginx:/etc/nginx/conf.d:ro" \
  -v "$D/conf/empty:/etc/nginx/sites-enabled:ro" \
  -v "$D/logs/nginx:/var/log/nginx" \
  t11043/nginx-deb10:1 nginx -g 'daemon off;'
sleep 2
docker ps --filter name=t11043-nginx --format '{{.Names}} {{.Status}}'
