#!/bin/bash
# Set up one isolated lab container for a PHP 8.4.x early build.
# usage: setup_build.sh <version> <port> <container> <run-dir>
#
# <run-dir>/conf/php.ini and <run-dir>/www/index.php are taken from the receipts
# (php-<version>/evidence/config/php.ini and php-<version>/evidence/docroot/index.php).
set -eu
V="$1"; PORT="$2"; C="$3"; D="$4"
mkdir -p "$D/conf" "$D/www" "$D/logs" "$D/out"
if [ ! -f "$D/conf/php.ini" ]; then
  docker run --rm --entrypoint cat "php:$V-apache" /usr/local/etc/php/php.ini-production > "$D/conf/php.ini"
fi
if [ ! -f "$D/www/index.php" ]; then
  printf '%s\n' '<?php echo "OK\n"; ?>' > "$D/www/index.php"
fi
cat > "$D/conf/000-default-p2s.conf" <<'EOF'
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/p2s-access.log p2s
</VirtualHost>
EOF
cat > "$D/conf/zz-p2s.conf" <<'EOF'
LogFormat "%P %{%s}t %m %U %>s %b %D" p2s
EOF
chmod 777 "$D/logs"
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" -p "127.0.0.1:$PORT:80" \
  -v "$D/conf/php.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$D/conf/000-default-p2s.conf:/etc/apache2/sites-enabled/000-default.conf:ro" \
  -v "$D/conf/zz-p2s.conf:/etc/apache2/conf-enabled/zz-p2s.conf:ro" \
  -v "$D/www:/var/www/html:ro" \
  -v "$D/logs:/var/log/apache2" \
  "php:$V-apache" >/dev/null
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/index.php" || true)
  [ "$code" = "200" ] && break
  sleep 0.25
done
echo "setup v=$V port=$PORT container=$C docroot=$D/www status=$code"
docker exec "$C" sh -c 'php -v | head -1; apache2 -v | head -1'
