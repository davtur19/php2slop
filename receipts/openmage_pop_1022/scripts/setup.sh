#!/bin/bash
# Lab setup for the OpenMage session-injection + stock POP chain receipt.
# Private lab only: new FPM masters, new nginx instances, loopback ports 28896/28897.
set -euo pipefail
R=/tmp/opencode/research/openmage_pop_20261022T021222Z
NP=/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
PIE=/tmp/opencode/realapps/install_realapps/sbin/php-fpm
NGINX=/opt/nginx-1.30.1/sbin/nginx
LIB_NP=/tmp/opencode/realapps/icu-out/lib
LIB_PIE=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib

mkdir -p "$R"/{conf,log,run,phase,req,scripts,markers,sess}
mkdir -p "$R"/run/nginx_np/{client_body,proxy,fastcgi,uwsgi,scgi}
mkdir -p "$R"/run/nginx_pie/{client_body,proxy,fastcgi,uwsgi,scgi}

# ---------------------------------------------------------------- lab-only class
cat > "$R/www/lib/TestClass.php" <<'PHP'
<?php
/**
 * LAB-ONLY class for the OpenMage session-injection receipt.
 * Not part of OpenMage. It exists solely to show that the *application's*
 * session_start() autoloads a class named in the session file and runs its
 * magic methods. Markers live outside the docroot.
 */
class TestClass
{
    public function __wakeup()
    {
        @file_put_contents('/tmp/opencode/research/openmage_pop_20261022T021222Z/markers/testclass_wakeup.log',
            date('c') . ' wakeup pid=' . getmypid() . ' sapi=' . PHP_SAPI . "\n", FILE_APPEND);
        @touch('/tmp/opencode/research/openmage_pop_20261022T021222Z/MARK_WAKEUP');
    }

    public function __destruct()
    {
        @file_put_contents('/tmp/opencode/research/openmage_pop_20261022T021222Z/markers/testclass_destruct.log',
            date('c') . ' destruct pid=' . getmypid() . ' sapi=' . PHP_SAPI . "\n", FILE_APPEND);
        @touch('/tmp/opencode/research/openmage_pop_20261022T021222Z/MARK_DESTRUCT');
    }
}
PHP

# ---------------------------------------------------------------- sink script
cat > "$R/www/lab_upload_sink.php" <<'PHP'
<?php
/* LAB-ONLY upload sink: deliberately does NOT call session_start().
   The rfc1867 upload-progress handler is the only session user here. */
header('Content-Type: text/plain');
echo "SINK\n";
PHP

# ---------------------------------------------------------------- FPM: non-PIE
cat > "$R/conf/fpm.np.conf" <<EOF
[global]
pid = $R/run/fpm_np.pid
error_log = $R/log/fpm_np.error.log
log_level = notice
daemonize = yes
process_control_timeout = 10
emergency_restart_threshold = 0

; Reader pool: the stock OpenMage application. NO session.* / upload_progress.*
; overrides -> PHP defaults (serialize_handler=php, upload_progress.cleanup=On).
[app_np]
user = davide
group = davide
listen = $R/run/app_np.sock
listen.mode = 0660
pm = static
pm.max_children = 2
pm.max_requests = 0
catch_workers_output = yes
access.log = $R/log/fpm_np.access.log
access.format = "%p|%d|%t|%m|%s"
php_admin_value[error_log] = $R/log/php_np.error.log
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_value[error_reporting] = 32767
php_value[memory_limit] = 512M
php_value[post_max_size] = 16M
php_value[upload_max_filesize] = 16M
php_value[max_execution_time] = 120
php_value[max_input_time] = 120
php_value[default_socket_timeout] = 60

; Writer pool (deployment delta: php_serialize writer, shared save_path).
; upload_progress.cleanup is left at the PHP default (On).
[writer_np]
user = davide
group = davide
listen = $R/run/writer_np.sock
listen.mode = 0660
pm = static
pm.max_children = 2
pm.max_requests = 0
catch_workers_output = yes
access.log = $R/log/fpm_np.access.log
access.format = "%p|%d|%t|%m|%s|w"
php_admin_value[error_log] = $R/log/php_np.error.log
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_value[error_reporting] = 32767
php_value[memory_limit] = 256M
php_value[post_max_size] = 16M
php_value[upload_max_filesize] = 16M
php_value[max_execution_time] = 120
php_value[max_input_time] = 120
php_value[session.serialize_handler] = php_serialize
php_value[session.save_path] = $R/www/var/session
php_value[session.use_strict_mode] = 0

; Control pool: stock php writer, same save_path. Shows the delimiter rejection.
[writer_stock_np]
user = davide
group = davide
listen = $R/run/writer_stock_np.sock
listen.mode = 0660
pm = static
pm.max_children = 1
pm.max_requests = 0
catch_workers_output = yes
access.log = $R/log/fpm_np.access.log
access.format = "%p|%d|%t|%m|%s|s"
php_admin_value[error_log] = $R/log/php_np.error.log
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_value[error_reporting] = 32767
php_value[memory_limit] = 256M
php_value[post_max_size] = 16M
php_value[upload_max_filesize] = 16M
php_value[max_execution_time] = 120
php_value[max_input_time] = 120
php_value[session.save_path] = $R/www/var/session
php_value[session.use_strict_mode] = 0
EOF

# ---------------------------------------------------------------- FPM: PIE
sed -e "s#fpm_np#fpm_pie#g" -e "s#app_np#app_pie#g" -e "s#writer_np#writer_pie#g" \
    -e "s#writer_stock_np#writer_stock_pie#g" "$R/conf/fpm.np.conf" > "$R/conf/fpm.pie.conf"
# the stock-control pool is not needed on the PIE master; keep the file simple
python3 - "$R/conf/fpm.pie.conf" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
i = s.index('; Control pool:')
open(p, 'w').write(s[:i].rstrip() + '\n')
PY

# ---------------------------------------------------------------- nginx
mk_nginx() { # $1=file $2=port $3=prefix $4=app_sock $5=writer_sock $6=stock_sock $7=tag
cat > "$1" <<EOF
worker_processes 1;
pid $3/nginx.pid;
error_log $R/log/nginx_$7.log notice;
events { worker_connections 128; }
http {
    client_body_temp_path $3/client_body;
    proxy_temp_path $3/proxy;
    fastcgi_temp_path $3/fastcgi;
    uwsgi_temp_path $3/uwsgi;
    scgi_temp_path $3/scgi;
    include /opt/nginx-1.30.1/conf/mime.types;
    default_type application/octet-stream;
    access_log $R/log/nginx_$7.access.log;
    client_max_body_size 16m;
    client_body_timeout 120s;
    send_timeout 120s;
    fastcgi_request_buffering off;
    server {
        listen 127.0.0.1:$2;
        server_name 127.0.0.1;
        root $R/www;
        index index.php index.html;
        location = /lab_upload_sink.php {
            include /tmp/opencode/realapps/nginx/fastcgi_params;
            fastcgi_pass unix:$5;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            fastcgi_read_timeout 120s;
            fastcgi_send_timeout 120s;
        }
        location = /lab_upload_stock.php {
            include /tmp/opencode/realapps/nginx/fastcgi_params;
            fastcgi_pass unix:$6;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            fastcgi_read_timeout 120s;
            fastcgi_send_timeout 120s;
        }
        location / { try_files \$uri \$uri/ /index.php?\$args; }
        location ~ \\.php\$ {
            include /tmp/opencode/realapps/nginx/fastcgi_params;
            fastcgi_pass unix:$4;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            fastcgi_read_timeout 120s;
            fastcgi_send_timeout 120s;
        }
    }
}
EOF
}
mk_nginx "$R/conf/nginx.np.conf"  28896 "$R/run/nginx_np"  "$R/run/app_np.sock" "$R/run/writer_np.sock" "$R/run/writer_stock_np.sock" np
mk_nginx "$R/conf/nginx.pie.conf" 28897 "$R/run/nginx_pie" "$R/run/app_pie.sock" "$R/run/writer_pie.sock" "-" pie

# ---------------------------------------------------------------- start
LD_LIBRARY_PATH="$LIB_NP" "$NP" -y "$R/conf/fpm.np.conf"
LD_LIBRARY_PATH="$LIB_PIE" "$PIE" -y "$R/conf/fpm.pie.conf"
"$NGINX" -c "$R/conf/nginx.np.conf"
"$NGINX" -c "$R/conf/nginx.pie.conf"
sleep 1
echo "fpm_np.pid  $(cat "$R/run/fpm_np.pid")"
echo "fpm_pie.pid $(cat "$R/run/fpm_pie.pid")"
echo "nginx_np.pid $(cat "$R/run/nginx_np/nginx.pid")"
echo "nginx_pie.pid $(cat "$R/run/nginx_pie/nginx.pid")"
