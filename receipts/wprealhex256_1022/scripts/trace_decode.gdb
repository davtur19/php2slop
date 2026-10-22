set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
break php_session_decode
commands
silent
printf "DECODE data=%p len=%lu level=%ld\n", $rdi, ((zend_string*)$rdi)->len, basic_globals.unserialize.level
bt 4
continue
end
continue
