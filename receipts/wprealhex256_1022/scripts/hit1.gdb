set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
break php_session_decode
commands
silent
printf "HIT data=%p val=%p len=%lu level=%ld pser=%p ser1decode=%p\n", $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, *(void**)0x22d0f20, *(void**)0x22c54c8
detach
quit
end
continue
