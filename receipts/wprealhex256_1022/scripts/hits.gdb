set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
break php_session_decode
commands
silent
printf "DECODE data=%p val=%p len=%lu level=%ld pser=%p ser1decode=%p\n", $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, *(void**)0x22d0f20, *(void**)0x22c54c8
continue
end
break *0x9e702c
commands
silent
if $rbx > 1000000
printf "BIGKEY C=%p val=%p len=%lu P=%p off=%ld\n", $rax, $rax+0x18, $rbx, basic_globals.unserialize.data, (long)basic_globals.unserialize.data-(long)($rax+0x18)
end
continue
end
continue
