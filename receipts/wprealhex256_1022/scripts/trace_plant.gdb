set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
break php_session_decode
commands
silent
printf "DECODE data=%p len=%lu level=%ld real=%lu limit=%lu\n", $rdi, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, alloc_globals.mm_heap->real_size, alloc_globals.mm_heap->limit
continue
end
break *0x9e702c
commands
silent
if $rbx > 1000000
printf "KEYALLOC namelen=%lu real=%lu limit=%lu\n", $rbx, alloc_globals.mm_heap->real_size, alloc_globals.mm_heap->limit
end
continue
end
break zend_mm_alloc_huge
commands
silent
if $rsi > 50000000
printf "HUGEREQ size=%lu real=%lu limit=%lu\n", $rsi, alloc_globals.mm_heap->real_size, alloc_globals.mm_heap->limit
end
continue
end
break zend_mm_safe_error
commands
silent
printf "SAFEERR real=%lu limit=%lu fmt=%s\n", alloc_globals.mm_heap->real_size, alloc_globals.mm_heap->limit, (char*)$rsi
continue
end
continue
