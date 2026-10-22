set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
set $hits=0
break php_session_decode
commands
silent
set $hits=$hits+1
set $v=((zend_string*)$rdi)->val
set $l=((zend_string*)$rdi)->len
printf "DECODE #%d data=%p val=%p len=%lu level=%ld ser1=%p\n", $hits,$rdi,$v,$l,basic_globals.unserialize.level,*(void**)0x22c54c8
if $l > 40000000
  printf "RAW2c=%08x RAW50=%p RAW58=%u\n", *(unsigned int*)($v+0x2c), *(void**)($v+0x50), *(unsigned char*)($v+0x58)
  printf "HEAD "
  x/16bx $v
  printf "PAY100 "
  x/8bx ($v+1700033+0x100)
  printf "PBYTES "
  x/10gx basic_globals.unserialize.data
end
if $hits>=7
  detach
  quit
end
continue
end
break *0x9e702c
commands
silent
if $rbx > 1000000
printf "BIGKEY C=%p len=%lu P=%p off=%ld\n",$rax,$rbx,basic_globals.unserialize.data,(long)basic_globals.unserialize.data-(long)($rax+0x18)
end
continue
end
continue
