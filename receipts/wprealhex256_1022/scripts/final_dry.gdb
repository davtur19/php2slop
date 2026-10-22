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
printf "DECODE #%d data=%p val=%p len=%lu level=%ld ser1=%p P=%p\n",$hits,$rdi,$v,$l,basic_globals.unserialize.level,*(void**)0x22c54c8,basic_globals.unserialize.data
if $hits==2
  printf "RAW2c=%08x RAW50=%p RAW58=%u\n",*(unsigned int*)($v+0x2c),*(void**)($v+0x50),*(unsigned char*)($v+0x58)
  printf "PBYTES "
  x/10gx basic_globals.unserialize.data
  printf "CMD "
  x/s (*(char**)($v+0x50))+0x18
end
if $hits>=5
  detach
  quit
end
continue
end
break *0xa3c074
commands
silent
printf "ZIF_PASSTHRU rdi=%p rsi=%p numargs=%u arg1=%p type=%u\n",$rdi,$rsi,*(unsigned int*)($rdi+0x2c),*(void**)($rdi+0x50),*(unsigned char*)($rdi+0x58)
printf "ZCMD "
x/s (*(char**)($rdi+0x50))+0x18
continue
end
break *0xa3c047
commands
silent
printf "PHP_EXEC_RET eax=%d ser1=%p\n",$eax,*(void**)0x22c54c8
continue
end
continue
