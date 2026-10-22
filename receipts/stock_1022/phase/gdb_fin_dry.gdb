set pagination off
set confirm off
set $n=0
break php_session_decode
commands
 silent
 set $n=$n+1
 printf "DECODE n=%d str=%p val=%p len=%llu bg=%d bgd=%p ser1=%p ser2=%p\n", $n, $rdi, $rdi+24, *(unsigned long long *)($rdi+16), basic_globals.unserialize.level, basic_globals.unserialize.data, *(unsigned long long *)0x22c54c8, *(unsigned long long *)0x22c54e0
 continue
end
break zif_passthru
commands
 silent
 printf "ZIF_PASSTHRU exec=%p rsi=%llu numargs=%d arg1=%p type=%d\n", $rdi, $rsi, *(int *)($rdi+0x2c), *(unsigned long long *)($rdi+0x50), *(unsigned char *)($rdi+0x58)
 x/2gx *(unsigned long long *)($rdi+0x50)
 detach
 quit
end
continue
