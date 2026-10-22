set pagination off
set confirm off
set $n=0
break php_session_decode
commands
 silent
 set $n=$n+1
 set $len = *(unsigned long long *)($rdi+16)
 printf "DECODE n=%d data=%p val=%p len=%llu bg=%d bgd=%p\n", $n, $rdi, $rdi+24, $len, basic_globals.unserialize.level, basic_globals.unserialize.data
 if $n >= 2
   detach
   quit
 end
 continue
end
continue
