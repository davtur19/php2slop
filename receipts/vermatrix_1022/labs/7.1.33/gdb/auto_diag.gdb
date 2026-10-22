set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
set $nv = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p len=%lu level=%ld bgdata=%p ser2=%p\n", $nh, $rdi, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode
if basic_globals.unserialize.data
  x/5gx basic_globals.unserialize.data
end
continue
end
break var_tmp_var
commands
silent
set $nv = $nv + 1
set $p = *(char**)var_hashx
set $ld = *(unsigned long*)($p+24)
printf "VT n=%d P=%p ld=%p used=%ld\n", $nv, $p, (void*)$ld, *(long*)($ld+0x4000)
continue
end
break php_session_flush
commands
silent
printf "FLUSH level=%ld bgdata=%p ser2=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode
continue
end
break system
commands
silent
printf "SYSTEM cmd=%p\n", $rdi
x/s $rdi
continue
end
continue
printf "STOPPED\n"
bt 8
detach
quit
