set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $P = (char*)basic_globals.unserialize.data
set $nh = 0
set $nv = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld ser2=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, ps_serializers[2].decode
if $nh >= 2
  detach
  quit
end
continue
end
break var_tmp_var
commands
silent
set $nv = $nv + 1
printf "VT n=%d P=%p ld=%p used=%ld\n", $nv, $P, *(void**)($P+24), *(long*)(*(unsigned long*)($P+24)+0x4000)
continue
end
continue
printf "STOPPED\n"
bt 6
detach
quit
