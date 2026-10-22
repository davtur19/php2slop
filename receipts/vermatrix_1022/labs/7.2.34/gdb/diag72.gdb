set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
break php_session_decode
commands
silent
printf "DECODE data=%p val=%p len=%lu level=%ld bgdata=%p ser2=%p\n", $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode
set $p = basic_globals.unserialize.data
if $p
  printf "P_AT_DECODE %p:\n", $p
  x/6gx $p
end
continue
end
break var_tmp_var
commands
silent
set $pp = *(void**)$rdi
printf "TMPVAR var_hashx=%p P=%p\n", $rdi, $pp
if $pp
  x/6gx $pp
end
continue
end
break *0x54b0c4
commands
silent
printf "USED rdx=%p used=%ld slot=%p\n", $rdx, *(long*)($rdx+0x4000), $rdx + 16*(*(long*)($rdx+0x4000))
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rax rsp rbp
detach
quit
