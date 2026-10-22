set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
set $nf = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2name=%s\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].name
if $nh == 1
  x/8gx ((zend_string*)$rdi)->val
end
continue
end
break system
commands
silent
printf "SYSTEM hit cmd=%p\n", $rdi
x/s $rdi
continue
end
break php_session_flush
commands
silent
set $nf = $nf + 1
printf "FLUSH n=%d ser2=%p\n", $nf, ps_serializers[2].decode
if $nf >= 2
  detach
  quit
end
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rcx rax
detach
quit
