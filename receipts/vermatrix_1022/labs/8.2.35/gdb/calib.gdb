set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2name=%s\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].name
x/9gx &ps_serializers
if $nh == 1
  printf "VAL1 first 0x40:\n"
  x/8gx ((zend_string*)$rdi)->val
end
if $nh >= 2
  printf "VAL2 first 0x80:\n"
  x/16gx ((zend_string*)$rdi)->val
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
