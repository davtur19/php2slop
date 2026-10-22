set pagination off
set confirm off
set auto-load safe-path /
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2encode=%p pser=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].encode, *(void**)0x22d0f20
x/9gx &ps_serializers
if $nh == 1
  printf "VAL1 first 0x60:\n"
  x/12gx ((zend_string*)$rdi)->val
  printf "PSER0 %p %p %p\n", ps_serializers[0].name, ps_serializers[0].encode, ps_serializers[0].decode
  printf "PSER1 %p %p %p\n", ps_serializers[1].name, ps_serializers[1].encode, ps_serializers[1].decode
  printf "PSER2 %p %p %p\n", ps_serializers[2].name, ps_serializers[2].encode, ps_serializers[2].decode
  printf "PSER3 %p %p %p\n", ps_serializers[3].name, ps_serializers[3].encode, ps_serializers[3].decode
  if basic_globals.unserialize.data
    printf "BG P:\n"
    x/9gx basic_globals.unserialize.data
    if basic_globals.unserialize.data->first_dtor
      printf "BG B0:\n"
      x/4gx basic_globals.unserialize.data->first_dtor
    end
  end
end
if $nh == 2
  printf "VAL2 first 0x80:\n"
  x/16gx ((zend_string*)$rdi)->val
end
if $nh >= 2
  detach
  quit
end
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rcx rax rsp rbp
x/4i $rip
detach
quit
