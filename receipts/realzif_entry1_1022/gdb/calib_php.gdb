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
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p pser=%p ser1decode=%p ser1encode=%p ser2decode=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, *(void**)0x22d0f20, ps_serializers[1].decode, ps_serializers[1].encode, ps_serializers[2].decode
x/9gx &ps_serializers
if $nh == 1
  printf "VAL1 first 0x60:\n"
  x/12gx ((zend_string*)$rdi)->val
  printf "RAW 0x2c numargs=%u 0x50 arg1=%p 0x58 type=%u\n", *(unsigned int*)(((zend_string*)$rdi)->val+0x2c), *(void**)(((zend_string*)$rdi)->val+0x50), *(unsigned char*)(((zend_string*)$rdi)->val+0x58)
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
  printf "VAL2 RAW 0x2c numargs=%u 0x50 arg1=%p 0x58 type=%u\n", *(unsigned int*)(((zend_string*)$rdi)->val+0x2c), *(void**)(((zend_string*)$rdi)->val+0x50), *(unsigned char*)(((zend_string*)$rdi)->val+0x58)
  printf "VAL2 key bytes 0x00..0x5f:\n"
  x/12gx ((zend_string*)$rdi)->val
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
