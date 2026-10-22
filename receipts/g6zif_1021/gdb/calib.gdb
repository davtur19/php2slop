set pagination off
set confirm off
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d str=%p val=%p len=%lu level=%ld data=%p ser2decode=%p ser2encode=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].encode
x/6gx 0x14c1b50
if $nh == 1
  printf "VAL1 bytes:\n"
  x/8gx ((zend_string*)$rdi)->val
  x/8gx basic_globals.unserialize.data
  x/4gx basic_globals.unserialize.data->last_dtor
end
if $nh == 2
  printf "VAL2 bytes (first 0x80):\n"
  x/16gx ((zend_string*)$rdi)->val
end
if $nh >= 2
  detach
  quit
end
continue
end
continue
