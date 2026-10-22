set pagination off
set confirm off
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d str=%p val=%p len=%lu level=%ld data=%p ser2decode=%p\n", $nh, data, data->val, data->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode
if $nh >= 2
  detach
  quit
end
continue
end
continue
