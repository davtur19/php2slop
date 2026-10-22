set pagination off
set confirm off
set $nh = 0
set $ns = 0
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
break php_set_session_var
commands
silent
set $ns = $ns + 1
set $slot = (zval*)state_val->value.ptr
printf "SETVAR#%d name=[%s] slot=%p type=0x%x\n", $ns, name->val, $slot, $slot->u1.type_info
if ($slot->u1.type_info & 0xff) == 6
  printf "  STR zend=%p len=%lu val=%p\n", $slot->value.str, $slot->value.str->len, $slot->value.str->val
  if $ns == 1
    printf "  DUMP at S (%p) 192 qwords:\n", $slot->value.str
    x/192gx $slot->value.str
  end
end
continue
end
continue
