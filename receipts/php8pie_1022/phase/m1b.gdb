set pagination off
set confirm off
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d str=%p val=%p len=%lu level=%ld data=%p\n", $nh, data, data->val, data->len, basic_globals.unserialize.level, basic_globals.unserialize.data
continue
end
break php_set_session_var
commands
silent
set $z = (zval*)state_val->value.ptr
printf "SETVAR name=[%s] ztype=%d ", name->val, $z->u1.type_info
if $z->u1.type_info == 6
  printf "str=%p len=%lu val=%p", $z->value.str, $z->value.str->len, $z->value.str->val
end
printf "\n"
continue
end
continue
