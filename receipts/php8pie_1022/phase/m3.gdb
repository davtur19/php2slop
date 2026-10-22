set pagination off
set confirm off
handle SIGSEGV stop print nopass
set $nh = 0
set $nt = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d str=%p val=%p len=%lu level=%ld data=%p\n", $nh, data, data->val, data->len, basic_globals.unserialize.level, basic_globals.unserialize.data
if $nh == 1
  printf "FAKEP last=%p first_dtor=%p last_dtor=%p used=%ld max=%ld\n", basic_globals.unserialize.data->last, basic_globals.unserialize.data->first_dtor, basic_globals.unserialize.data->last_dtor, basic_globals.unserialize.data->entries.used_slots, basic_globals.unserialize.data->max_depth
  printf "TMP used=%ld next=%p\n", basic_globals.unserialize.data->last_dtor->used_slots, basic_globals.unserialize.data->last_dtor->next
end
continue
end
break var_tmp_var
commands
silent
set $nt = $nt + 1
printf "TMPVAR call=%d used=%ld\n", $nt, basic_globals.unserialize.data->last_dtor->used_slots
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
printf "STOPPED\n"
bt
detach
quit
