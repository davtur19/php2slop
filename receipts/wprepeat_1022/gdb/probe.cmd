set pagination off
set confirm off
catch signal SIGSEGV
commands
silent
printf "SIGSEGV rip=%p\n", $pc
detach
quit
end
catch signal SIGABRT
commands
silent
printf "SIGABRT rip=%p\n", $pc
detach
quit
end
set $n=0
break php_session_decode
commands
silent
set $n=$n+1
printf "DECODE n=%d data=%p val=%p len=%lu bg=%d bgd=%p\n", $n, data, data->val, data->len, basic_globals.unserialize.level, basic_globals.unserialize.data
continue
end
break php_set_session_var
commands
silent
printf "SETVAR name=%p nlen=%lu namebytes=%s state_val=%p type=0x%x valueptr=%p\n", name, name->len, name->val, state_val, state_val->u1.type_info, state_val->value.ptr
x/2gx state_val
x/8gx state_val->value.ptr
if name->len == 1 && name->val[0] == 83
  printf "S_ZVAL %p\n", state_val
  x/2gx state_val
  printf "S_VALUEPTR %p\n", state_val->value.ptr
  x/8gx state_val->value.ptr
  printf "S_VALUEPTR_PLUS8 %p\n", (char*)state_val->value.ptr+8
  x/4gx ((char*)state_val->value.ptr+8)
end
continue
end
break var_tmp_var
commands
silent
set $dp = *var_hashx
printf "TMPVAR var_hashx=%p d=%p last_dtor=%p used=%ld next=%p\n", var_hashx, $dp, $dp->last_dtor, $dp->last_dtor->used_slots, $dp->last_dtor->next
x/12gx $dp
continue
end
break php_request_shutdown
commands
silent
printf "REQUEST_SHUTDOWN\n"
detach
quit
end
printf "ARMED\n"
continue
