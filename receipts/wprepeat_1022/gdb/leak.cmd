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
set $nhit=0
break php_session_decode
commands
silent
set $nhit=$nhit+1
printf "DECODE n=%d data=%p val=%p len=%lu bg_level=%d bg_data=%p\n", $nhit, data, data->val, data->len, basic_globals.unserialize.level, basic_globals.unserialize.data
if $nhit >= 2
  printf "LEAK_TWO_DECODES\n"
  detach
  quit
end
continue
end
break php_set_session_var
commands
silent
printf "SETVAR name=%p nlen=%lu namebytes=%s val=%p type=0x%x\n", name, name->len, name->val, state_val, state_val->u1.type_info
if name->len == 1 && name->val[0] == 83
  set $real=(zval*)state_val->value.ptr
  printf "SREAL z=%p type=0x%x str=%p sdata=%p slen=%lu\n", $real, $real->u1.type_info, $real->value.str, $real->value.str->val, $real->value.str->len
end
continue
end
printf "ARMED\n"
continue
