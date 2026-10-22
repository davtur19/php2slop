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
set $len = *(unsigned long long *)($rdi+16)
printf "DECODE n=%d data=%p val=%p len=%llu bg=%d bgd=%p decodefield=%p\n", $n, $rdi, $rdi+24, $len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[1].decode
continue
end
break php_set_session_var
commands
silent
printf "SETVAR name=%p nlen=%lu namebytes=%s val=%p type=0x%x\n", name, name->len, name->val, state_val, state_val->u1.type_info
continue
end
break zif_passthru
commands
silent
printf "ZIF_PASSTHRU rdi=%p rsi=%llu\n", $rdi, $rsi
x/8gx $rdi
continue
end
break popen
commands
silent
printf "POPEN cmd=%s\n", $rdi
continue
end
break php_request_shutdown
commands
silent
printf "REQUEST_SHUTDOWN static=%p\n", ps_serializers[1].decode
detach
quit
end
printf "ARMED\n"
continue
