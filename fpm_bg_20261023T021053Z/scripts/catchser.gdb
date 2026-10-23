set pagination off
set confirm off
set $bg=(char*)&basic_globals
catch signal SIGSEGV
commands
silent
printf "SIGSEGV pc=%p\n", $pc
bt 14
info registers rip rax rbx rdi rsi rdx
detach
quit
end
break php_request_startup
commands
silent
printf "REQSTART sdata=%p slevel=%u\n", *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
continue
end
break php_var_serialize_init
commands
silent
printf "SER_INIT sdata=%p slevel=%u\n", *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
continue
end
break php_var_serialize_destroy
commands
silent
printf "SER_DESTROY sdata=%p slevel=%u\n", *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
continue
end
break php_request_shutdown
commands
silent
printf "REQSHUTDOWN sdata=%p slevel=%u\n", *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
continue
end
continue
