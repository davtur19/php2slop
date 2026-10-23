set pagination off
set confirm off
set $bg=(char*)&basic_globals
break php_var_unserialize_init
commands
silent
set $d=*(void**)($bg+0x368)
printf "U_INIT lock=%u udata=%p ulevel=%u", *(unsigned int*)($bg+0x350), $d, *(unsigned int*)($bg+0x370)
if $d != 0
  printf " W0=%p W1=%p W2=%p W3=%p\n", *(void**)$d, *(void**)($d+8), *(void**)($d+16), *(void**)($d+24)
else
  printf "\n"
end
continue
end
break php_request_shutdown
commands
silent
printf "SHUTDOWN lock=%u udata=%p ulevel=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
continue
end
continue
