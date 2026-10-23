set pagination off
set confirm off
set $bg=(char*)&basic_globals
set $shut=0
define show
  printf "lock=%u sdata=%p slevel=%u udata=%p ulevel=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x358), *(unsigned int*)($bg+0x360), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
end
break php_request_startup
commands
silent
printf "REQSTART "
show
continue
end
break sapi_activate
commands
silent
printf "SAPI_ACTIVATE "
show
continue
end
break php_var_unserialize_init
commands
silent
printf "U_INIT_ENTRY "
show
bt 3
continue
end
break php_var_unserialize_destroy
commands
silent
printf "U_DESTROY_ENTRY d=%p ", $rdi
show
continue
end
break _zend_bailout
commands
silent
printf "ZEND_BAILOUT "
show
bt 6
continue
end
break php_request_shutdown
commands
silent
printf "REQSHUTDOWN "
show
set $shut=$shut+1
if $shut >= 2
  printf "AUTO_DETACH after %d shutdowns\n", $shut
  detach
  quit
end
continue
end
continue
