set pagination off
set confirm off
set $bg=(char*)&basic_globals
define show
  printf "lock=%u sdata=%p slevel=%u udata=%p ulevel=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x358), *(unsigned int*)($bg+0x360), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
end
set $final=0
break php_request_startup
commands
silent
printf "REQSTART "
show
continue
end
break php_var_unserialize_init
commands
silent
printf "UNSER_INIT "
show
bt 3
continue
end
break php_var_serialize_init
commands
silent
printf "SER_INIT "
show
bt 5
continue
end
break php_var_serialize_destroy
commands
silent
printf "SER_DESTROY "
show
continue
end
break shutdown_memory_manager
commands
silent
printf "PRE_MEMMGR "
show
set $final=$final+1
if $final >= 1
  printf "FINAL_STATE_REACHED\n"
  detach
  quit
end
continue
end
continue
printf "STOPPED_WITHOUT_MEMMGR\n"
bt 15
show
detach
quit
