set pagination off
set confirm off
set $bg=(char*)&basic_globals
break php_var_unserialize_init
commands
silent
printf "TRACE INIT_ENTRY lock=%u luck_data=%p level=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
continue
end
break php_var_unserialize_destroy
commands
silent
printf "TRACE DESTROY_ENTRY d=%p lock=%u data=%p level=%u\n", d, *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
continue
end
continue
