set pagination off
set confirm off
set breakpoint pending on
set $bg = (char*)&basic_globals
printf "PRE lock=%u data=%p level=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
break php_basic_early_rinit
commands
silent
printf "TL EARLY_RINIT_ENTRY lock=%u data=%p level=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
continue
end
break php_hash_environment
commands
silent
printf "TL HASH_ENV_ENTRY lock=%u data=%p level=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
continue
end
break php_var_unserialize_init if *(unsigned int*)($bg+0x370) != 0
commands
silent
printf "TL INIT_STALE lock=%u data=%p level=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
bt 8
continue
end
continue
