set pagination off
set confirm off
set breakpoint pending on
printf "PRE level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
break php_basic_early_rinit
commands
silent
printf "TL EARLY_RINIT_ENTRY level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
continue
end
break php_hash_environment
commands
silent
printf "TL HASH_ENV_ENTRY level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
continue
end
break php_var_unserialize_init if basic_globals.unserialize.level != 0
commands
silent
printf "TL INIT_STALE level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
bt 8
continue
end
continue
