set pagination off
set confirm off
set breakpoint pending on
set print pretty off
break php_request_shutdown
commands
silent
printf "TL SHUTDOWN_ENTRY level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
continue
end
break php_hash_environment
commands
silent
printf "TL HASH_ENV_ENTRY level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
continue
end
break zm_activate_basic
commands
silent
printf "TL RINIT_BASIC_ENTRY level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
continue
end
break php_var_unserialize_init if basic_globals.unserialize.level != 0
commands
silent
printf "TL INIT_STALE level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
bt 18
continue
end
break php_var_unserialize_destroy if basic_globals.unserialize.level != 0
commands
silent
printf "TL DESTROY_ENTRY level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
continue
end
continue
