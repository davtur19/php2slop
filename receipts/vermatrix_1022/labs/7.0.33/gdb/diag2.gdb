set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
break ps_srlzr_decode_php_binary
commands
silent
printf "SERDEC level=%ld data=%p last_dtor=%p used=%ld A=(%p,%d) A16=(%p,%d)\n", basic_globals.unserialize.level, basic_globals.unserialize.data, basic_globals.unserialize.data->last_dtor, ((var_dtor_entries*)basic_globals.unserialize.data->last_dtor)->used_slots, *(void**)0x804e20, *(int*)0x804e28, *(void**)0x804e30, *(int*)0x804e38
continue
end
break var_tmp_var
commands
silent
printf "TMPVAR enter level=%ld data=%p last_dtor=%p used=%ld\n", basic_globals.unserialize.level, basic_globals.unserialize.data, (*var_hashx)->last_dtor, ((var_dtor_entries*)(*var_hashx)->last_dtor)->used_slots
finish
continue
end
break php_session_normalize_vars
commands
silent
printf "NORMALIZE A=(%p,%d) A16=(%p,%d) A32=(%p,%d) A48=(%p,%d)\n", *(void**)0x804e20, *(int*)0x804e28, *(void**)0x804e30, *(int*)0x804e38, *(void**)0x804e40, *(int*)0x804e48, *(void**)0x804e50, *(int*)0x804e58
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt 8
detach
quit
