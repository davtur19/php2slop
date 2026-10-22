set pagination off
set confirm off
set $n = 0
break php_var_unserialize_init
commands
silent
set $n = $n + 1
printf "INIT n=%d level=%ld data=%p caller=%p\n", $n, basic_globals.unserialize.level, basic_globals.unserialize.data, *(void**)$rsp
continue
end
break zif_unserialize
commands
silent
printf "ZIF_UNSER level=%ld data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
continue
end
break ps_srlzr_decode_php_binary
commands
silent
printf "SESSDEC level=%ld data=%p vallen=%lu\n", basic_globals.unserialize.level, basic_globals.unserialize.data, $rsi
continue
end
continue
printf "STOPPED\n"
detach
quit
