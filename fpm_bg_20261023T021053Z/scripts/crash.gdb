set pagination off
set confirm off
set breakpoint pending on
printf "PRE_ATTACH level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
break php_var_unserialize_init if basic_globals.unserialize.level != 0
commands
silent
printf "TL INIT_STALE level=%d lock=%d data=%p\n", basic_globals.unserialize.level, basic_globals.serialize_lock, basic_globals.unserialize.data
bt 10
continue
end
continue
printf "=== STOPPED (signal) ===\n"
bt 20
info registers rip rdi rsi rdx rax
x/8i $pc
p/x $pc
p $_siginfo
