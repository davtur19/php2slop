set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $P = (char*)basic_globals.unserialize.data
printf "P=%p level=%ld\n", $P, basic_globals.unserialize.level
x/6gx $P
set $B0 = *(unsigned long*)($P+0x18)
printf "B0=%p used=%ld\n", (void*)$B0, *(long*)($B0+0x4000)
watch *(unsigned long*)($P+0x18)
commands
silent
printf "WATCH P+0x18 now=%p\n", *(unsigned long*)($P+0x18)
bt 8
continue
end
set $n = 0
break var_tmp_var
commands
silent
set $n = $n + 1
printf "VT n=%d P=%p first=%p last=%p fd=%p ld=%p used=%ld\n", $n, $P, *(void**)$P, *(void**)($P+8), *(void**)($P+16), *(void**)($P+24), *(long*)(*(unsigned long*)($P+24)+0x4000)
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rcx rax
detach
quit
