set pagination off
set confirm off
break _efree
commands
silent
printf "EFREE ptr=%p\n", $rdi
continue
end
break *0x54b05a
commands
silent
printf "ECALLOC_RET p=%p\n", $rax
continue
end
continue
printf "STOPPED\n"
detach
quit
