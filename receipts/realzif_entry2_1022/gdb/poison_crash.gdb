set pagination off
set confirm off
set auto-load safe-path /
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nz = 0
break zif_passthru
commands
silent
set $nz = $nz + 1
printf "POISON_ZIF_PASSTHRU hit=%d rdi=%p rsi=%p\n", $nz, $rdi, $rsi
x/10gx $rdi
continue
end
break php_exec_ex
commands
silent
printf "POISON_PHP_EXEC_EX rdi=%p rsi=%p rdx=%p numargs=%u arg1=%p type=%u\n", $rdi, $rsi, $rdx, *(unsigned int*)($rdi+0x2c), *(void**)($rdi+0x50), *(unsigned char*)($rdi+0x58)
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rcx rax rsp rbp
x/4i $rip
detach
quit
