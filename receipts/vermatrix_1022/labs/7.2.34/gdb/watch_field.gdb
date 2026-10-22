set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
watch *(long*)0x7ffff7a5e220
commands
silent
printf "WATCH addr=0x7ffff7a5e220 rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rcx rax rbx rbp rsp
x/6i $rip-12
detach
quit
end
continue
printf "STOPPED rip=%p\n", $rip
bt
detach
quit
