set pagination off
set confirm off
attach 1682756
set $n=0
break *0x9e68b5
commands
silent
set $n=$n+1
printf "DECODE n=%d data=%p val=%p len=%ld bg=%u bgd=%p\n",$n,$rdi,$rdi+0x18,*(long*)($rdi+0x10),*(unsigned int*)0x22d1c80,*(void**)0x22d1c78
continue
end
break *0xa3c074
commands
silent
printf "ZIF rdi=%p rsi=%ld numargs=%u arg=%p type=%u\n",$rdi,$rsi,*(unsigned int*)($rdi+0x2c),*(void**)($rdi+0x50),*(unsigned int*)($rdi+0x58)
set $a=*(void**)($rdi+0x50)
printf "ARG %p len=%ld cmd=",$a,*(long*)($a+0x10)
x/s $a+0x18
detach
quit
end
continue
