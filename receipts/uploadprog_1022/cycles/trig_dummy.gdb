set pagination off
set confirm off
attach 1675577
set $n=0
break *0x9e68b5
commands
silent
set $n=$n+1
printf "DECODE n=%d data=%p val=%p len=%ld bg=%u bgd=%p\n",$n,$rdi,$rdi+0x18,*(long*)($rdi+0x10),*(unsigned int*)0x22d1c80,*(void**)0x22d1c78
if $n >= 2
  detach
  quit
end
continue
end
continue
