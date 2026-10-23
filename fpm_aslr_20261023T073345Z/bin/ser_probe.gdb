set pagination off
set confirm off
set $bg=(char*)&basic_globals
set $n=0
break php_var_serialize_init
commands
silent
set $s=*(void**)($bg+0x358)
printf "S_INIT sdata=%p slevel=%u\n", $s, *(unsigned int*)($bg+0x360)
if $s != 0
  printf "SWORDS %p %p %p %p %p %p %p %p\n", *(void**)$s, *(void**)($s+8), *(void**)($s+16), *(void**)($s+24), *(void**)($s+32), *(void**)($s+40), *(void**)($s+48), *(void**)($s+56)
  printf "PDESTRUCTOR=%p N=%p CHUNKBASE=%p\n", *(void**)($s+48), *(void**)($s+56), ((long)$s & ~0x1fffff)
end
continue
end
break php_request_shutdown
commands
silent
set $s=*(void**)($bg+0x358)
printf "REQSHUTDOWN sdata=%p slevel=%u\n", $s, *(unsigned int*)($bg+0x360)
if $s != 0
  printf "SWORDS2 %p %p %p %p %p %p %p %p\n", *(void**)$s, *(void**)($s+8), *(void**)($s+16), *(void**)($s+24), *(void**)($s+32), *(void**)($s+40), *(void**)($s+48), *(void**)($s+56)
end
set $n=$n+1
if $n >= 2
  detach
  quit
end
continue
end
handle SIGSEGV stop print
continue
printf "SIGSEGV rax=%p rip=%p\n", $rax, $rip
bt 8
detach
quit
