set pagination off
set confirm off
set $bg=(char*)&basic_globals
set $n=0
break php_var_unserialize_init
commands
silent
set $d=*(void**)($bg+0x368)
printf "U_INIT udata=%p ulevel=%u\n", $d, *(unsigned int*)($bg+0x370)
if $d != 0
  printf "W=%p %p %p\n", *(void**)$d, *(void**)($d+8), *(void**)($d+16)
end
continue
end
break php_request_shutdown
commands
silent
set $d=*(void**)($bg+0x368)
printf "REQSHUTDOWN udata=%p ulevel=%u W=%p %p %p\n", $d, *(unsigned int*)($bg+0x370), *(void**)$d, *(void**)($d+8), *(void**)($d+16)
if $d != 0
  printf "AT_X+40\n"
  x/4gx $d+0x40
  printf "AT_64K\n"
  x/4gx (((long)$d & ~0xffff)+0x40)
end
set $n=$n+1
if $n >= 2
  printf "DETACH\n"
  detach
  quit
end
continue
end
handle SIGSEGV stop print
continue
printf "SIGSEGV rax=%p rip=%p\n", $rax, $rip
bt 5
detach
quit
