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
  printf "WORDS %p %p %p %p %p %p %p %p\n", *(void**)$d, *(void**)($d+8), *(void**)($d+16), *(void**)($d+24), *(void**)($d+32), *(void**)($d+40), *(void**)($d+48), *(void**)($d+56)
  printf "TARGET %p\n", $d+0x2000
  x/6gx $d+0x2000
end
continue
end
break php_request_shutdown
commands
silent
set $d=*(void**)($bg+0x368)
printf "REQSHUTDOWN udata=%p ulevel=%u\n", $d, *(unsigned int*)($bg+0x370)
if $d != 0
  printf "WORDS2 %p %p %p %p %p %p %p %p\n", *(void**)$d, *(void**)($d+8), *(void**)($d+16), *(void**)($d+24), *(void**)($d+32), *(void**)($d+40), *(void**)($d+48), *(void**)($d+56)
  x/6gx $d+0x2000
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
bt 6
x/8gx *(void**)($bg+0x368)
detach
quit
