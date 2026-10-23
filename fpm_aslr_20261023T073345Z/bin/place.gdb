set pagination off
set confirm off
set $bg=(char*)&basic_globals
set $done=0
break php_var_unserialize_init
commands
silent
set $d=*(void**)($bg+0x368)
printf "U_INIT udata=%p ulevel=%u\n", $d, *(unsigned int*)($bg+0x370)
if $d != 0 && $done == 0
  set $done=1
  printf "X=%p\n", $d
  find /g ((long)$d & ~0x1fffff), $d+0x400, 0x0102030405060708
  printf "DONE_FIND\n"
end
continue
end
handle SIGSEGV stop print
continue
printf "SIGSEGV rax=%p rip=%p\n", $rax, $rip
detach
quit
