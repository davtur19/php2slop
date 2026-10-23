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
  set $base=((long)$d & ~0x1fffff)
  printf "X=%p BASE=%p\n", $d, $base
  printf "MAGIC1_SEARCH\n"
  find /g $base, $d+0x40, 0x1122334455667788
  printf "MAGIC2_SEARCH\n"
  find /g $base, $d+0x40, 0x8877665544332211
  printf "MAGIC_DONE\n"
  x/8gx $d
end
continue
end
handle SIGSEGV stop print
continue
printf "SIGSEGV rax=%p rip=%p\n", $rax, $rip
detach
quit
