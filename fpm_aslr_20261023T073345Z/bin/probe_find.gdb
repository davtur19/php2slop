set pagination off
set confirm off
set $bg=(char*)&basic_globals
set $done=0
break php_var_unserialize_init
commands
silent
set $d=*(void**)($bg+0x368)
printf "U_INIT lock=%u udata=%p ulevel=%u\n", *(unsigned int*)($bg+0x350), $d, *(unsigned int*)($bg+0x370)
if $d != 0 && $done == 0
  set $done=1
  printf "WORDS %p %p %p %p\n", *(void**)$d, *(void**)($d+8), *(void**)($d+16), *(void**)($d+24)
  printf "CHUNKBASE %p\n", ((long)$d & ~0x1fffff)
  find /b ((long)$d & ~0x1fffff), $d+0x40, 0xde, 0xad, 0xbe, 0xef
  printf "FIND_DONE\n"
end
continue
end
break _zend_bailout
commands
silent
printf "BAILOUT udata=%p ulevel=%u\n", *(void**)($bg+0x368), *(unsigned int*)($bg+0x370)
continue
end
handle SIGSEGV stop print
continue
printf "SIGSEGV rax=%p\n", $rax
detach
quit
