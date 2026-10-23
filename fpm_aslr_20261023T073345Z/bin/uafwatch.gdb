set pagination off
set confirm off
set $bg=(char*)&basic_globals
break php_var_unserialize_init
commands
silent
set $d=*(void**)($bg+0x368)
printf "U_INIT lock=%u udata=%p ulevel=%u\n", *(unsigned int*)($bg+0x350), $d, *(unsigned int*)($bg+0x370)
if $d != 0
  printf "WORDS %p %p %p %p %p %p %p %p\n", *(void**)$d, *(void**)($d+8), *(void**)($d+16), *(void**)($d+24), *(void**)($d+32), *(void**)($d+40), *(void**)($d+48), *(void**)($d+56)
end
continue
end
break php_var_serialize_init
commands
silent
set $s=*(void**)($bg+0x358)
printf "S_INIT lock=%u sdata=%p slevel=%u n=%u\n", *(unsigned int*)($bg+0x350), $s, *(unsigned int*)($bg+0x360), ($s?*(unsigned int*)($s+0x38):0)
if $s != 0
  printf "SWORDS %p %p %p %p %p %p %p %p\n", *(void**)$s, *(void**)($s+8), *(void**)($s+16), *(void**)($s+24), *(void**)($s+32), *(void**)($s+40), *(void**)($s+48), *(void**)($s+56)
end
continue
end
break _zend_bailout
commands
silent
printf "BAILOUT lock=%u udata=%p ulevel=%u sdata=%p slevel=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370), *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
bt 6
continue
end
break php_request_shutdown
commands
silent
printf "REQSHUTDOWN lock=%u udata=%p ulevel=%u sdata=%p slevel=%u\n", *(unsigned int*)($bg+0x350), *(void**)($bg+0x368), *(unsigned int*)($bg+0x370), *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
continue
end
handle SIGSEGV stop print
continue
printf "SIGSEGV_STOP\n"
bt
info registers rip rdi rsi rdx rax
printf "BG udata=%p ulevel=%u sdata=%p slevel=%u\n", *(void**)($bg+0x368), *(unsigned int*)($bg+0x370), *(void**)($bg+0x358), *(unsigned int*)($bg+0x360)
x/8gx *(void**)($bg+0x368)
detach
quit
