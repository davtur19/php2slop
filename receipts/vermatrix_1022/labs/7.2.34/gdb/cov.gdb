set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE n=%d data=%p val=%p len=%lu level=%ld bg=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data
set $p = basic_globals.unserialize.data
if $p
  printf "PFIELDS %p %p %p %p %p\n", $p, *(void**)$p, *(void**)($p+8), *(void**)($p+16), *(void**)($p+24)
end
if $nh >= 2
  detach
  quit
end
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt
detach
quit
