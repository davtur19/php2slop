set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
set $nf = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode
if $nh == 2
  return
end
continue
end
break php_session_flush
commands
silent
set $nf = $nf + 1
printf "FLUSH n=%d ser2=%p\n", $nf, ps_serializers[2].decode
if $nf >= 2
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
