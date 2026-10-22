set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2name=%s\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].name
if $nh == 1
  x/8gx ((zend_string*)$rdi)->val
end
continue
end
break zif_passthru
commands
silent
printf "ZIF_PASSTHRU hit rdi=%p rsi=%p rdx=%p\n", $rdi, $rsi, $rdx
x/12gx $rdi
continue
end
break php_exec_ex
commands
silent
printf "PHP_EXEC_EX rdi=%p rsi=%p rdx=%p numargs=%u arg1val=%p arg1type=%u\n", $rdi, $rsi, $rdx, *(unsigned int*)($rdi+0x2c), *(void**)($rdi+0x50), *(unsigned char*)($rdi+0x58)
set $f = *(void**)($rdi+0x50)
if $f
  printf "F=%p F_PLUS_10_LEN=%lu\n", $f, *(unsigned long*)($f+0x10)
  x/s $f+0x18
end
continue
end
break php_exec
commands
silent
printf "PHP_EXEC type=%d cmd=%p array=%p retval=%p\n", (int)$rdi, $rsi, $rdx, $rcx
x/s $rsi
continue
end
break *0x513824
commands
silent
printf "AFTER_PHP_EXEC eax=%d\n", $eax
detach
quit
end
continue
printf "STOPPED rip=%p\n", $rip
bt
info registers rip rdi rsi rdx rcx rax rsp rbp
x/4i $rip
detach
quit
