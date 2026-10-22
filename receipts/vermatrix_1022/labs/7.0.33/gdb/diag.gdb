set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
set $nu = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2=%p\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode
set $p = basic_globals.unserialize.data
if $p
  printf "  P first=%p last=%p first_dtor=%p last_dtor=%p\n", *(void**)$p, *(void**)($p+8), *(void**)($p+16), *(void**)($p+24)
  set $b = *(void**)($p+24)
  if $b
    printf "  B0=%p used_slots=%ld next=%p\n", $b, *(long*)($b+0x4000), *(void**)($b+0x4008)
  end
end
continue
end
break php_var_unserialize
commands
silent
set $nu = $nu + 1
if $nu < 12
  printf "UNSER#%d rval=%p pre=(%p,%d) p=%p ser2=%p\n", $nu, $rdi, *(void**)$rdi, *(int*)($rdi+8), **(void***)$rsi, ps_serializers[2].decode
end
continue
end
break php_session_normalize_vars
commands
silent
printf "NORMALIZE enter ser2=%p A=(%p,%d) A16=(%p,%d) A32=(%p,%d)\n", ps_serializers[2].decode, *(void**)0x804e20, *(int*)0x804e28, *(void**)0x804e30, *(int*)0x804e38, *(void**)0x804e40, *(int*)0x804e48
continue
end
break php_session_encode
commands
silent
printf "ENCODE enter ser2=%p A=(%p,%d)\n", ps_serializers[2].decode, *(void**)0x804e20, *(int*)0x804e28
bt 6
continue
end
break php_session_save_current_state
commands
silent
printf "SAVE state ser2=%p A=(%p,%d)\n", ps_serializers[2].decode, *(void**)0x804e20, *(int*)0x804e28
continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt 10
detach
quit
