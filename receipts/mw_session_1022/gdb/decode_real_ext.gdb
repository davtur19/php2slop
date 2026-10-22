set pagination off
set confirm off
echo \n=== ATTACHED ===\n
break ps_srlzr_decode_php
commands
  silent
  echo \n=== PS_SRLZR_DECODE_PHP HIT ===\n
  bt 4
  printf "rdi(data)=%p\n", $rdi
  x/4gx $rdi
  x/8bx $rdi
  continue
end
break php_session_decode
commands
  silent
  echo \n=== PHP_SESSION_DECODE ===\n
  printf "data=%p\n", $rdi
  x/2gx $rdi
  printf "ps_globals.serializer=%p\n", ps_globals.serializer
  x/6gx 0x22c54b8
  continue
end
watch *(unsigned long*)0x22c54c8
commands
  silent
  echo \n=== WATCHPOINT ps_serializers.decode CHANGED ===\n
  bt 6
  continue
end
continue
