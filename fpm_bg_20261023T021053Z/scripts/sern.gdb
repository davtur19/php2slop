set pagination off
set confirm off
set $bg=(char*)&basic_globals
define showser
  set $d=*(void**)($bg+0x358)
  printf "sdata=%p slevel=%u", $d, *(unsigned int*)($bg+0x360)
  if $d != 0
    printf " n=%u flags=%u mask=%d arData=%p nNumUsed=%u nTableSize=%u\n", *(unsigned int*)($d+0x38), *(unsigned int*)($d+8), *(int*)($d+0xc), *(void**)($d+0x10), *(unsigned int*)($d+0x18), *(unsigned int*)($d+0x20)
  else
    printf "\n"
  end
end
break php_var_serialize_init
commands
silent
printf "SER_INIT "
showser
continue
end
break php_request_shutdown
commands
silent
printf "SHUTDOWN "
showser
continue
end
continue
