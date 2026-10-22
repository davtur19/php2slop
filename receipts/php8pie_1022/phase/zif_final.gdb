set pagination off
set confirm off
set $nh=0
break php_session_decode
commands
silent
set $nh=$nh+1
printf "DECODE hit=%d str=%p val=%p len=%lu\n",$nh,data,data->val,data->len
printf "  num_args=%u arg1=%p type=%u\n", *(unsigned int*)(data->val+0x2c), *(void**)(data->val+0x50), *(unsigned char*)(data->val+0x58)
if $nh>=2
  set $F=*(unsigned long*)(data->val+0x50)
  printf "  F=%p F+0x10(len)=%lu F+0x18=%p\n", $F, *(unsigned long*)($F+0x10), *(void**)($F+0x18)
  x/12cb $F+0x18
  printf "  serializer decode slot=%p\n", *(void**)(0x556e4b8c1980)
  detach
  quit
end
continue
end
continue
