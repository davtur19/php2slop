set pagination off
set confirm off
set $nh=0
set $ns=0
set $saddr=0
break php_session_decode
commands
silent
set $nh=$nh+1
printf "DECODE hit=%d str=%p val=%p len=%lu\n",$nh,data,data->val,data->len
if $nh>=2
 detach
 quit
end
continue
end
break php_set_session_var
commands
silent
set $ns=$ns+1
set $slot=(zval*)state_val->value.ptr
printf "SETVAR#%d name=[%s] slot=%p type=0x%x free56=%p\n",$ns,name->val,$slot,$slot->u1.type_info,alloc_globals.mm_heap->free_slot[6]
if ($slot->u1.type_info & 0xff)==6
 printf "  STR zend=%p len=%lu val=%p al=%lu\n",$slot->value.str,$slot->value.str->len,$slot->value.str->val,((unsigned long)$slot->value.str)&0xf
 if $ns==2
  set $saddr=(unsigned long)$slot->value.str
 end
end
if ($slot->u1.type_info & 0xff)==7
 printf "  ARR ht=%p al=%lu\n",$slot->value.arr,((unsigned long)$slot->value.arr)&0xf
end
if $ns==6
 printf "FINAL S=%p\n",$saddr
 x/26gx $saddr
end
continue
end
continue
