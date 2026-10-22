set pagination off
set confirm off
set $nh = 0
set $ns = 0
set $saddr = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d str=%p val=%p len=%lu\n", $nh, data, data->val, data->len
printf "  heap=%p free64=%p free80=%p\n", alloc_globals.mm_heap, alloc_globals.mm_heap->free_slot[7], alloc_globals.mm_heap->free_slot[8]
if $nh >= 2
  detach
  quit
end
continue
end
break php_set_session_var
commands
silent
set $ns = $ns + 1
set $slot = (zval*)state_val->value.ptr
printf "SETVAR#%d name=[%s] slot=%p type=0x%x heap=%p free64=%p\n", $ns, name->val, $slot, $slot->u1.type_info, alloc_globals.mm_heap, alloc_globals.mm_heap->free_slot[7]
if ($slot->u1.type_info & 0xff) == 6
  printf "  STR zend=%p len=%lu val=%p\n", $slot->value.str, $slot->value.str->len, $slot->value.str->val
  if $saddr == 0
    set $saddr = (unsigned long)$slot->value.str
  end
end
if ($slot->u1.type_info & 0xff) == 7
  printf "  ARR ht=%p\n", $slot->value.arr
end
continue
end
continue
