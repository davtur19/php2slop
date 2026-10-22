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
printf "SETVAR#%d name=[%s] slot=%p type=0x%x\n",$ns,name->val,$slot,$slot->u1.type_info
if $ns==6
 printf "FINAL S=%p\n",$saddr
 x/24gx $saddr
end
continue
end
continue
