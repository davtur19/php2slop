set pagination off
set confirm off
break php_var_serialize_init
commands
silent
printf "[INIT] lock=%u level=%u data=%p\n", BG(serialize_lock), BG(serialize).level, BG(serialize).data
continue
end
break php_var_serialize_destroy
commands
silent
printf "[DEST] level=%u data=%p\n", BG(serialize).level, BG(serialize).data
continue
end
run
