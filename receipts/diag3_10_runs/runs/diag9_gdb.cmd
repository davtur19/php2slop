set pagination off
set confirm off
set auto-load safe-path /
break ext/standard/var.c:1352
commands
silent
printf "[FRESH] d=%p\n", d
continue
end
break ext/standard/var.c:1359
commands
silent
printf "[REUSE] d=%p\n", d
continue
end
break ext/standard/var.c:1367
commands
silent
printf "[DESTROY] d=%p\n", d
continue
end
run
