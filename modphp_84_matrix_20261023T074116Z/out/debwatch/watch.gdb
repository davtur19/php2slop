set pagination off
set confirm off
set can-use-hw-watchpoints 1
watch *(unsigned long long*)0x7f236827d6e0
commands
silent
printf "WA0 val=0x%lx\n", *(unsigned long long*)0x7f236827d6e0
bt 7
continue
end
watch *(unsigned long long*)0x7f236827d6e8
commands
silent
printf "W8 val=0x%lx\n", *(unsigned long long*)0x7f236827d6e8
bt 7
continue
end
continue
detach
quit
