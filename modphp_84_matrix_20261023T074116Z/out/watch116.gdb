set pagination off
set confirm off
set can-use-hw-watchpoints 1
watch *(unsigned long long*)0x7f014fc7d720
commands
silent
printf "WA0 val=0x%lx\n", *(unsigned long long*)0x7f014fc7d720
bt 5
continue
end
watch *(unsigned long long*)0x7f014fc7d728
commands
silent
printf "W8 val=0x%lx\n", *(unsigned long long*)0x7f014fc7d728
bt 5
continue
end
continue
detach
quit
