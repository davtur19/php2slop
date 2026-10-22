set pagination off
set confirm off
set auto-load safe-path /
set $cur = *(void**)0x22c54c8
printf "before ser1decode=%p\n", $cur
set *(void**)0x22c54c8 = (void*)0x9e6fae
printf "after ser1decode=%p encode=%p table=%p\n", *(void**)0x22c54c8, *(void**)0x22c54c0, *(void**)0x22d0f20
detach
quit
