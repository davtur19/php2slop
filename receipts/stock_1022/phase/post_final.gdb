set pagination off
set confirm off
printf "WORKER pid=%d\n", 1682840
printf "ser1_decode=%p\n", *(unsigned long long *)0x22c54c8
printf "ser2_decode=%p\n", *(unsigned long long *)0x22c54e0
printf "BG level=%ld data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
detach
quit
