set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
printf "ps_serializers:\n"
x/8gx 0x22c54a0
printf "entry1 decode=%p encode=%p name=%p\n", *(void**)0x22c54c8, *(void**)0x22c54c0, *(void**)0x22c54b8
detach
quit
