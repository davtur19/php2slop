set pagination off
set confirm off
printf "VERIFY_BEGIN\n"
p basic_globals.unserialize
p ps_serializers[1].decode
x/2gx 0x22c54c8
printf "VERIFY_END\n"
detach
quit
