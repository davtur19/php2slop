set pagination off
set confirm off
printf "PSER0=%s|%p|%p\n", ps_serializers[0].name, (void*)ps_serializers[0].encode, (void*)ps_serializers[0].decode
printf "PSER1=%s|%p|%p\n", ps_serializers[1].name, (void*)ps_serializers[1].encode, (void*)ps_serializers[1].decode
printf "PSER2=%s|%p|%p\n", ps_serializers[2].name, (void*)ps_serializers[2].encode, (void*)ps_serializers[2].decode
printf "PSER3NAME=%p\n", (void*)ps_serializers[3].name
printf "PSER3ENC=%p\n", (void*)ps_serializers[3].encode
printf "BG_LEVEL=%ld\n", basic_globals.unserialize.level
printf "BG_DATA=%p\n", basic_globals.unserialize.data
detach
quit
