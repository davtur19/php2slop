set pagination off
set confirm off
printf "EXEC_SIZE=%ld\n", (long)sizeof(zend_execute_data)
printf "THIS_OFF=%ld\n", (long)((char*)&((zend_execute_data*)0)->This-(char*)0)
printf "PS_GLOBALS=%p\n", (void*)&ps_globals
printf "PS_SER_OFF=%ld\n", (long)((char*)&ps_globals.serializer-(char*)&ps_globals)
printf "BG_GLOBALS=%p\n", (void*)&basic_globals
printf "BG_UNSER_OFF=%ld\n", (long)((char*)&basic_globals.unserialize-(char*)&basic_globals)
printf "BG_UNSER_SIZE=%ld\n", (long)sizeof(basic_globals.unserialize)
printf "PS_SERIALIZERS=%p\n", (void*)&ps_serializers
printf "PSER_SIZE=%ld\n", (long)sizeof(ps_serializers[0])
printf "PSER0=%s|%p|%p\n", ps_serializers[0].name, (void*)ps_serializers[0].encode, (void*)ps_serializers[0].decode
printf "PSER1=%s|%p|%p\n", ps_serializers[1].name, (void*)ps_serializers[1].encode, (void*)ps_serializers[1].decode
printf "PSER2=%s|%p|%p\n", ps_serializers[2].name, (void*)ps_serializers[2].encode, (void*)ps_serializers[2].decode
printf "PSER3NAME=%p\n", (void*)ps_serializers[3].name
printf "PSER3ENC=%p\n", (void*)ps_serializers[3].encode
printf "UNSER_SIZE=%ld\n", (long)sizeof(struct php_unserialize_data)
printf "UNSER_LAST_OFF=%ld\n", (long)((char*)&((struct php_unserialize_data*)0)->last-(char*)0)
printf "UNSER_FIRST_DTOR_OFF=%ld\n", (long)((char*)&((struct php_unserialize_data*)0)->first_dtor-(char*)0)
printf "UNSER_LAST_DTOR_OFF=%ld\n", (long)((char*)&((struct php_unserialize_data*)0)->last_dtor-(char*)0)
printf "DTOR_SIZE=%ld\n", (long)sizeof(var_dtor_entries)
printf "DTOR_DATA_OFF=%ld\n", (long)((char*)&((var_dtor_entries*)0)->data-(char*)0)
printf "DTOR_USED_OFF=%ld\n", (long)((char*)&((var_dtor_entries*)0)->used_slots-(char*)0)
printf "DTOR_DATA_MAX=%ld\n", (long)(sizeof(((var_dtor_entries*)0)->data)/sizeof(zval))
quit
