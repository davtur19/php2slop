set pagination off
set confirm off
p/x &ps_globals
p/x &ps_globals.serializer
p/x ps_globals.serializer
p/x *(void**)((char*)&ps_globals + 0x160)
detach
quit
