set pagination off
attach 1675577
p basic_globals.unserialize
p/x *(void**)(basic_globals.unserialize.data+0x10)
p/x *(void**)(basic_globals.unserialize.data+0x08)
p/x *(void**)(basic_globals.unserialize.data+0x00)
p/x *(long*)(basic_globals.unserialize.data+0x38)
p/x *(long*)(basic_globals.unserialize.data+0x40)
detach
quit
