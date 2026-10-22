set pagination off
set confirm off
x/9gx &ps_serializers
p ps_serializers[0]
p ps_serializers[1]
p ps_serializers[2]
p ps_serializers[3]
p basic_globals.unserialize.level
p basic_globals.unserialize.data
detach
quit
