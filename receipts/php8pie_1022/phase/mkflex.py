#!/usr/bin/env python3
"""Flexible php_binary session record builder for the PIE lab.

Usage: mkflex.py OUT TOTAL 'rec1name:STR:32:S' 'rec2name:LONG:4096' ...
The last record is a filler STR padded to reach TOTAL.
"""
import sys

def rec(name, val):
    nb = name.encode()
    assert 1 <= len(nb) <= 127
    return bytes([len(nb)]) + nb + val

def strval(s):
    return b's:%d:"' % len(s) + s + b'";'

def longval(n):
    return b'i:%d;' % n

def build(total, specs):
    prefix = b''
    for sp in specs:
        parts = sp.split(':')
        nm = parts[0]
        if parts[1] == 'STR':
            prefix += rec(nm, strval(bytes([int(parts[2])]) * int(parts[3])))
        elif parts[1] == 'LONG':
            prefix += rec(nm, longval(int(parts[2])))
        else:
            raise SystemExit('bad spec')
    # filler
    hdr_len = len(rec('K', b's:'))
    L = total - len(prefix) - hdr_len - 2 - 1
    for _ in range(8):
        h = rec('K', b's:%d:"' % L)
        nl = total - len(prefix) - len(h) - 2
        if nl == L:
            break
        L = nl
    h = rec('K', b's:%d:"' % L)
    data = prefix + h + b'A' * L + b'";'
    assert len(data) == total, (len(data), total)
    return data

if __name__ == '__main__':
    out = sys.argv[1]; total = int(sys.argv[2], 0)
    data = build(total, sys.argv[3:])
    open(out, 'wb').write(data)
    print('wrote', out, len(data))
