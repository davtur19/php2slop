#!/usr/bin/env python3
import socket, sys, argparse, re

def read_response(s):
    data = b""
    while b"\r\n\r\n" not in data:
        b = s.recv(4096)
        if not b: return data, True
        data += b
    head, rest = data.split(b"\r\n\r\n", 1)
    m = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
    if m:
        n = int(m.group(1))
        while len(rest) < n:
            b = s.recv(4096)
            if not b: break
            rest += b
        return head + b"\r\n\r\n" + rest[:n], False
    # chunked
    while b"\r\n0\r\n\r\n" not in rest and not rest.endswith(b"0\r\n\r\n"):
        b = s.recv(4096)
        if not b: break
        rest += b
    return head + b"\r\n\r\n" + rest, False

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--n", type=int, default=6)
ap.add_argument("--path", default="/pid.php")
ap.add_argument("--host", default="127.0.0.1")
a = ap.parse_args()
s = socket.create_connection((a.host, a.port), timeout=10)
s.settimeout(10)
req = ("GET %s HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n" % a.path).encode()
for i in range(a.n):
    s.sendall(req)
    resp, closed = read_response(s)
    body = resp.split(b"\r\n\r\n",1)[-1]
    # dechunk crudely: take last numeric-looking line
    txt = re.sub(rb"[^0-9\n]", b"", body).strip()
    print(i, "closed" if closed else "ok", txt.decode()[:40])
    if closed: break
s.close()
