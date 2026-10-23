#!/usr/bin/env python3
"""Raw HTTP sender: chunked or plain, no redirects, records response bytes."""
import argparse, socket, sys, time

def recv_all(s, limit=8<<20):
    out = bytearray()
    try:
        while len(out) < limit:
            b = s.recv(65536)
            if not b: break
            out += b
    except OSError:
        pass
    return bytes(out)

def send_chunked(host, port, path, body, timeout=120, chunk=65536, keep=False):
    boundary = b"C" * 10
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: %s\r\n\r\n" %
           (path, host, port, boundary.decode(), "keep-alive" if keep else "close")).encode()
    req = bytearray(hdr)
    for i in range(0, len(body), chunk):
        piece = body[i:i+chunk]
        req += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    req += b"0\r\n\r\n"
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendall(req)
        resp = recv_all(s)
    finally:
        s.close()
    return resp, time.time()-t0

def send_plain(host, port, path, body, timeout=120, ctype="multipart/form-data; boundary=CCCCCCCCCC", keep=False):
    req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: %s\r\n"
           "Content-Length: %d\r\nConnection: %s\r\n\r\n" %
           (path, host, port, ctype, len(body), "keep-alive" if keep else "close")).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    t0=time.time()
    try:
        s.sendall(req + body)
        resp = recv_all(s)
    finally:
        s.close()
    return resp, time.time()-t0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--file", default="")
    ap.add_argument("--data", default="")
    ap.add_argument("--chunked", action="store_true")
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--save", default="")
    a = ap.parse_args()
    body = open(a.file,"rb").read() if a.file else a.data.encode()
    if a.chunked:
        resp, dt = send_chunked(a.host, a.port, a.path, body, a.timeout)
    else:
        resp, dt = send_plain(a.host, a.port, a.path, body, a.timeout)
    if a.save: open(a.save,"wb").write(resp)
    print("status=", resp.split(b"\r\n",1)[0][:80], "bytes=", len(resp), "secs=%.2f"%dt)
