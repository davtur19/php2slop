#!/usr/bin/env python3
"""Raw HTTP client for stage tests: send a body file, dump response, print status.

Usage:
  stage.py post <url> <bodyfile> <ctype> [--out out.resp] [--timeout 120]
  stage.py get <url> [--out out.resp]
Prints: STATUS=<code> TIME=<s> LEN=<bytes> and the body prefix (500 B).
"""
import argparse, socket, sys, time, urllib.parse


def send(url, method="GET", body=b"", ctype="", timeout=120, chunked=False, extra=""):
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path + ("?" + u.query if u.query else "") or "/"
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(timeout)
    hdr = "%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n" % (method, path, host, port)
    if ctype:
        hdr += "Content-Type: %s\r\n" % ctype
    if chunked:
        hdr += "Transfer-Encoding: chunked\r\n"
    elif body:
        hdr += "Content-Length: %d\r\n" % len(body)
    hdr += extra + "\r\n"
    out = bytearray()
    t0 = time.time()
    try:
        s.sendall(hdr.encode() + body)
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except (socket.timeout, OSError) as e:
        sys.stderr.write("io: %r\n" % (e,))
    dt = time.time() - t0
    s.close()
    return bytes(out), dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["get", "post"])
    ap.add_argument("url")
    ap.add_argument("bodyfile", nargs="?")
    ap.add_argument("ctype", nargs="?")
    ap.add_argument("--out", default="")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--chunked", action="store_true")
    ap.add_argument("--cookie", default="")
    a = ap.parse_args()
    body = open(a.bodyfile, "rb").read() if a.bodyfile else b""
    xh = ("Cookie: %s\r\n" % a.cookie) if a.cookie else ""
    if a.chunked and body:
        enc = bytearray()
        for i in range(0, len(body), 65536):
            c = body[i:i + 65536]
            enc += ("%x\r\n" % len(c)).encode() + c + b"\r\n"
        enc += b"0\r\n\r\n"
        resp, dt = send(a.url, "POST", bytes(enc), a.ctype or "", a.timeout, chunked=True, extra=xh)
    else:
        resp, dt = send(a.url, "POST" if a.cmd == "post" else "GET", body,
                        a.ctype or "", a.timeout, extra=xh)
    if a.out:
        open(a.out, "wb").write(resp)
    try:
        code = int(resp.split(b" ")[1])
    except Exception:
        code = 0
    hdr_end = resp.find(b"\r\n\r\n")
    print("STATUS=%d TIME=%.3f LEN=%d" % (code, dt, len(resp)))
    print("---RESP---")
    sys.stdout.write(resp[:500].decode("latin1", "replace"))
    print()
    if hdr_end >= 0:
        print("---BODY---")
        sys.stdout.write(resp[hdr_end + 4:hdr_end + 4 + 300].decode("latin1", "replace"))
        print()


if __name__ == "__main__":
    main()
