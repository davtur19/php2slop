#!/usr/bin/env python3
import socket, sys, os, argparse

def build_body(sid, key, fname, fdata, pad, bnd, pads=1, padlen=None):
    parts = []
    def field(name, value):
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n" % (bnd, name)).encode())
        parts.append(value if isinstance(value, bytes) else value.encode())
        parts.append(b"\r\n")
    field("PHPSESSID", sid)
    if pad > 0:
        for _ in range(pads):
            field("pad", b"P" * pad)
    field("PHP_SESSION_UPLOAD_PROGRESS", key)
    parts.append(("--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"%s\"\r\nContent-Type: text/plain\r\n\r\n" % (bnd, fname)).encode())
    parts.append(fdata)
    parts.append(("\r\n--%s--\r\n" % bnd).encode())
    return b"".join(parts), bnd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29310)
    ap.add_argument("--path", default="/consumer.php")
    ap.add_argument("--sid", default="bgsid1")
    ap.add_argument("--key", default="bgupload")
    ap.add_argument("--pad", type=int, default=0)
    ap.add_argument("--pads", type=int, default=1)
    ap.add_argument("--bnd", default="----bgBoundary7MA4YWxkTrZu0gW")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--tag", default="req")
    args = ap.parse_args()
    body, bnd = build_body(args.sid, args.key, "a.txt", b"A", args.pad, args.bnd, args.pads)
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" % (args.path, args.host, args.port, bnd, len(body))).encode()
    raw = hdr + body
    os.makedirs(args.outdir, exist_ok=True)
    open(os.path.join(args.outdir, args.tag + ".raw"), "wb").write(raw)
    s = socket.create_connection((args.host, args.port), timeout=15)
    s.sendall(raw)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
    except socket.timeout:
        pass
    s.close()
    open(os.path.join(args.outdir, args.tag + ".resp"), "wb").write(data)
    sys.stdout.write(data.decode("latin1"))

if __name__ == "__main__":
    main()
