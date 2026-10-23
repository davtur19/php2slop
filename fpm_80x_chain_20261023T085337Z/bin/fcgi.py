#!/usr/bin/env python3
"""Minimal FastCGI (responder) client for direct FPM diagnostics.

Modes:
  default            : CONTENT_LENGTH = len(body)   (what nginx sends when buffering)
  --no-content-length: no CONTENT_LENGTH, TE=chunked (what Apache mod_php chunked sees)
"""
import argparse, socket, struct, sys, os

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7

def rec(t, rid, content):
    return struct.pack("!BBHHBx", 1, t, rid, len(content), 0) + content

def kv(k, v):
    kb, vb = k.encode(), v.encode() if isinstance(v, str) else v
    def ln(n):
        return struct.pack("!B", n) if n < 128 else struct.pack("!I", n | 0x80000000)
    return ln(len(kb)) + ln(len(vb)) + kb + vb

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--body-file", default="")
    ap.add_argument("--query", default="")
    ap.add_argument("--content-type", default="")
    ap.add_argument("--no-content-length", action="store_true")
    ap.add_argument("--script", default="")
    ap.add_argument("--docroot", default="/var/www/html")
    ap.add_argument("--save", default="")
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    body = open(args.body_file, "rb").read() if args.body_file else b""
    script = args.script or args.path.split("?")[0]
    params = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REQUEST_METHOD": args.method,
        "SCRIPT_FILENAME": args.docroot + script,
        "SCRIPT_NAME": script,
        "REQUEST_URI": args.path,
        "DOCUMENT_ROOT": args.docroot,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "lab-fcgi",
        "REMOTE_ADDR": "127.0.0.1",
        "SERVER_ADDR": "127.0.0.1",
        "SERVER_PORT": str(args.port),
        "SERVER_NAME": "lab",
        "REDIRECT_STATUS": "200",
        "QUERY_STRING": args.query,
    }
    if args.content_type:
        params["CONTENT_TYPE"] = args.content_type
    if body:
        if args.no_content_length:
            params["HTTP_TRANSFER_ENCODING"] = "chunked"
        else:
            params["CONTENT_LENGTH"] = str(len(body))

    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    s.settimeout(args.timeout)
    out = bytearray()
    err = bytearray()
    reqid = 1
    p = b"".join(kv(k, v) for k, v in params.items())
    pkt = rec(FCGI_BEGIN_REQUEST, reqid, struct.pack("!HB5x", 1, 0))
    pkt += rec(FCGI_PARAMS, reqid, p)
    pkt += rec(FCGI_PARAMS, reqid, b"")
    if body:
        for i in range(0, len(body), 65535):
            pkt += rec(FCGI_STDIN, reqid, body[i:i+65535])
    pkt += rec(FCGI_STDIN, reqid, b"")
    try:
        s.sendall(pkt)
        buf = b""
        while True:
            while len(buf) < 8:
                c = s.recv(65536)
                if not c:
                    raise EOFError
                buf += c
            ver, t, rid, clen, pad = struct.unpack("!BBHHB", buf[:7])
            payload = buf[8:8+clen] if False else buf[8:]
            need = 8 + clen + pad
            while len(buf) < need:
                c = s.recv(65536)
                if not c:
                    break
                buf += c
            payload = buf[8:8+clen]
            buf = buf[need:]
            if t == FCGI_STDOUT:
                out += payload
            elif t == FCGI_STDERR:
                err += payload
            elif t == FCGI_END_REQUEST:
                break
    except (EOFError, socket.timeout, ConnectionResetError, OSError):
        pass
    s.close()
    if args.save:
        open(args.save, "wb").write(bytes(out))
    sys.stdout.buffer.write(bytes(out))
    if err:
        sys.stderr.write("[stderr] " + err.decode("latin1", "replace") + "\n")

if __name__ == "__main__":
    main()
