#!/usr/bin/env python3
"""Minimal but controllable FastCGI client for the FPM lab.

Sends one request to php-fpm and saves the raw FCGI_STDOUT (CGI response)
to --out. Supports query strings, cookies, arbitrary headers, chunked/slow
request bodies and an abort-after-bytes mode.
"""
import argparse
import os
import socket
import struct
import sys
import time

HOST = os.environ.get("FPM_HOST", "127.0.0.1")
PORT = int(os.environ.get("FPM_PORT", "18750"))
DOCROOT = os.environ.get("DOCROOT", "/tmp/opencode/research/mw_109619_20261023T010708Z/fpm8511/html")
DEFAULT_INI = os.environ.get("FPM_INI", "")


def rec(t, rid, content=b""):
    return struct.pack("!BBHHBB", 1, t, rid, len(content), 0, 0) + content


def nv(name, val):
    nb, vb = name.encode(), str(val).encode()

    def l(n):
        return bytes([n]) if n < 128 else struct.pack("!I", n | 0x80000000)

    return l(len(nb)) + l(len(vb)) + nb + vb


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--method", default="GET")
    ap.add_argument("--uri", default="/index.php")
    ap.add_argument("--body", default=None)
    ap.add_argument("--content-type", default="application/x-www-form-urlencoded")
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--out", default=None)
    ap.add_argument("--chunk-size", type=int, default=0)
    ap.add_argument("--chunk-delay", type=float, default=0.0)
    ap.add_argument("--abort-after", type=int, default=0)
    ap.add_argument("--truncate-after", type=int, default=0)
    ap.add_argument("--hold-seconds", type=float, default=0.0)
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    body = b""
    if args.body:
        if args.body == "-":
            body = sys.stdin.buffer.read()
        elif os.path.exists(args.body):
            body = open(args.body, "rb").read()
        else:
            body = args.body.encode("latin1")

    uri = args.uri
    if "?" in uri:
        script, query = uri.split("?", 1)
    else:
        script, query = uri, ""

    params = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REQUEST_METHOD": args.method,
        "SCRIPT_FILENAME": DOCROOT + script,
        "SCRIPT_NAME": script,
        "REQUEST_URI": uri,
        "QUERY_STRING": query,
        "DOCUMENT_ROOT": DOCROOT,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "mw109619-fcgi-client",
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": str(PORT),
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_HOST": os.environ.get("FPM_HOSTHEADER", "127.0.0.1:%d" % PORT),
        "HTTP_USER_AGENT": "mw109619-fcgi-client/1.0",
    }
    if body or args.method in ("POST", "PUT"):
        params["CONTENT_TYPE"] = args.content_type
        params["CONTENT_LENGTH"] = str(len(body))
    if args.cookie:
        params["HTTP_COOKIE"] = args.cookie
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            key = "HTTP_" + k.strip().upper().replace("-", "_")
            if key == "HTTP_CONTENT_TYPE":
                params["CONTENT_TYPE"] = v.strip()
            elif key == "HTTP_CONTENT_LENGTH":
                params["CONTENT_LENGTH"] = v.strip()
            else:
                params[key] = v.strip()

    req = rec(1, 1, struct.pack("!HB5x", 1, 0))
    req += rec(4, 1, b"".join(nv(k, v) for k, v in params.items()))
    req += rec(4, 1, b"")
    # We stream the body separately below so slow uploads work.
    s = socket.create_connection((HOST, PORT), timeout=args.timeout)
    s.settimeout(args.timeout)
    s.sendall(req)

    sent = 0
    aborted = False
    truncated = False
    try:
        while sent < len(body):
            n = args.chunk_size if args.chunk_size > 0 else len(body)
            if args.truncate_after and sent >= args.truncate_after:
                truncated = True
                break
            chunk = body[sent:sent + n]
            if args.truncate_after and sent + len(chunk) >= args.truncate_after:
                chunk = chunk[:args.truncate_after - sent]
                truncated = True
            if args.abort_after and sent + len(chunk) >= args.abort_after:
                cut = max(0, args.abort_after - sent)
                chunk = chunk[:cut]
                if chunk:
                    s.sendall(rec(5, 1, chunk))
                aborted = True
                break
            s.sendall(rec(5, 1, chunk))
            sent += len(chunk)
            if args.chunk_delay:
                time.sleep(args.chunk_delay)
        if not aborted and not truncated:
            s.sendall(rec(5, 1, b""))
        if truncated:
            sys.stderr.write("client: truncated body at %d bytes, holding %.1fs\n" %
                             (sent, args.hold_seconds))
            time.sleep(args.hold_seconds)
            aborted = True
    except (BrokenPipeError, ConnectionResetError) as e:
        sys.stderr.write("client: body send failed: %s\n" % e)
        aborted = True

    if aborted:
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass
        sys.stderr.write("client: aborted after approximately %d body bytes\n" % sent)
        return 2

    out = bytearray()
    buf = b""
    app_status = None
    proto_status = None
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            sys.stderr.write("client: timeout reading response\n")
            break
        if not d:
            break
        buf += d
        while len(buf) >= 8:
            ver, typ, rid, clen, plen, _ = struct.unpack("!BBHHBB", buf[:8])
            if len(buf) < 8 + clen + plen:
                break
            content = buf[8:8 + clen]
            buf = buf[8 + clen + plen:]
            if typ == 6:
                out += content
            elif typ == 7:
                sys.stderr.write("client stderr: %s\n" % content.decode("latin1", "replace"))
            elif typ == 3:
                if len(content) >= 8:
                    app_status, proto_status = struct.unpack("!IB3x", content[:8])
                buf = b""
                break
        if proto_status is not None or app_status is not None:
            break
    s.close()

    raw = bytes(out)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(raw)
    if not args.quiet:
        # Print status line + selected headers.
        head, sep, rest = raw.partition(b"\r\n\r\n")
        if not sep:
            head, sep, rest = raw.partition(b"\n\n")
        lines = head.decode("latin1", "replace").splitlines()
        sys.stderr.write("client: app_status=%r proto_status=%r body_bytes=%d\n" %
                         (app_status, proto_status, len(rest)))
        for line in lines[:40]:
            sys.stderr.write("  " + line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
