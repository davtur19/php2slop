#!/usr/bin/env python3
"""shim.py - REFERENCE body-inspection edge rule (NOT nginx).

Why this exists: the nginx build in this environment (1.30.1, only
--with-http_ssl_module) has no modsecurity, no njs and no lua, so core nginx
cannot inspect multipart field names.  This shim reproduces *exactly* the rule
an njs/modsecurity deployment would install -- "reject any request whose body
contains the literal PHP_SESSION_UPLOAD_PROGRESS" -- so that the rule's blocking
power and its bypass conditions can be MEASURED instead of guessed.

It is a transparent forwarder: matched requests get 403 and never reach nginx/
PHP; unmatched requests are forwarded byte-identically to the upstream nginx
lane (127.0.0.1:29006 -> fpm_n3, memory_limit 8M, no size cap).

--max-inspect N emulates a WAF body-prefix inspection window (e.g. 8192 bytes).
"""
import argparse
import json
import re
import socket
import threading
import time

TOKEN = re.compile(rb"PHP_SESSION_UPLOAD_PROGRESS")


def read_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        b = sock.recv(4096)
        if not b:
            return None, None
        buf += b
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def read_body(sock, head, rest):
    lines = head.split(b"\r\n")
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs[k.strip().lower()] = v.strip()
    if b"transfer-encoding" in hdrs and b"chunked" in hdrs[b"transfer-encoding"].lower():
        buf = rest
        out = b""
        while True:
            while b"\r\n" not in buf:
                d = sock.recv(65536)
                if not d:
                    return out
                buf += d
            line, _, buf = buf.partition(b"\r\n")
            size = int(line.split(b";")[0], 16)
            if size == 0:
                return out
            while len(buf) < size + 2:
                d = sock.recv(65536)
                if not d:
                    return out
                buf += d
            out += buf[:size]
            buf = buf[size + 2:]
    else:
        n = int(hdrs.get(b"content-length", b"0"))
        buf = rest
        while len(buf) < n:
            d = sock.recv(65536)
            if not d:
                break
            buf += d
        return buf[:n]


def forward(up_port, head, body):
    up = socket.create_connection(("127.0.0.1", up_port), timeout=120)
    up.settimeout(120)
    lines = head.split(b"\r\n")
    keep = [lines[0]]
    for ln in lines[1:]:
        k = ln.split(b":")[0].strip().lower()
        if k in (b"connection", b"transfer-encoding", b"content-length", b"keep-alive"):
            continue
        keep.append(ln)
    keep.append(b"Content-Length: %d" % len(body))
    keep.append(b"Connection: close")
    up.sendall(b"\r\n".join(keep) + b"\r\n\r\n" + body)
    out = []
    while True:
        d = up.recv(65536)
        if not d:
            break
        out.append(d)
    up.close()
    return b"".join(out)


def handle(conn, args, lock):
    try:
        conn.settimeout(120)
        head, rest = read_headers(conn)
        if head is None:
            return
        body = read_body(conn, head, rest)
        window = body[:args.max_inspect] if args.max_inspect else body
        m = TOKEN.search(window)
        reqline = head.split(b"\r\n")[0].decode("latin1", "replace")
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "req": reqline,
               "body_len": len(body), "max_inspect": args.max_inspect,
               "match": bool(m), "match_offset": m.start() if m else None,
               "decision": 403 if m else "forward"}
        with lock:
            with open(args.log, "a") as f:
                f.write(json.dumps(rec) + "\n")
        if m:
            msg = (b"403 blocked by reference token rule\n")
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(msg) + msg)
            return
        resp = forward(args.upstream_port, head, body)
        conn.sendall(resp)
    except Exception as e:  # keep the shim alive; record the failure
        with lock:
            with open(args.log, "a") as f:
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "error": f"{type(e).__name__}: {e}"}) + "\n")
        try:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--upstream-port", type=int, default=29006)
    ap.add_argument("--max-inspect", type=int, default=0)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.listen))
    srv.listen(128)
    lock = threading.Lock()
    with open(a.log, "a") as f:
        f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "event": "start", "listen": a.listen,
                            "upstream": a.upstream_port,
                            "max_inspect": a.max_inspect}) + "\n")
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, a, lock), daemon=True).start()


if __name__ == "__main__":
    main()
