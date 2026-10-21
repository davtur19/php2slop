#!/usr/bin/env python3
"""narm.py - arm / shape driver for the nginx-edge mitigation lanes.

Byte-shape source (stock parity, read-only reference):
  /tmp/opencode/mitigation_1021/scripts/http_arm.py (field/file_part/arm_body)
  /home/davide/ailocal/php2slop/tool/modules/arm.py

Stock arm: field PHPSESSID, field PHP_SESSION_UPLOAD_PROGRESS=MMM,
20 file parts (filename F*9 then F*262144), terminator; body 4,983,500 B.

This driver never executes PHP code: it only sends benign multipart bodies whose
filenames are 'F' repetitions. Loopback only.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import sys
import time

BOUNDARY = b"NATIVEOUTPUTEXACT"
OOM_RE = re.compile(r"Allowed memory size of (\d+) bytes exhausted"
                    r"(?: \(tried to allocate (\d+) bytes\))?")
FATAL_RE = re.compile(r"Fatal error[^\r\n<]*")
ARM_SID = b"armsess1021"


def field(name: bytes, value: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + value + b"\r\n")


def file_part(index: int, filename: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="upload'
            + str(index).encode() + b'"; filename="' + filename + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\nX\r\n")


def arm_body(sid: bytes, length: int = 262144, parts: int = 20,
             token_field: bytes = b"PHP_SESSION_UPLOAD_PROGRESS",
             token_value: bytes = b"MMM") -> bytes:
    body = field(b"PHPSESSID", sid)
    if token_field:
        body += field(token_field, token_value)
    for i in range(parts):
        n = 9 if i == 0 else length
        body += file_part(i, b"F" * n)
    return body + b"--" + BOUNDARY + b"--\r\n"


def shape_body(sid: bytes, token_field: bytes | None,
               quote: bool = True, case: str = "as-is",
               encoded: bool = False) -> bytes:
    """Tiny multipart with a small file part, for grammar/recognition tests."""
    if token_field is not None:
        name = token_field
        if case == "lower":
            name = name.lower()
        elif case == "upper":
            name = name.upper()
        if encoded:
            name = b"".join(b"%%%02X" % c for c in name)
        disp = (b'Content-Disposition: form-data; name="' + name + b'"'
                if quote else b"Content-Disposition: form-data; name=" + name)
        head = b"--" + BOUNDARY + b"\r\n" + disp + b"\r\n\r\nMMM\r\n"
    else:
        head = b""
    body = field(b"PHPSESSID", sid)
    body += head
    body += (b"--" + BOUNDARY + b"\r\n"
             + b'Content-Disposition: form-data; name="f"; filename="x.bin"\r\n'
             b"Content-Type: application/octet-stream\r\n\r\nY\r\n")
    return body + b"--" + BOUNDARY + b"--\r\n"


def legit_body(filename: bytes = b"legit.bin") -> bytes:
    payload = b"LEGIT" * 256   # 1280 B
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="file"; filename="' + filename + b'"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + payload + b"\r\n--" + BOUNDARY + b"--\r\n")


def parse_response(raw: bytes):
    if not raw:
        return {"status": None, "headers": {}, "body": ""}
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    m = re.match(rb"HTTP/\d\.\d (\d{3})", lines[0]) if lines else None
    if m:
        status = int(m.group(1))
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs.setdefault(k.strip().lower().decode("latin1"), v.strip().decode("latin1"))
    try:
        body = rest.decode("utf-8", "replace")
    except Exception:
        body = ""
    return {"status": status, "headers": hdrs, "body": body}


def raw_post(port: int, path: str, body: bytes, timeout: float = 120.0,
             chunked: bool = False, cookie: str | None = None,
             extra_headers: dict | None = None) -> dict:
    t0 = time.time()
    hdrs = [f"POST {path} HTTP/1.1", f"Host: 127.0.0.1:{port}",
            "Content-Type: multipart/form-data; boundary=" + BOUNDARY.decode(),
            "Connection: close", "User-Agent: narm/1"]
    if cookie:
        hdrs.append("Cookie: " + cookie)
    if extra_headers:
        for k, v in extra_headers.items():
            hdrs.append(f"{k}: {v}")
    if chunked:
        hdrs.append("Transfer-Encoding: chunked")
    else:
        hdrs.append("Content-Length: %d" % len(body))
    req = ("\r\n".join(hdrs) + "\r\n\r\n").encode()

    sent = 0
    send_error = None
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req)
        try:
            if chunked:
                step = 64 * 1024
                for i in range(0, len(body), step):
                    part = body[i:i + step]
                    s.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
                    sent += len(part)
                s.sendall(b"0\r\n\r\n")
            else:
                step = 64 * 1024
                for i in range(0, len(body), step):
                    part = body[i:i + step]
                    s.sendall(part)
                    sent += len(part)
        except (BrokenPipeError, ConnectionResetError) as e:
            send_error = type(e).__name__
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except (ConnectionResetError, socket.timeout) as e:
                send_error = send_error or type(e).__name__
                break
            if not b:
                break
            chunks.append(b)
    finally:
        s.close()
    raw = b"".join(chunks)
    r = parse_response(raw)
    body_text = r["body"]
    oom = OOM_RE.search(body_text)
    fatal = FATAL_RE.search(body_text)
    out = {
        "port": port, "path": path, "body_len": len(body),
        "chunked": chunked, "bytes_sent": sent, "send_error": send_error,
        "http_status": r["status"], "resp_headers": r["headers"],
        "resp_len": len(raw), "resp_body_head": body_text[:600],
        "resp_body_sha256": hashlib.sha256(raw).hexdigest(),
        "duration_s": round(time.time() - t0, 3),
        "resp_oom": oom.group(0) if oom else None,
        "resp_oom_limit": int(oom.group(1)) if oom else None,
        "resp_oom_tried": (int(oom.group(2)) if (oom and oom.group(2)) else None),
        "resp_fatal": fatal.group(0) if fatal else None,
    }
    return out


def http_get(port: int, path: str, cookies: str | None = None,
             timeout: float = 30.0, extra_headers: dict | None = None) -> dict:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    req = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
           + (f"Cookie: {cookies}\r\n" if cookies else "")
           + "".join(f"{k}: {v}\r\n" for k, v in (extra_headers or {}).items())
           + "Connection: close\r\n\r\n").encode()
    s.sendall(req)
    chunks = []
    while True:
        b = s.recv(65536)
        if not b:
            break
        chunks.append(b)
    s.close()
    r = parse_response(b"".join(chunks))
    return {"port": port, "path": path, "http_status": r["status"],
            "resp_body_head": r["body"][:600]}


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    a = sub.add_parser("arm")
    for p in (a,):
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--path", default="/index.php")
        p.add_argument("--sid", default=ARM_SID.decode())
        p.add_argument("--tag", default="arm")
        p.add_argument("--outdir", default=None)
        p.add_argument("--chunked", action="store_true")
        p.add_argument("--timeout", type=float, default=180.0)
        p.add_argument("--header", action="append", default=[])

    b = sub.add_parser("big")
    b.add_argument("--port", type=int, required=True)
    b.add_argument("--path", default="/index.php")
    b.add_argument("--sid", default=ARM_SID.decode())
    b.add_argument("--parts", type=int, default=7)
    b.add_argument("--length", type=int, default=262144)
    b.add_argument("--token", choices=["on", "off"], default="on")
    b.add_argument("--nodelim", action="store_true",
                   help="omit the UPG field entirely (same as --token off)")

    g = sub.add_parser("shape")
    g.add_argument("--port", type=int, required=True)
    g.add_argument("--path", default="/index.php")
    g.add_argument("--sid", default=ARM_SID.decode())
    g.add_argument("--field-name", default="PHP_SESSION_UPLOAD_PROGRESS")
    g.add_argument("--no-token", action="store_true")
    g.add_argument("--unquoted", action="store_true")
    g.add_argument("--case", choices=["as-is", "lower", "upper"], default="as-is")
    g.add_argument("--percent-encode", action="store_true")

    l = sub.add_parser("legit")
    l.add_argument("--port", type=int, required=True)
    l.add_argument("--path", default="/upload.php")

    h = sub.add_parser("get")
    h.add_argument("--port", type=int, required=True)
    h.add_argument("--path", default="/probe.php")
    h.add_argument("--sid", default=None)

    args = ap.parse_args()
    extra = {}
    rec = {"mode": args.mode, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}

    if args.mode == "arm":
        body = arm_body(args.sid.encode())
        rec["expected_len"] = 4983500
        rec.update(raw_post(args.port, args.path, body, args.timeout,
                            chunked=args.chunked,
                            cookie="PHPSESSID=" + args.sid,
                            extra_headers={"X-Test": "arm"}))
        rec["exact_len_ok"] = (len(body) == 4983500)
    elif args.mode == "big":
        tf = b"" if (args.token == "off" or args.nodelim) else b"PHP_SESSION_UPLOAD_PROGRESS"
        body = arm_body(args.sid.encode(), args.length, args.parts, token_field=tf)
        rec.update(raw_post(args.port, args.path, body, 180.0,
                            cookie="PHPSESSID=" + args.sid))
        rec["token"] = bool(tf)
    elif args.mode == "shape":
        body = shape_body(args.sid.encode(),
                          None if args.no_token else args.field_name.encode("latin1"),
                          quote=not args.unquoted, case=args.case,
                          encoded=args.percent_encode)
        rec.update(raw_post(args.port, args.path, body, 60.0,
                            cookie="PHPSESSID=" + args.sid))
        rec["shape"] = {"field": None if args.no_token else args.field_name,
                        "quoted": not args.unquoted, "case": args.case,
                        "percent_encoded": args.percent_encode}
    elif args.mode == "legit":
        body = legit_body()
        rec.update(raw_post(args.port, args.path, body, 60.0))
        rec["legit_len"] = len(body)
    else:
        rec.update(http_get(args.port, args.path,
                            cookies=("PHPSESSID=" + args.sid) if args.sid else None))

    out = json.dumps(rec, indent=2)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
