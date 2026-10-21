#!/usr/bin/env python3
"""Minimal FastCGI client (no external deps) for the FPM same-worker lane.

One request per TCP connection; collects STDOUT/STDERR and END_REQUEST status.
"""
import socket, struct, time, threading

FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1

HDR = struct.Struct(">BBHHBB")


def _nv(name, value):
    if isinstance(name, str):
        name = name.encode()
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, int):
        value = str(value).encode()

    def L(n):
        return bytes([n]) if n < 128 else struct.pack(">I", n | 0x80000000)

    return L(len(name)) + L(len(value)) + name + value


def _rec(typ, rid, content=b""):
    pad = (8 - len(content) % 8) % 8
    return HDR.pack(1, typ, rid, len(content), pad, 0) + content + b"\x00" * pad


def _recs(typ, rid, data, chunk=65535):
    out = b""
    for i in range(0, len(data), chunk):
        out += _rec(typ, rid, data[i:i + chunk])
    return out + _rec(typ, rid, b"")


def _readn(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("peer closed after %d/%d bytes" % (len(buf), n))
        buf += part
    return buf


def request(host, port, params, body=b"", timeout=60.0, connect_timeout=10.0):
    """Return dict with rc/stdout/stderr/end/app_status/protocol_status/duration/error."""
    rid = 1
    t0 = time.time()
    res = {"rc": None, "stdout": b"", "stderr": b"", "end": None,
           "app_status": None, "protocol_status": None, "error": None,
           "duration_s": None}
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock.settimeout(timeout)
        payload = _rec(FCGI_BEGIN_REQUEST, rid, struct.pack(">HB5s", FCGI_RESPONDER, 0, b"\x00" * 5))
        payload += _recs(FCGI_PARAMS, rid, b"".join(_nv(k, v) for k, v in params.items()))
        sock.sendall(payload)

        # Send the body in a thread: if the server aborts the request early (OOM)
        # and closes the socket, we still must be able to read/observe that.
        send_state = {"sent": 0, "error": None}

        def _sender():
            try:
                for i in range(0, len(body), 65535):
                    sock.sendall(_rec(FCGI_STDIN, rid, body[i:i + 65535]))
                    send_state["sent"] = min(i + 65535, len(body))
                sock.sendall(_rec(FCGI_STDIN, rid, b""))
            except Exception as exc:
                send_state["error"] = "%s: %s" % (type(exc).__name__, exc)

        th = threading.Thread(target=_sender, daemon=True)
        th.start()
        th_local = th
        while True:
            hdr = _readn(sock, 8)
            ver, typ, srid, clen, plen, _ = HDR.unpack(hdr)
            content = _readn(sock, clen)
            if plen:
                _readn(sock, plen)
            if typ == FCGI_STDOUT:
                res["stdout"] += content
            elif typ == FCGI_STDERR:
                res["stderr"] += content
            elif typ == FCGI_END_REQUEST:
                res["app_status"], res["protocol_status"], _ = struct.unpack(">IB3s", content)
                res["end"] = True
                break
        res["rc"] = 0
        th_local.join(timeout=5)
        res["stdin_sent"] = send_state
        sock.close()
    except Exception as exc:  # timeouts, resets, early close
        res["error"] = "%s: %s" % (type(exc).__name__, exc)
        res["rc"] = "ERR"
        try:
            res["stdin_sent"] = send_state
        except NameError:
            pass
    res["duration_s"] = round(time.time() - t0, 4)
    res["ts"] = t0
    return res


def split_http(raw):
    """Split an FCGI STDOUT blob into (status_line, headers dict, body)."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    status = lines[0].decode("latin-1") if lines and lines[0] else ""
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        headers.setdefault(k.strip().lower().decode("latin-1"), []).append(v.strip().decode("latin-1"))
    return status, headers, body


def env(sid, script, workdir, method="GET", body_len=0, content_type=None, query="",
        extra=None, host="127.0.0.1", port=28961, body=b"", timeout=60.0):
    p = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": method,
        "SCRIPT_FILENAME": "%s/%s" % (workdir, script),
        "SCRIPT_NAME": "/" + script,
        "REQUEST_URI": "/" + script + (("?" + query) if query else ""),
        "QUERY_STRING": query,
        "DOCUMENT_ROOT": workdir,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8080",
        "REMOTE_ADDR": "127.0.0.1",
        "REMOTE_PORT": "40000",
        "HTTP_HOST": "localhost",
        "HTTP_COOKIE": "PHPSESSID=" + sid,
    }
    if body_len:
        p["CONTENT_LENGTH"] = str(body_len)
    if content_type:
        p["CONTENT_TYPE"] = content_type
    if extra:
        p.update(extra)
    return request(host, port, p, body=body, timeout=timeout)


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=28961)
    ap.add_argument("--script", default="probe.php")
    ap.add_argument("--sid", default="labprobe123")
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--query", default="")
    a = ap.parse_args()
    r = env(a.sid, a.script, a.workdir, query=a.query, port=a.port)
    st, hd, bd = split_http(r["stdout"])
    print(json.dumps({"rc": r["rc"], "error": r["error"], "status": st,
                      "headers": hd, "body": bd.decode("latin-1"),
                      "stderr": r["stderr"].decode("latin-1", "replace"),
                      "duration_s": r["duration_s"]}, indent=1))
