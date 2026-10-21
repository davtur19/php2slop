#!/usr/bin/env python3
"""capture.py - exact wire transcripts for the edge responses (loopback only)."""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import narm

BASE = "/tmp/opencode/nginx_mitigation_1021"
T = os.path.join(BASE, "results", "transcripts")
SID = narm.ARM_SID
COOKIE = "PHPSESSID=" + SID.decode()


def wire(port, path, body, cookie=COOKIE, headers=None, chunked=False, timeout=120):
    hdrs = [f"POST {path} HTTP/1.1", f"Host: 127.0.0.1:{port}",
            "Content-Type: multipart/form-data; boundary=" + narm.BOUNDARY.decode(),
            "Connection: close"]
    if cookie:
        hdrs.append("Cookie: " + cookie)
    for k, v in (headers or {}).items():
        hdrs.append(f"{k}: {v}")
    if chunked:
        hdrs.append("Transfer-Encoding: chunked")
    else:
        hdrs.append("Content-Length: %d" % len(body))
    req = ("\r\n".join(hdrs) + "\r\n\r\n").encode()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(req)
    try:
        if chunked:
            step = 65536
            for i in range(0, len(body), step):
                p = body[i:i + step]
                s.sendall(b"%x\r\n" % len(p) + p + b"\r\n")
            s.sendall(b"0\r\n\r\n")
        else:
            step = 65536
            for i in range(0, len(body), step):
                s.sendall(body[i:i + step])
    except (BrokenPipeError, ConnectionResetError) as e:
        print("  send stopped early:", type(e).__name__)
    out = []
    while True:
        try:
            b = s.recv(65536)
        except (ConnectionResetError, socket.timeout):
            break
        if not b:
            break
        out.append(b)
    s.close()
    return b"".join(out)


def save(name, raw, meta):
    p = os.path.join(T, name)
    mode = "wb"
    with open(p, mode) as f:
        f.write(raw)
    with open(p + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    print(name, "bytes=", len(raw), "status-line=", raw.split(b"\r\n")[0][:40])


def main():
    os.makedirs(T, exist_ok=True)
    arm = narm.arm_body(SID)
    small = narm.shape_body(b"capshape000000001", b"PHP_SESSION_UPLOAD_PROGRESS")

    raw = wire(29001, "/index.php", arm)
    save("413_n1_client_max_body_size.http", raw,
         {"lane": "N1", "port": 29001, "body_len": len(arm),
          "expect": "413 from nginx, request never forwarded to PHP"})

    raw = wire(29000, "/index.php", arm)
    save("200empty_n0_oom.http", raw,
         {"lane": "N0", "port": 29000, "body_len": len(arm),
          "expect": "200 with empty chunked body; PHP fatal only in fpm error log"})

    big = narm.arm_body(SID, 262144, 8)
    raw = wire(29001, "/index.php", big)
    save("200_n1_under_cap.http", raw,
         {"lane": "N1", "port": 29001, "body_len": len(big),
          "expect": "200 + script output (128M headroom)"})

    raw = wire(29003, "/index.php", arm)
    save("403_shim_token_arm.http", raw,
         {"lane": "N3-refshim", "port": 29003, "body_len": len(arm),
          "expect": "403 from reference token rule; PHP never reached"})

    raw = wire(29003, "/index.php", small, cookie="PHPSESSID=capsmall0000000001")
    save("403_shim_small_token.http", raw,
         {"lane": "N3-refshim", "port": 29003, "body_len": len(small),
          "expect": "403 even for a tiny body: rule is content-only"})

    raw = wire(29007, "/index.php", small, cookie="PHPSESSID=capcore0000000001")
    save("200_n3core_if_request_body.http", raw,
         {"lane": "N3-core-approx", "port": 29007, "body_len": len(small),
          "expect": "200: if($request_body ~ TOKEN) never fires (body not read at rewrite phase)"})

    # 429: exhaust the 10r/m + burst=5 zone on N4 with tiny requests
    for i in range(7):
        raw = wire(29004, "/upload.php", narm.legit_body())
        if i == 6:
            save("429_n4_limit_req.http", raw,
                 {"lane": "N4", "port": 29004, "burst_index": i + 1,
                  "expect": "429 limit_req_status after burst=5 at rate=10r/m"})


if __name__ == "__main__":
    main()
