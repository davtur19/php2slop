#!/usr/bin/env python3
"""headroom2.py - amplification model + token on/off contribution.

Model under test:  peak_parser_bytes ~= BASE + K * (total filename bytes in body)
For the stock arm shape, filename bytes ~= body bytes, so the edge rule is
memory_limit >= K * client_max_body_size + BASE.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import narm

BASE = "/tmp/opencode/nginx_mitigation_1021"
SID = narm.ARM_SID
COOKIE = "PHPSESSID=" + SID.decode()
ERR = f"{BASE}/logs/fpm_fresh.error.log"
OUT = []


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


def new_bytes(p, off):
    try:
        with open(p, "rb") as f:
            f.seek(off)
            return f.read()
    except OSError:
        return b""


def trial(parts, limit_bytes, length=262144, token=True, port=29010):
    body = narm.arm_body(SID, length, parts,
                         token_field=b"PHP_SESSION_UPLOAD_PROGRESS" if token else b"")
    off = size(ERR)
    r = narm.raw_post(port, "/index.php", body, 90, cookie=COOKIE,
                      extra_headers={"X-PHP-Mem": str(limit_bytes)})
    time.sleep(0.04)
    delta = new_bytes(ERR, off).decode("utf-8", "replace")
    oom = narm.OOM_RE.search(delta)
    rec = {"parts": parts, "length": length, "token": token,
           "body_len": len(body), "filename_bytes": parts * length - (length - 9) if length else 0,
           "limit_bytes": limit_bytes, "limit_mb": round(limit_bytes / 1048576, 3),
           "fatal": bool(oom),
           "tried": int(oom.group(2)) if (oom and oom.group(2)) else None,
           "resp_len": r["resp_len"], "status": r["http_status"]}
    OUT.append(rec)
    return rec


def safe(parts, limit_bytes, length=262144, token=True, reps=3):
    rs = [trial(parts, limit_bytes, length, token) for _ in range(reps)]
    return all(not r["fatal"] for r in rs), rs


def min_safe(parts, length=262144, token=True, lo=2 << 20, hi=64 << 20, step=1 << 20):
    assert safe(parts, hi, length, token)[0]
    while hi - lo > step:
        mid = ((lo + hi) // 2) // step * step
        if mid <= lo:
            break
        ok, _ = safe(parts, mid, length, token)
        if ok:
            hi = mid
        else:
            lo = mid
    return hi


def main():
    print("== A: upload-progress token contribution @ fresh worker ==")
    for parts in (8, 12, 20):
        for lim in (8 << 20, 10 << 20, 12 << 20):
            for tok in (True, False):
                rs = [trial(parts, lim, 262144, tok) for _ in range(4)]
                nf = sum(1 for r in rs if r["fatal"])
                print(f"parts={parts:2d} lim={lim>>20:2d}M token={str(tok):5s} "
                      f"fatal={nf}/4 tried={sorted({r['tried'] for r in rs if r['tried']})}")
    print("== B: min safe limit vs filename bytes (token on) ==")
    for parts, length in ((8, 65536), (8, 131072), (8, 262144), (8, 524288), (20, 262144)):
        m = min_safe(parts, length)
        body = parts * length
        print(f"parts={parts:2d} len={length:6d} body={body:8d} filename_bytes~{body:8d} "
              f"min_safe={m} ({m/1048576:.1f}M) k={m/body:.2f}")
    print("== C: at-cap 2m body at 8M vs 16M ==")
    # build the largest giant-filename body under 2m
    target = 2_090_000
    parts = 8
    per = (target - 1200) // (parts - 1)
    b = narm.arm_body(SID, per, parts)
    while len(b) >= 2_097_152:
        per -= 512
        b = narm.arm_body(SID, per, parts)
    for lim in (8 << 20, 12 << 20, 16 << 20):
        rs = [trial(parts, lim, per) for _ in range(3)]
        print(f"at_cap len={len(b)} lim={lim>>20}M fatal={sum(1 for r in rs if r['fatal'])}/3")
    with open(os.path.join(BASE, "results", "headroom2.json"), "a") as f:
        for r in OUT:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
