#!/usr/bin/env python3
"""headroom.py - fresh vs warm worker OOM boundary for the multipart arm.

Every trial reads the FPM error log delta, so a fatal is attributed to the
exact request (a response body alone is not reliable: FPM returns an empty
200 on a pre-RINIT fatal).
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
ERR = {"fresh": f"{BASE}/logs/fpm_fresh.error.log",
       "warm": f"{BASE}/logs/fpm_warm.error.log"}
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


def trial(kind, parts, limit_mb, length=262144, tag=""):
    body = narm.arm_body(SID, length, parts)
    p = ERR[kind]
    off = size(p)
    r = narm.raw_post(29010 if kind == "fresh" else 29011, "/index.php", body, 90,
                      cookie=COOKIE, extra_headers={"X-PHP-Mem": f"{limit_mb}M"})
    time.sleep(0.05)
    delta = new_bytes(p, off)
    oom = narm.OOM_RE.search(delta.decode("utf-8", "replace"))
    rec = {"kind": kind, "parts": parts, "length": length, "body_len": len(body),
           "limit_mb": limit_mb, "fatal": bool(oom),
           "tried": int(oom.group(2)) if (oom and oom.group(2)) else None,
           "resp_len": r["resp_len"], "output": "S:count=" in (r["resp_body_head"] or ""),
           "status": r["http_status"], "tag": tag}
    OUT.append(rec)
    return rec


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    # A) fresh vs warm at 8M across body sizes
    print("== A: fresh vs warm @ 8M ==")
    for parts in (4, 6, 8, 10, 12, 16, 20):
        for kind in ("fresh", "warm"):
            rs = [trial(kind, parts, 8) for _ in range(trials)]
            nf = sum(1 for r in rs if r["fatal"])
            print(f"parts={parts:2d} len={rs[0]['body_len']:8d} {kind:5s} "
                  f"fatal={nf}/{trials} tried={sorted({r['tried'] for r in rs if r['tried']})}")
    # B) limit grid, fresh workers
    print("== B: limit grid (fresh) ==")
    for parts, limits in ((8, (6, 8, 10, 12, 16)),
                          (20, (8, 12, 16, 20, 24, 32))):
        for lim in limits:
            rs = [trial("fresh", parts, lim) for _ in range(trials)]
            nf = sum(1 for r in rs if r["fatal"])
            print(f"parts={parts:2d} len={rs[0]['body_len']:8d} lim={lim:2d}M "
                  f"fatal={nf}/{trials} tried={sorted({r['tried'] for r in rs if r['tried']})}")
    with open(os.path.join(BASE, "results", "headroom.json"), "a") as f:
        for r in OUT:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
