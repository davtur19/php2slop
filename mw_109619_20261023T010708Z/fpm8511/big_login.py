#!/usr/bin/env python3
"""One large-password login attempt against the MW FPM lab, with memory/receipt capture."""
import os, re, sqlite3, subprocess, sys, time, zlib
import login_probe as L
import fpmstat

LAB = os.path.dirname(os.path.abspath(__file__))

def session_row(sid):
    c = sqlite3.connect(os.path.join(LAB, "data", "wikicache.sqlite"))
    r = c.execute("select keyname,value from objectcache where keyname like ?",
                  ("%MWSession:" + sid,)).fetchone()
    if not r:
        return None
    k, v = r
    try:
        d = zlib.decompress(v, -15)
    except Exception:
        d = v
    return {"blob_len": len(v), "inflated_len": len(d), "prefix": d[:120],
            "has_authn": b"AuthManager::authnState" in d}

def one(size, name="SomeUser", char="A"):
    before = fpmstat.status()
    g = L.get_login()
    sid = g["sid"]
    t0 = time.time()
    r = L.post_login(g["cookie"], g["token"], g["edittoken"], name, char * size,
                     outname="big_%d.raw" % size)
    dt = time.time() - t0
    time.sleep(0.2)
    after = fpmstat.status()
    row = session_row(sid)
    return {"size": size, "sid": sid, "post": r, "seconds": round(dt, 3),
            "before_pids": [p.get("pid") for p in before],
            "after_pids": [p.get("pid") for p in after],
            "after_mem": [(p.get("pid"), p.get("last request memory")) for p in after],
            "row": row}

if __name__ == "__main__":
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 4_000_000
    name = sys.argv[2] if len(sys.argv) > 2 else "SomeUser"
    res = one(size, name)
    print("size", res["size"], "sid", res["sid"], "secs", res["seconds"])
    print("status", res["post"]["status"], "first", res["post"]["first"], "len", res["post"]["len"])
    print("before pids", res["before_pids"])
    print("after pids ", res["after_pids"])
    print("after mem  ", res["after_mem"])
    print("row", res["row"])
    raw = open(os.path.join(LAB, "probe_tmp", "big_%d.raw" % size), "rb").read()
    body = raw.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")
    for m in re.finditer(r'<div class="[^"]*(?:error|message)[^"]*"[^>]*>(.*?)</div>', body, re.S):
        txt = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        if txt:
            print("msg:", txt[:300])
    print("stderr tail:", res["post"]["stderr"][-300:])
