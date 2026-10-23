#!/usr/bin/env python3
"""Size sweep: username length vs password length for a login POST; capture memory + worker survival."""
import os, re, sqlite3, subprocess, sys, time, zlib
import login_probe as L
import fpmstat

LAB = os.path.dirname(os.path.abspath(__file__))
FIXED = 210  # approximate fixed body bytes

def session(sid):
    c = sqlite3.connect(os.path.join(LAB, "data", "wikicache.sqlite"))
    r = c.execute("select value from objectcache where keyname like ?",
                  ("%MWSession:" + sid,)).fetchone()
    if not r:
        return None
    v = r[0]
    try:
        d = zlib.decompress(v, -15)
    except Exception:
        d = v
    return {"blob": len(v), "inflated": len(d), "authn": b"AuthManager::authnState" in d,
            "keys": re.findall(rb's:\d+:"([^"]{1,40})"', d)[:8]}

def attempt(namelen, pwlen, tag):
    before = [p.get("pid") for p in fpmstat.status()]
    g = L.get_login()
    sid = g["sid"]
    t0 = time.time()
    r = L.post_login(g["cookie"], g["token"], g["edittoken"], "A" * namelen, "B" * pwlen,
                     outname="sweep_%s.raw" % tag)
    dt = time.time() - t0
    time.sleep(0.2)
    after = fpmstat.status()
    return {"tag": tag, "namelen": namelen, "pwlen": pwlen, "sid": sid,
            "body": FIXED + namelen + pwlen, "secs": round(dt, 3),
            "status": r["status"], "len": r["len"],
            "before": before, "after": [p.get("pid") for p in after],
            "mem": [(p.get("pid"), p.get("last request memory"), p.get("state")) for p in after],
            "session": session(sid)}

if __name__ == "__main__":
    namelen = int(sys.argv[1]); pwlen = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    tag = sys.argv[3] if len(sys.argv) > 3 else ("%d_%d" % (namelen, pwlen))
    res = attempt(namelen, pwlen, tag)
    for k, v in res.items():
        print(k, "=", v)
