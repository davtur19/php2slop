#!/usr/bin/env python3
"""Login probe: GET Special:UserLogin, extract token, POST a login attempt."""
import os, re, subprocess, sys, urllib.parse, glob

LAB = os.path.dirname(os.path.abspath(__file__))
FCGI = os.path.join(LAB, "fcgi.py")
TMP = os.path.join(LAB, "probe_tmp")
os.makedirs(TMP, exist_ok=True)

def run(args, out):
    p = subprocess.run([sys.executable, FCGI] + args + ["--out", out],
                       capture_output=True, text=True, timeout=300)
    return p

def get_login(cookie=None):
    out = os.path.join(TMP, "get.raw")
    args = ["--method", "GET", "--uri", "/index.php?title=Special:UserLogin"]
    if cookie:
        args += ["--cookie", cookie]
    p = run(args, out)
    raw = open(out, "rb").read()
    m = re.search(rb"Set-Cookie: my_wiki_session=([0-9a-zA-Z]+);", raw)
    sid = m.group(1).decode() if m else None
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw
    html = body.decode("utf-8", "replace")
    tok = re.search(r'name="wpLoginToken" type="hidden" value="([^"]+)"', html)
    edit = re.search(r'<input id="wpEditToken" type="hidden" value="([^"]*)" name="wpEditToken">', html)
    status = re.search(r"client: app_status=(\S+)", p.stderr)
    return {
        "sid": sid,
        "cookie": cookie or ("my_wiki_session=" + sid if sid else None),
        "token": tok.group(1) if tok else None,
        "edittoken": edit.group(1) if edit else None,
        "status": status.group(1) if status else p.stderr,
        "body_len": len(body),
    }

def post_login(cookie, token, edittoken, name, password, extra="", outname="post.raw"):
    out = os.path.join(TMP, outname)
    body = ("title=Special:UserLogin&authAction=login&wploginattempt=Log+in"
            "&wpName=" + urllib.parse.quote_plus(name) +
            "&wpPassword=" + urllib.parse.quote_plus(password) +
            "&wpRemember=1&wpEditToken=" + urllib.parse.quote_plus(edittoken or "") +
            "&wpLoginToken=" + urllib.parse.quote_plus(token or "") +
            "&force=" + extra).encode()
    bfile = os.path.join(TMP, outname + ".body")
    open(bfile, "wb").write(body)
    args = ["--method", "POST", "--uri", "/index.php?title=Special:UserLogin",
            "--body", bfile, "--cookie", cookie, "--chunk-size", "65535"]
    p = run(args, out)
    if not os.path.exists(out):
        return {"status": "NOOUT", "first": "", "len": 0, "body_len": len(body),
                "stderr": p.stderr[-1000:]}
    raw = open(out, "rb").read()
    status = re.search(r"client: app_status=(\S+)", p.stderr)
    first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace") if raw else ""
    return {"status": status.group(1) if status else p.stderr, "first": first,
            "len": len(raw), "body_len": len(body), "stderr": p.stderr[-500:]}

if __name__ == "__main__":
    g = get_login()
    print("GET:", {k: (v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v)
                    for k, v in g.items()})
    r = post_login(g["cookie"], g["token"], g["edittoken"], "SomeUser", "wrongpass")
    print("POST:", r)
