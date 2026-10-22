#!/usr/bin/env python3
"""GET helper for the OpenMage reader pool: sends the app cookie and the configured
base-URL Host header (127.0.0.1:28895) to a private nginx port."""
import sys, http.client, time

port = int(sys.argv[1]); sid = sys.argv[2]; path = sys.argv[3]; out = sys.argv[4]
c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
h = {"Host": "127.0.0.1:28895", "Cookie": f"om_frontend={sid}", "Connection": "close"}
t0 = time.time()
c.request("GET", path, headers=h)
r = c.getresponse(); body = r.read(); c.close()
with open(out + ".hdr", "wb") as f:
    f.write(f"HTTP/1.1 {r.status} {r.reason}\n".encode())
    for k, v in r.getheaders():
        f.write(f"{k}: {v}\n".encode())
open(out + ".body", "wb").write(body)
print(f"status={r.status} len={len(body)} t={time.time()-t0:.3f} body={body[:120]!r}")
