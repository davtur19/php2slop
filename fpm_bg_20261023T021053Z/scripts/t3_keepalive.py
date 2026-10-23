#!/usr/bin/env python3
import http.client, re, sys

def run(port, n=10, host="127.0.0.1"):
    c = http.client.HTTPConnection(host, port, timeout=10)
    pids = []
    for _ in range(n):
        c.request("GET", "/ping.php")
        r = c.getresponse()
        body = r.read().decode("latin1")
        m = re.search(r"PID=(\d+)", body)
        pids.append(m.group(1) if m else "?")
    c.close()
    return pids

if __name__ == "__main__":
    port = int(sys.argv[1])
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    pids = run(port, n)
    print("port=%d n=%d distinct=%d" % (port, n, len(set(pids))))
    print(" ".join(pids))
