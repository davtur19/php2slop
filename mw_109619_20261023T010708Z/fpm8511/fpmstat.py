#!/usr/bin/env python3
"""Fetch /fpm-status?full via the lab FastCGI client and parse per-worker info."""
import os, re, subprocess, sys

LAB = os.path.dirname(os.path.abspath(__file__))
FCGI = os.path.join(LAB, "fcgi.py")
OUT = os.path.join(LAB, "probe_tmp", "status.raw")

def status():
    subprocess.run([sys.executable, FCGI, "--method", "GET", "--uri", "/fpm-status?full",
                    "--out", OUT, "--quiet"], capture_output=True, text=True, timeout=60)
    raw = open(OUT, "rb").read()
    body = raw.split(b"\r\n\r\n", 1)[1].decode("latin1") if b"\r\n\r\n" in raw else ""
    procs = []
    cur = None
    for line in body.splitlines():
        line = line.rstrip()
        if line.startswith("pid:"):
            if cur: procs.append(cur)
            cur = {"pid": line.split(":", 1)[1].strip()}
        elif cur is not None and ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip()
    if cur: procs.append(cur)
    return procs

if __name__ == "__main__":
    for p in status():
        print(p.get("pid"), p.get("state"), "reqs=" + str(p.get("requests")),
              "mem=" + str(p.get("last request memory")),
              "uri=" + str(p.get("request URI")))
