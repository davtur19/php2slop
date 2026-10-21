#!/usr/bin/env python3
"""Slow stdin feeder: emits body bytes at a controlled rate (default 40 KB/s)."""
import sys, time
path = sys.argv[1]
rate = int(sys.argv[2]) if len(sys.argv) > 2 else 40000  # bytes/s
buf = 4096
delay = buf / rate
with open(path, "rb") as f:
    while True:
        chunk = f.read(buf)
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        time.sleep(delay)
