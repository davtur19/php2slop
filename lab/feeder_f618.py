#!/usr/bin/env python3
"""Feeder: writes phase1 to stdout, sleeps stall, writes tail, closes."""
import sys
import time

phase1_path, tail_path, stall = sys.argv[1], sys.argv[2], float(sys.argv[3])
with open(phase1_path, "rb") as f:
    phase1 = f.read()
with open(tail_path, "rb") as f:
    tail = f.read()
out = sys.stdout.buffer
out.write(phase1)
out.flush()
time.sleep(stall)
out.write(tail)
out.flush()
