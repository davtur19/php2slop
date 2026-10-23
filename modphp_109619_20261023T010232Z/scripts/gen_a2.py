#!/usr/bin/env python3
"""Generate an A2 (cheap OOM) body with layout knobs."""
import argparse, sys
sys.path.insert(0, "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure")
from cheap_oom_a import build_body

ap = argparse.ArgumentParser()
ap.add_argument("--body", required=True)
ap.add_argument("--parts", type=int, default=880)
ap.add_argument("--depth", type=int, default=64)
ap.add_argument("--fillers", type=int, default=115)
ap.add_argument("--shift40", type=int, default=0)
ap.add_argument("--fillers128", type=int, default=0)
ap.add_argument("--drainers256", type=int, default=0)
ap.add_argument("--donors64", type=int, default=0)
ap.add_argument("--burners1200", type=int, default=0)
ap.add_argument("--burner-len", type=int, default=1200)
a = ap.parse_args()
body = build_body(a.parts, a.depth, a.fillers, b"a" * 32, b"k0", b"C" * 10,
                  shift40=a.shift40, fillers128=a.fillers128,
                  drainers256=a.drainers256, donors64=a.donors64,
                  burners1200=a.burners1200, burner_len=a.burner_len)
open(a.body, "wb").write(body)
print("wrote %d" % len(body))
