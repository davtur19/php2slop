#!/usr/bin/env python3
"""Summarize every attempt result into one TSV (receipts/summary.tsv)."""
from __future__ import annotations

import glob
import json
import os
import re

D = open("/tmp/opencode/.fullchain_mw_current").read().strip()


def main() -> int:
    rows = []
    for rp in sorted(glob.glob(os.path.join(D, "work", "attempt_r*", "result.json")),
                     key=lambda p: int(re.search(r"attempt_r(\d+)", p).group(1))):
        n = int(re.search(r"attempt_r(\d+)", rp).group(1))
        r = json.load(open(rp))
        meta = os.path.join(D, "receipts", "logs", "attempt_r%d" % n, "meta.json")
        mode = ""
        if os.path.exists(meta):
            mode = json.loads(open(meta).readline()).get("mode", "")
        stages = r.get("stages", [])
        b1 = [s for s in stages if s["stage"] == "B1"]
        a2 = [s for s in stages if s["stage"] == "A2"]
        b2 = [s for s in stages if s["stage"] == "B2"]
        crash = ""
        dp = os.path.join(D, "receipts", "logs", "attempt_r%d" % n, "docker.log")
        if os.path.exists(dp):
            pids = []
            for line in open(dp, errors="replace"):
                m = re.search(r"AH00052: child pid (\d+) exit signal "
                              r"(Segmentation fault|Abort)", line)
                if m:
                    pids.append("%s:%s" % (m.group(1), m.group(2)))
            crash = ",".join(pids)
        target = ("p2s-single-18611"
                  if n in set(range(21, 27)) | {14, 15, 16} | set(range(31, 37))
                  else "p2s-mw-18610")
        rows.append([
            n, target, mode, r.get("route", ""), r.get("success"),
            r.get("b1_hit_attempt", ""), r.get("b2_hit_attempt", ""),
            r.get("failed_stage", ""), len(b1), len(a2), len(b2),
            r.get("post_health", {}).get("status", ""),
            r.get("post_health", {}).get("body", "").strip(),
            crash,
        ])
    out = os.path.join(D, "receipts", "summary.tsv")
    with open(out, "w") as fh:
        fh.write("attempt\ttarget\tmode\troute\tsuccess\tb1_hit\tb2_hit\tfailed_stage\t"
                 "b1_n\ta2_n\tb2_n\thealth\tbody\tcrash\n")
        for row in rows:
            fh.write("\t".join("" if x is None else str(x) for x in row) + "\n")
    print(out, len(rows), "rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
