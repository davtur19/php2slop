#!/usr/bin/env python3
"""Post-hoc attribution of the blind chain to prefork children.

Uses the instrumentation-only access log (leading %P = child pid) and the
master's AH00052 crash lines.  This is lab analysis after the fact; the attack
driver never reads these.
"""
from __future__ import annotations

import calendar
import json
import os
import re
import sys
import time

D = open("/tmp/opencode/.fullchain_mw_current").read().strip()


def epoch(ts: str) -> float:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


def main() -> int:
    rows = []
    summary = {}
    wanted = [int(x) for x in sys.argv[1:]] or list(range(1, 27))
    for n in wanted:
        base = os.path.join(D, "work", "attempt_r%d" % n)
        if not os.path.exists(os.path.join(base, "result.json")):
            continue
        r = json.load(open(os.path.join(base, "result.json")))
        meta = json.loads(open(os.path.join(
            D, "receipts", "logs", "attempt_r%d" % n, "meta.json")).readline())
        t0 = epoch(meta["start"])
        logp = os.path.join(D, "receipts", "logs", "attempt_r%d" % n, "p2s-access.log")
        lines = []
        for line in open(logp, errors="replace"):
            f = line.split()
            if len(f) < 7:
                continue
            try:
                ts = float(f[1])
                pid = int(f[0])
            except ValueError:
                continue
            if ts < t0 - 0.5:
                continue
            lines.append({"pid": pid, "ts": ts, "method": f[2], "path": f[3],
                          "status": f[4], "body": f[5],
                          "dur_us": int(f[6]) if f[6].isdigit() else None,
                          "raw": line.rstrip("\n")})
        b1 = [s for s in r["stages"] if s["stage"] == "B1"]
        a2 = [s for s in r["stages"] if s["stage"] == "A2"]
        b2 = [s for s in r["stages"] if s["stage"] == "B2"]

        # %U omits the query string, so assign by the known chronological
        # stage order: A1, B1 x n_b1, A2 x n_a2, B2 misses (the successful B2
        # crashes before an access line is written).
        posts = [l for l in lines if l["method"] == "POST"]
        a1 = posts[0] if posts and posts[0]["status"] == "500" else None
        rest = posts[1:] if a1 else posts
        b1_lines = [l for l in rest[:len(b1)] if l["status"] == "200"]
        rest = rest[len(b1):]
        a2_lines = [l for l in rest[:len(a2)] if l["status"] == "500"]
        rest = rest[len(a2):]
        b2_lines = [l for l in rest if l["status"] == "200" and l["body"] == "3"]

        if a1:
            rows.append((n, "A1", "", a1["pid"], a1["status"], a1["body"],
                         a1["dur_us"], "%.6f" % a1["ts"], "q-params"))
        for i, s in enumerate(b1):
            l = b1_lines[i] if i < len(b1_lines) else None
            rows.append((n, "B1", i, l["pid"] if l else "", s.get("leak"),
                         s.get("bytes"), l["dur_us"] if l else "",
                         "%.6f" % l["ts"] if l else "", "cookie-leak"))
        for i, s in enumerate(a2):
            l = a2_lines[i] if i < len(a2_lines) else None
            rows.append((n, "A2", i, l["pid"] if l else "", s.get("status"),
                         s.get("bytes"), l["dur_us"] if l else "",
                         "%.6f" % l["ts"] if l else "", "cheap-OOM"))
        for i, s in enumerate(b2):
            l = b2_lines[i] if i < len(b2_lines) else None
            rows.append((n, "B2", i, l["pid"] if l else "", s.get("status"),
                         s.get("bytes"), l["dur_us"] if l else "",
                         "%.6f" % l["ts"] if l else "", "fake-ref"))
        crash = []
        crash_detail = {}
        dp = os.path.join(D, "receipts", "logs", "attempt_r%d" % n, "docker.log")
        for line in open(dp, errors="replace"):
            m = re.search(r"AH00052: child pid (\d+) exit signal "
                          r"(Segmentation fault|Abort)", line)
            if m:
                pid = int(m.group(1))
                crash.append(pid)
                crash_detail[pid] = m.group(2)
        summary[str(n)] = {
            "a1_pid": a1["pid"] if a1 else None,
            "b1_hit_pid": (b1_lines[-1]["pid"] if b1_lines and b1[-1].get("leak") == "hit"
                           else None),
            "b1_hit_attempt": r.get("b1_hit_attempt"),
            "a2_pids": [l["pid"] for l in a2_lines],
            "b2_miss_pids": [l["pid"] for l in b2_lines],
            "crash_pids": crash,
            "crash_detail": crash_detail,
            "success": r.get("success"),
            "b2_hit_attempt": r.get("b2_hit_attempt"),
            "sizes": {"a1": r["bodies"]["a1"]["bytes"], "b1": r["bodies"]["b1"]["bytes"],
                      "a2": r["bodies"].get("a2", {}).get("bytes"),
                      "b2": r["bodies"].get("b2_first", {}).get("bytes")},
        }
    out = os.path.join(D, "receipts", "worker_attribution.tsv")
    with open(out, "w") as fh:
        fh.write("attempt\tstage\tindex\tpid\tresult\tbytes\tduration_us\tts_epoch\tnote\n")
        for row in rows:
            fh.write("\t".join(str(x) for x in row) + "\n")
    json.dump(summary, open(os.path.join(D, "receipts", "worker_attribution.json"), "w"),
              indent=1)
    for k, v in summary.items():
        print(k, json.dumps(v))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
