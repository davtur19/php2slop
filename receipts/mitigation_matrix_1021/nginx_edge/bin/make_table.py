#!/usr/bin/env python3
"""make_table.py - render results/lanes.jsonl + headroom data into results/table.md"""
import json
import os

BASE = "/tmp/opencode/nginx_mitigation_1021"
R = os.path.join(BASE, "results")
ROWS = [json.loads(l) for l in open(os.path.join(R, "lanes.jsonl"))]


def g(r, k, d="-"):
    v = r.get(k)
    return d if v in (None, "") else v


lines = ["# Measured lane results (nginx 1.30.1 edge -> PHP 8.5.10 FPM)", "",
         "Arm shape: multipart body, `PHPSESSID` field + optional",
         "`PHP_SESSION_UPLOAD_PROGRESS` field + N file parts with `F`*262144",
         "filenames. Stock arm = 4,983,500 B. `PHP reached` = an FPM access-log",
         "line exists for the request OR a PHP fatal was logged. (FPM does not",
         "write an access line for a request that dies pre-RINIT, so the error",
         "log is the authoritative signal for a fatal.)", "",
         "| lane | scenario | body B | HTTP | PHP reached | PHP fatal | OOM limit/tried | evidence |",
         "|---|---|---:|---:|---|---|---|---|"]

for r in ROWS:
    reached = "yes" if (r.get("fpm_access_lines") or r.get("php_fatal")) else "NO"
    fatal = "yes" if r.get("php_fatal") else "no"
    oom = f"{r['oom_limit']}/{r['oom_tried']}" if r.get("oom_limit") else "-"
    ev = []
    if r.get("resp_len") is not None:
        ev.append(f"resp={r['resp_len']}B")
    if r.get("script_output"):
        ev.append("script output")
    if r.get("new_session_files"):
        ev.append("new sess " + ",".join(r["new_session_files"])[:40])
    if r.get("changed_session_has_upload_progress"):
        ev.append("sess updated upload_progress")
    if r.get("send_error"):
        ev.append("send:" + str(r["send_error"]))
    lines.append(f"| {r['lane']} | {r['tag']} | {g(r,'body_len')} | {g(r,'http_status')} | "
                 f"{reached} | {fatal} | {oom} | {'; '.join(ev) or '-'} |")

# headroom section (token=True only: the attacker can always include it)
lines += ["", "## Headroom measurements (fresh worker per request, token field present)", "",
          "| parts | body B | max limit WITH fatal | min limit with 0 fatal | k = limit/body |",
          "|---:|---:|---:|---:|---:|"]
import collections
agg = collections.defaultdict(lambda: {"ok": set(), "bad": set(), "body": set()})
for f in ("headroom.json", "headroom2.json"):
    for ln in open(os.path.join(R, f)):
        r = json.loads(ln)
        if not r.get("token", True):
            continue
        k = (r["parts"], r["length"])
        lb = r.get("limit_bytes", (r.get("limit_mb") or 0) * 1048576)
        agg[k]["ok" if not r["fatal"] else "bad"].add(lb)
        agg[k]["body"].add(r["body_len"])
for (parts, length), v in sorted(agg.items()):
    ok, bad = sorted(v["ok"]), sorted(v["bad"])
    if not ok:
        continue
    body = max(v["body"])
    badmax = bad[-1] if bad else 0
    lines.append(f"| {parts} | {body} | {badmax} | {ok[0]} | {ok[0]/body:.2f} |")

with open(os.path.join(R, "table.md"), "w") as f:
    f.write("\n".join(lines) + "\n")
print("wrote", os.path.join(R, "table.md"), len(lines), "lines")
