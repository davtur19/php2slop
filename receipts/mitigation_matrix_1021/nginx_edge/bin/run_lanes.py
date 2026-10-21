#!/usr/bin/env python3
"""run_lanes.py - measured battery for the nginx edge mitigation lanes.

Every case snapshots the PHP-FPM error log, the PHP-FPM access log and the
per-lane session directory before/after the request, so "PHP never saw it"
(edge reject) is distinguished from "PHP saw it and died" (fatal in FPM log).
Writes results/lanes.jsonl (one JSON object per case).
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import narm

BASE = "/tmp/opencode/nginx_mitigation_1021"
RESULTS = os.path.join(BASE, "results")
OOM_RE = narm.OOM_RE


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


def read_new(p, off):
    try:
        with open(p, "rb") as f:
            f.seek(off)
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def sess_state(d):
    try:
        names = os.listdir(d)
    except OSError:
        return {}
    out = {}
    for n in names:
        p = os.path.join(d, n)
        try:
            with open(p, "rb") as f:
                data = f.read()
            out[n] = {"size": len(data), "upg": b"upload_progress_" in data}
        except OSError:
            pass
    return out


LANES = {
    "N0": {"port": 29000, "err": f"{BASE}/logs/fpm_n0.error.log",
           "acc": f"{BASE}/logs/fpm_n0.access.log",
           "ngx": f"{BASE}/logs/n0.access.log", "sess": f"{BASE}/sessions/n0"},
    "N1": {"port": 29001, "err": f"{BASE}/logs/fpm_n1.error.log",
           "acc": f"{BASE}/logs/fpm_n1.access.log",
           "ngx": f"{BASE}/logs/n1.access.log", "sess": f"{BASE}/sessions/n1"},
    "N2": {"port": 29002, "err": f"{BASE}/logs/fpm_n2.error.log",
           "acc": f"{BASE}/logs/fpm_n2.access.log",
           "ngx": f"{BASE}/logs/n2.access.log", "sess": f"{BASE}/sessions/n2"},
    "N3": {"port": 29003, "err": f"{BASE}/logs/fpm_n3.error.log",
           "acc": f"{BASE}/logs/fpm_n3.access.log",
           "ngx": f"{BASE}/logs/n3up.access.log", "sess": f"{BASE}/sessions/n3"},
    "N3-8k": {"port": 29008, "err": f"{BASE}/logs/fpm_n3.error.log",
              "acc": f"{BASE}/logs/fpm_n3.access.log",
              "ngx": f"{BASE}/logs/n3up.access.log", "sess": f"{BASE}/sessions/n3"},
    "N4": {"port": 29004, "err": f"{BASE}/logs/fpm_n4.error.log",
           "acc": f"{BASE}/logs/fpm_n4.access.log",
           "ngx": f"{BASE}/logs/n4.access.log", "sess": f"{BASE}/sessions/n4"},
    "SWEEP": {"port": 29005, "err": f"{BASE}/logs/fpm_sweep.error.log",
              "acc": f"{BASE}/logs/fpm_sweep.access.log",
              "ngx": f"{BASE}/logs/sweep.access.log",
              "sess": f"{BASE}/sessions/sweep"},
    "N3-core": {"port": 29007, "err": f"{BASE}/logs/fpm_n3.error.log",
                "acc": f"{BASE}/logs/fpm_n3.access.log",
                "ngx": f"{BASE}/logs/n3core.access.log",
                "sess": f"{BASE}/sessions/n3"},
    "SHAPE": {"port": 29009, "err": f"{BASE}/logs/fpm_shape.error.log",
              "acc": f"{BASE}/logs/fpm_shape.access.log",
              "ngx": f"{BASE}/logs/shape.access.log",
              "sess": f"{BASE}/sessions/shape"},
}

ROWS = []


def pre(lane):
    L = LANES[lane]
    return {"err": size(L["err"]), "acc": size(L["acc"]), "ngx": size(L["ngx"]),
            "sess": sess_state(L["sess"])}


def post(lane, tag, extra, pre_state):
    time.sleep(0.15)   # let FPM flush its access/error log lines
    L = LANES[lane]
    err = read_new(L["err"], pre_state["err"])
    acc = read_new(L["acc"], pre_state["acc"])
    ngx = read_new(L["ngx"], pre_state["ngx"])
    now = sess_state(L["sess"])
    new_sess = {k: v for k, v in now.items() if k not in pre_state["sess"]}
    changed = {k: v for k, v in now.items()
               if k in pre_state["sess"] and v != pre_state["sess"][k]}
    oom = OOM_RE.search(err)
    php_fatal = "Fatal error" in err or "Fatal error" in extra.get("resp_body_head", "")
    row = {
        "tag": tag, "lane": lane, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "port": extra.get("port"), "path": extra.get("path"),
        "body_len": extra.get("body_len"),
        "http_status": extra.get("http_status"),
        "resp_len": extra.get("resp_len"),
        "send_error": extra.get("send_error"),
        "duration_s": extra.get("duration_s"),
        "resp_out_head": (extra.get("resp_body_head") or "")[:160],
        "script_output": "S:count=" in (extra.get("resp_body_head") or ""),
        "php_fatal": php_fatal,
        "oom_limit": int(oom.group(1)) if oom else None,
        "oom_tried": (int(oom.group(2)) if (oom and oom.group(2)) else None),
        "fpm_access_lines": len([x for x in acc.splitlines() if x.strip()]),
        "fpm_access_tail": acc.strip().splitlines()[-1] if acc.strip() else None,
        "nginx_access_lines": len([x for x in ngx.splitlines() if x.strip()]),
        "nginx_access_tail": ngx.strip().splitlines()[-1] if ngx.strip() else None,
        "php_error_delta_chars": len(err),
        "new_session_files": list(new_sess.keys()),
        "new_session_has_upload_progress": any(v["upg"] for v in new_sess.values()),
        "changed_session_has_upload_progress": any(v["upg"] for v in changed.values()),
        "extra": extra.get("extra", {}),
    }
    ROWS.append(row)
    with open(os.path.join(RESULTS, "lanes.jsonl"), "a") as f:
        f.write(json.dumps(row) + "\n")
    return row


def case(lane, tag, body, path="/index.php", cookie=None, chunked=False,
         extra_headers=None, port=None, timeout=120.0):
    L = LANES[lane]
    p = pre(lane)
    r = narm.raw_post(port or L["port"], path, body, timeout, chunked=chunked,
                      cookie=cookie, extra_headers=extra_headers)
    r["extra"] = {"headers": extra_headers or {}}
    return post(lane, tag, r, p)


def get_case(lane, tag, path="/probe.php", sid=None, extra_headers=None):
    L = LANES[lane]
    p = pre(lane)
    r = narm.http_get(L["port"], path,
                      cookies=("PHPSESSID=" + sid) if sid else None)
    r["body_len"] = 0
    r["extra"] = {"headers": extra_headers or {}}
    return post(lane, tag, r, p)


def summarize(rows, keys):
    out = []
    for r in rows:
        out.append({k: r.get(k) for k in keys})
    return out


def dump_summary(name, rows, keys):
    with open(os.path.join(RESULTS, name), "w") as f:
        json.dump(summarize(rows, keys), f, indent=2)
