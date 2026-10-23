#!/usr/bin/env python3
"""MW producer/consumer chain test on a static 2-worker FPM (18852).

  H  : held 6 MB upload-progress request, PHPSESSID=S  -> occupies worker A
       and keeps /sessions/sess_S non-empty.
  C1 : ~300 B upload-progress consumer, PHPSESSID=S    -> worker B (A busy)
  P  : max-size login POST (8.39 MB)                   -> worker B
  C2 : same ~300 B consumer                            -> worker B

Worker identity is read from /proc/<pid>/status VmHWM (peak RSS): the worker
that served P shows ~100 MB, the held-writer worker does not. No status
requests are issued between C1/P/C2 so the scoreboard stays untouched.
"""
import os, subprocess, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))
os.chdir(LAB)
os.environ["FPM_PORT"] = os.environ.get("FPM_PORT", "18852")
SID = "zzz1111111111111111111111111111111"
SESS = os.path.join(LAB, "sessions", "sess_" + SID)
BOUND = "----mw109619boundary"

import fpmstat


def fcgi(args, timeout=400):
    return subprocess.run([sys.executable, "fcgi.py"] + args,
                          capture_output=True, text=True, timeout=timeout)


def status(tag):
    print("[%s]" % tag)
    for p in fpmstat.status():
        print("   pid=%s state=%-26s reqs=%-4s mem=%-10s uri=%s" % (
            p.get("pid"), p.get("state"), p.get("requests"),
            p.get("last request memory"), p.get("request URI")))
    return [p.get("pid") for p in fpmstat.status()]


def hwm(pid):
    try:
        for line in open("/proc/%s/status" % pid):
            if line.startswith("VmHWM:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return "gone"
    return "?"


def rss(pid):
    try:
        for line in open("/proc/%s/status" % pid):
            if line.startswith("VmRSS:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return "gone"
    return "?"


def sess_size():
    try:
        return os.path.getsize(SESS)
    except OSError:
        return None


def consumer(tag):
    out = "cons_%s.raw" % tag
    p = fcgi(["--method", "POST", "--uri", "/index.php",
              "--content-type", "multipart/form-data; boundary=" + BOUND,
              "--body", "b_cons1w.bin", "--cookie", "PHPSESSID=" + SID,
              "--chunk-size", "65535", "--out", out])
    size = os.path.getsize(os.path.join(LAB, out)) if os.path.exists(os.path.join(LAB, out)) else -1
    raw = open(os.path.join(LAB, out), "rb").read() if os.path.exists(os.path.join(LAB, out)) else b""
    first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace") if raw else ""
    st = [l.strip() for l in p.stderr.splitlines() if "app_status=" in l]
    print("[%s] %s body=%d first=%r" % (tag, st[0] if st else "no-status", size, first))
    return st


def main():
    hold = None
    try:
        pids = status("start")
        print("SID", SID, "pre size", sess_size())
        hold = subprocess.Popen(
            [sys.executable, "fcgi.py", "--method", "POST", "--uri", "/index.php",
             "--content-type", "multipart/form-data; boundary=" + BOUND,
             "--body", "b_bigA.bin", "--cookie", "PHPSESSID=" + SID,
             "--truncate-after", "6001200", "--hold-seconds", "90",
             "--chunk-size", "65535", "--out", "hold_chain.raw"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # wait for the 6 MB body to be parsed and the session file written
        for i in range(20):
            time.sleep(1)
            if sess_size():
                break
        print("held size", sess_size(), "after", i + 1, "s")
        status("after H")

        print("C1:"); consumer("C1")
        print("size after C1", sess_size())

        print("P (max login):")
        p = subprocess.run([sys.executable, "sweep_login.py", "8387000", "1", "chain2P"],
                           capture_output=True, text=True, timeout=400)
        print(p.stdout.strip()[-900:])

        print("C2:"); consumer("C2")
        print("size after C2", sess_size())

        print("workers HWM/RSS after the chain:")
        for pid in pids:
            print("   pid=%s VmHWM=%s VmRSS=%s" % (pid, hwm(pid), rss(pid)))
        print("hold stderr:", (hold.stderr.read()[-200:] if hold.stderr else ""))
    finally:
        if hold is not None:
            hold.terminate()
            try:
                hold.wait(timeout=10)
            except subprocess.TimeoutExpired:
                hold.kill()
        time.sleep(1.5)
        print("post-release size", sess_size())
        for pid in ("",):
            pass


if __name__ == "__main__":
    main()
