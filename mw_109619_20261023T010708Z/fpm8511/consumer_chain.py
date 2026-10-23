#!/usr/bin/env python3
"""MW producer/consumer chain test.

Plan on the 2-worker 8.5.11 FPM (18750):
  H  : held 6 MB upload-progress request with PHPSESSID=S  -> occupies worker A,
       creates a non-empty /sessions/sess_S that stays alive while held.
  C1 : ~300 B upload-progress consumer with PHPSESSID=S     -> must be served by
       the idle worker B (A is busy); reads sess_S.
  P  : max-size login POST (8.39 MB)                        -> also worker B;
       this is the candidate MW post-RINIT unserialize bailout.
  C2 : same ~300 B consumer                                 -> worker B again.
  Then release H and check cleanup.

Receipts: which worker served what (from /fpm-status?full), response statuses,
worker PIDs, session file sizes, and worker last-request memory.
"""
import os, subprocess, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))
os.chdir(LAB)
os.environ["FPM_PORT"] = os.environ.get("FPM_PORT", "18750")
SID = "c1w111111111111111111111111111111"
SESS = os.path.join(LAB, "sessions", "sess_" + SID)
BOUND = "----mw109619boundary"

import fpmstat


def fcgi(args, timeout=400):
    return subprocess.run([sys.executable, "fcgi.py"] + args,
                          capture_output=True, text=True, timeout=timeout)


def status_line(tag):
    procs = fpmstat.status()
    print("[%s] workers:" % tag)
    for p in procs:
        print("   pid=%s state=%-8s reqs=%-4s mem=%-10s uri=%s" % (
            p.get("pid"), p.get("state"), p.get("requests"),
            p.get("last request memory"), p.get("request URI")))
    return procs


def worker_of(procs, uri_frag="/index.php"):
    """Worker whose last request was the given URI (i.e. served our request)."""
    hits = [p for p in procs if uri_frag in (p.get("request URI") or "")]
    return hits


def sess_size():
    try:
        return os.path.getsize(SESS)
    except OSError:
        return None


def consumer(tag):
    body = "b_cons1w.bin"
    out = "cons_%s.raw" % tag
    p = fcgi(["--method", "POST", "--uri", "/index.php",
              "--content-type", "multipart/form-data; boundary=" + BOUND,
              "--body", body, "--cookie", "PHPSESSID=" + SID,
              "--chunk-size", "65535", "--out", out])
    first = ""
    if os.path.exists(os.path.join(LAB, out)):
        raw = open(os.path.join(LAB, out), "rb").read()
        first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
    st = "?"
    for line in p.stderr.splitlines():
        if "app_status=" in line:
            st = line.strip()
    print("[%s] consumer status=%s body=%d first=%r" % (tag, st, os.path.getsize(os.path.join(LAB, out)) if os.path.exists(os.path.join(LAB, out)) else -1, first))
    return st


def main():
    hold = None
    try:
        print("SID", SID)
        # fresh session dir state
        print("pre  sess size", sess_size())

        # 1) held writer on worker A
        hold = subprocess.Popen(
            [sys.executable, "fcgi.py", "--method", "POST", "--uri", "/index.php",
             "--content-type", "multipart/form-data; boundary=" + BOUND,
             "--body", "b_hold6m1w.bin", "--cookie", "PHPSESSID=" + SID,
             "--truncate-after", "6000300", "--hold-seconds", "150",
             "--chunk-size", "65535", "--out", "hold_1w.raw"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2.0)
        print("held sess size", sess_size())
        procs = status_line("after H")

        st1 = consumer("C1")
        procs = status_line("after C1")
        print("sess size after C1", sess_size())

        print("--- producer P (max login) ---")
        p = subprocess.run([sys.executable, "sweep_login.py", "8387000", "1", "chainP"],
                           capture_output=True, text=True, timeout=400)
        print(p.stdout.strip()[-1200:])
        procs = status_line("after P")
        print("sess size after P", sess_size())

        st2 = consumer("C2")
        procs = status_line("after C2")
        print("sess size after C2", sess_size())
        print("CONSUMER statuses:", st1, st2)
    finally:
        if hold is not None:
            hold.terminate()
            try:
                hold.wait(timeout=10)
            except subprocess.TimeoutExpired:
                hold.kill()
        time.sleep(1.0)
        print("post-release sess size", sess_size())
        print("hold stderr tail:", (hold.stderr.read()[-300:] if hold and hold.stderr else ""))


if __name__ == "__main__":
    main()
