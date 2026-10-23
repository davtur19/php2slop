#!/usr/bin/env python3
"""8.3.35 fresh-worker username-size sweep, v2 (Popen-owned master restart).

Each size runs on a brand-new single-worker 8.3.35 FPM. The PHP error log is
truncated first, so the OOM site list belongs to this size only.
"""
import json, os, signal, socket, subprocess, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))
os.chdir(LAB)
PORT = 18853
os.environ["FPM_PORT"] = str(PORT)
BIN = "/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.3.35/php-fpm"
ERR = os.path.join(LAB, "fpm8335-php-error.log")
ACC = os.path.join(LAB, "fpm8335-access.log")
OUT = os.path.join(LAB, "fpm8335.out")

import sweep_login


def port_open(timeout=0.3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", PORT))
        return True
    except OSError:
        return False
    finally:
        s.close()


def start_master():
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/tmp/opencode/realapps/icu-out/lib"
    p = subprocess.Popen([BIN, "-F", "-y", "fpm8335.conf"], env=env,
                         stdout=open(OUT, "ab"), stderr=subprocess.STDOUT,
                         cwd=LAB, start_new_session=True)
    for _ in range(100):
        time.sleep(0.1)
        if port_open():
            time.sleep(0.3)
            return p
    raise RuntimeError("fpm did not start")


def stop_master(p):
    if p is None:
        return
    try:
        p.terminate()
    except ProcessLookupError:
        pass
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    for _ in range(80):
        if not port_open():
            return
        time.sleep(0.1)


def acc_mark():
    try:
        return os.path.getsize(ACC)
    except OSError:
        return 0


def acc_new(mark):
    try:
        with open(ACC, "rb") as f:
            f.seek(mark)
            return f.read().decode("latin1", "replace").splitlines()
    except OSError:
        return []


def oom_sites():
    try:
        txt = open(ERR, encoding="latin1", errors="replace").read()
    except OSError:
        return []
    return [l.strip() for l in txt.splitlines() if "Allowed memory size" in l]


def run_one(n, tag):
    p = start_master()
    rec = {"namelen": n}
    try:
        open(ERR, "w").close()
        mark = acc_mark()
        res = sweep_login.attempt(n, 1, tag)
        time.sleep(0.3)
        sites = oom_sites()
        lines = acc_new(mark)
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
        rec.update({"body": res.get("body"), "http": http, "peak_kb": peak,
                    "fcgi_status": res.get("status"), "len": res.get("len"),
                    "secs": res.get("secs"), "before": res.get("before"),
                    "after": res.get("after"),
                    "worker_alive": bool(worker) and os.path.exists("/proc/%s" % worker),
                    "oom": sites, "post_line": post[-1:] or [],
                    "session_keys": [k.decode("latin1", "replace") if isinstance(k, bytes) else k
                                     for k in ((res.get("session") or {}).get("keys") or [])]})
    except Exception as e:  # noqa: BLE001
        rec["error"] = repr(e)
    finally:
        stop_master(p)
    try:
        os.unlink(os.path.join(LAB, "probe_tmp", "sweep_%s.raw.body" % tag))
    except OSError:
        pass
    return rec


def bisect(lo, hi):
    probes = {}
    r = run_one(lo, "bis_lo")
    probes[lo] = r
    print(json.dumps(r), flush=True)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        r = run_one(mid, "bis_%d" % mid)
        probes[mid] = r
        print("probe %d http=%s peak=%s oom=%s" % (
            mid, r.get("http"), r.get("peak_kb"),
            [s.split(" in ")[-1] for s in (r.get("oom") or [])]), flush=True)
        if r.get("oom"):
            hi = mid
        else:
            lo = mid
    for n in (lo, hi):
        if n not in probes:
            probes[n] = run_one(n, "bis_%d" % n)
            print(json.dumps(probes[n]), flush=True)
    with open(os.path.join(LAB, "bisect8335_results.json"), "w") as f:
        json.dump({str(k): v for k, v in sorted(probes.items())}, f, indent=1)
    print("=== boundary ===")
    for n in sorted(probes):
        r = probes[n]
        print("%d http=%s peakKB=%s oom=%s" % (
            n, r.get("http"), r.get("peak_kb"),
            "; ".join(s.split(" in ")[-1] for s in (r.get("oom") or [])) or "no-oom"))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "bisect":
        bisect(int(sys.argv[2]), int(sys.argv[3]))
        return
    sizes = [int(x) for x in sys.argv[1:]] or [8000000]
    results = []
    for n in sizes:
        rec = run_one(n, "s2_8335_%d" % n)
        results.append(rec)
        with open(os.path.join(LAB, "sweep8335b_results.json"), "w") as f:
            json.dump(results, f, indent=1)
        print(json.dumps(rec, indent=1), flush=True)
    print("=== summary ===")
    def fmt(s):
        try:
            path, line = s.split(" in ")[-1].split(" on line ")
            return path.split("/")[-1] + ":" + line
        except ValueError:
            return s
    for r in results:
        print("%9d http=%s peakKB=%s alive=%s worker=%s %s" % (
            r["namelen"], r.get("http"), r.get("peak_kb"), r.get("worker_alive"),
            r.get("after"), "; ".join(fmt(s) for s in (r.get("oom") or [])) or "no-oom"))


if __name__ == "__main__":
    main()
