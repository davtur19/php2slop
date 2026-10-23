#!/usr/bin/env python3
"""8.3.35 fresh-worker username-size sweep.

For each size: restart the single-worker 8.3.35 FPM, truncate the PHP error log,
run one GET+POST login, then classify the OOM site(s) and worker survival.
"""
import json, os, signal, socket, subprocess, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))
os.chdir(LAB)
os.environ["FPM_PORT"] = "18853"
PORT = 18853
BIN = "/tmp/opencode/research/plain_full_8x_20261023T011800Z/bin/8.3.35/php-fpm"
PIDF = os.path.join(LAB, "fpm8335.pid")
ERR = os.path.join(LAB, "fpm8335-php-error.log")
ACC = os.path.join(LAB, "fpm8335-access.log")
OUT = os.path.join(LAB, "fpm8335.out")

import sweep_login


def port_open():
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", PORT))
        return True
    except OSError:
        return False


def stop_master():
    try:
        pid = int(open(PIDF).read().strip())
    except (OSError, ValueError):
        pid = None
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(60):
            time.sleep(0.1)
            if not os.path.exists("/proc/%d" % pid):
                break
        if os.path.exists("/proc/%d" % pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            time.sleep(0.2)
    for _ in range(30):
        if not port_open():
            return
        time.sleep(0.1)


def start_master():
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/tmp/opencode/realapps/icu-out/lib"
    log = open(OUT, "ab")
    subprocess.Popen([BIN, "-F", "-y", "fpm8335.conf"], env=env,
                     stdout=log, stderr=subprocess.STDOUT, cwd=LAB,
                     start_new_session=True)
    for _ in range(100):
        time.sleep(0.1)
        if port_open():
            time.sleep(0.2)
            return
    raise RuntimeError("fpm did not start")


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


def main():
    sizes = [int(x) for x in sys.argv[1:]] or [8200000, 8250000, 8300000, 8350000, 8380000]
    stop_master()
    results = []
    for n in sizes:
        tag = "s8335_%d" % n
        start_master()
        open(ERR, "w").close()
        mark = acc_mark()
        try:
            res = sweep_login.attempt(n, 1, tag)
        except Exception as e:  # noqa: BLE001
            res = {"error": repr(e)}
        time.sleep(0.3)
        sites = oom_sites()
        lines = acc_new(mark)
        post = [l for l in lines if 'POST /index.php?title=Special:UserLogin' in l]
        worker = (res.get("after") or [None])[0]
        alive = bool(worker) and os.path.exists("/proc/%s" % worker)
        http = None
        if post:
            try:
                http = post[-1].split('"')[2].split()[0]
            except IndexError:
                pass
        rec = {"namelen": n, "body": res.get("body"), "status": res.get("status"),
               "http": http, "len": res.get("len"), "secs": res.get("secs"),
               "before": res.get("before"), "after": res.get("after"),
               "worker_alive": alive, "oom": sites[:4], "post_line": post[-1:] or [],
               "session_keys": [k.decode("latin1", "replace") if isinstance(k, bytes) else k
                                for k in ((res.get("session") or {}).get("keys") or [])]}
        results.append(rec)
        with open(os.path.join(LAB, "sweep8335_results.json"), "w") as f:
            json.dump(results, f, indent=1)
        print(json.dumps(rec, indent=1))
        # free the 8 MB response body immediately
        try:
            os.unlink(os.path.join(LAB, "probe_tmp", "sweep_%s.raw.body" % tag))
        except OSError:
            pass
    stop_master()
    with open(os.path.join(LAB, "sweep8335_results.json"), "w") as f:
        json.dump(results, f, indent=1)
    print("=== summary ===")
    def fmt(s):
        try:
            path, line = s.split(" in ")[-1].split(" on line ")
            return path.split("/")[-1] + ":" + line
        except ValueError:
            return s
    for r in results:
        site = "; ".join(fmt(s) for s in (r.get("oom") or []))
        print("%9d http=%s len=%s alive=%s worker=%s %s" % (
            r["namelen"], r.get("http"), r.get("len"), r.get("worker_alive"),
            r.get("after"), site or "no-oom"))


if __name__ == "__main__":
    main()
