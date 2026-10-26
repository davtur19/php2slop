#!/usr/bin/env python3
"""Verify a receipts tree: every hash, every proof, every leak fingerprint."""
import hashlib
import json
import lzma
import os
import re
import struct
import sys
import urllib.parse
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAIL = []
CHECKED = [0]


def ok(msg):
    CHECKED[0] += 1


def bad(msg):
    FAIL.append(msg)
    print("FAIL:", msg)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def check_sums():
    p = os.path.join(ROOT, "sha256sums.txt")
    for line in open(p):
        want, rel = line.rstrip("\n").split("  ", 1)
        got = sha256_file(os.path.join(ROOT, rel))
        if got != want:
            bad("sha256 mismatch: %s" % rel)
        else:
            ok(rel)


def parse_leak(resp, zdtor_off):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.replace(b"+", b"%20").decode("latin1"))
    counts = Counter()
    for off in range(0, len(dec) - 7, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7C0000000000 <= q <= 0x800000000000:
            counts[q] += 1
    if not counts:
        return {"decoded": len(dec), "hits": 0}
    zdtor, n = counts.most_common(1)[0]
    return {"decoded": len(dec), "hits": n, "zdtor": zdtor}


def read_resp(path):
    if path.endswith(".xz"):
        return lzma.decompress(open(path, "rb").read())
    return open(path, "rb").read()


def check_early():
    for name in sorted(os.listdir(ROOT)):
        if not re.match(r"php-8\.4\.[1-7]$", name):
            continue
        d = os.path.join(ROOT, name)
        pdir = os.path.join(d, "proofs")
        proofs = sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []
        if not proofs:
            bad("%s: no proofs" % name)
        for f in proofs:
            data = open(os.path.join(pdir, f), "rb").read()
            if b"uid=33(www-data) gid=33(www-data) groups=33(www-data)" not in data:
                bad("%s: proof %s lacks uid line" % (name, f))
            if f.encode() not in data:
                bad("%s: proof %s lacks its tag" % (name, f))
            ok("proof " + f)
        po = os.path.join(d, "evidence", "proof-origin.json")
        if os.path.exists(po):
            for p in json.load(open(po))["proofs"]:
                fp = os.path.join(pdir, p["tag"])
                if not os.path.exists(fp):
                    bad("%s: origin proof %s missing" % (name, p["tag"]))
                elif sha256_file(fp) != p["sha256"] or os.path.getsize(fp) != p["bytes"]:
                    bad("%s: origin metadata mismatch for %s" % (name, p["tag"]))
                else:
                    ok("%s origin %s" % (name, p["tag"]))
        for label in ("B", "C"):
            p = os.path.join(d, "evidence", "result-%s.json" % label)
            if not os.path.exists(p):
                bad("%s: missing %s" % (name, p))
                continue
            res = json.load(open(p))
            key = name.replace("php-", "").replace(".", "")
            ptag = "PR%s%s" % (key, label)
            pp = os.path.join(pdir, ptag)
            if not os.path.exists(pp):
                bad("%s: missing proof %s" % (name, ptag))
            elif open(pp, "rb").read().decode() != res.get("proof", res.get("proof_text")):
                bad("%s: %s text != driver-recorded proof_text" % (name, ptag))
            else:
                ok("%s %s provenance text" % (name, ptag))
            for s in res["stages"]:
                if s["stage"] != "B1" or "leak" not in s:
                    continue
                rp = os.path.join(d, "evidence", "responses", "%s-b1_0.resp.xz" % label)
                r = parse_leak(read_resp(rp), 0)
                if r["decoded"] != s["leak"]["decoded"] or r["hits"] != s["leak"]["zdtor_hits"]:
                    bad("%s %s: leak fingerprint %s != %s" % (name, label, r, s["leak"]))
                else:
                    ok("%s %s leak %d/%d" % (name, label, r["decoded"], r["hits"]))
            for s in res["stages"]:
                if s["stage"] == "B1":
                    continue
                letter = {"A1": "a1", "A2": "a2", "B2": "b2_0"}[s["stage"]]
                rp = os.path.join(d, "evidence", "responses", "%s-%s.resp" % (label, letter))
                if os.path.exists(rp) and os.path.getsize(rp) != s["bytes"]:
                    bad("%s %s %s: %d != %d" % (name, label, s["stage"],
                                                os.path.getsize(rp), s["bytes"]))
                else:
                    ok("%s %s %s" % (name, label, s["stage"]))


def check_copied():
    for name in sorted(os.listdir(ROOT)):
        m = re.match(r"php-8\.4\.(1[0-9]|2[0-6])$", name)
        if not m:
            continue
        d = os.path.join(ROOT, name)
        fin = json.load(open(os.path.join(d, "evidence", "final.json")))
        pf = [f for f in os.listdir(os.path.join(d, "proofs"))]
        if len(pf) != 1:
            bad("%s: expected one proof" % name)
            continue
        want_marker = pf[0].split("p1_conc_")[-1]
        chains = [c for c in (fin.get("chain"), fin.get("chain2"))
                  if c and c.get("marker") == want_marker and c.get("proof")]
        if len(chains) != 1:
            bad("%s: no unique chain record for marker %s" % (name, want_marker))
            continue
        txt = chains[0]["proof"]
        marker = chains[0]["marker"]
        data = open(os.path.join(d, "proofs", pf[0]), "rb").read().decode()
        if data != txt:
            bad("%s: proof text != final.json chain.proof" % name)
        elif marker not in data:
            bad("%s: marker missing" % name)
        else:
            ok("proof " + pf[0])


def main():
    check_sums()
    check_early()
    check_copied()
    print("checks: %d, failures: %d" % (CHECKED[0], len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
