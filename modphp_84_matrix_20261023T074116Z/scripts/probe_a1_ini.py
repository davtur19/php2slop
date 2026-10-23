#!/usr/bin/env python3
"""A1 probe with the stock php.ini-production of each build (resumable)."""
import json, os, subprocess, sys, time, urllib.request

D = "/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
PURE = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure"
VERSIONS = ["8.4.%d" % v for v in ([1, 2, 3, 4, 5, 6, 7, 8] + list(range(10, 28)))]
ONLY = os.environ.get("ONLY", "")
if ONLY:
    VERSIONS = ONLY.split(",")
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def sh(cmd, timeout=600):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)


def main():
    out = os.path.join(D, "receipts", "a1_probe_ini.json")
    data = json.load(open(out)) if os.path.exists(out) else {}
    for v in VERSIONS:
        if v in data and data[v].get("status"):
            continue
        img = "php:%s-apache" % v
        if sh(["docker", "image", "inspect", img]).returncode != 0:
            if sh(["docker", "pull", img], timeout=600).returncode != 0:
                data[v] = {"error": "pull_failed"}
                json.dump(data, open(out, "w"), indent=1)
                continue
        ctr = "m84p-%s" % v
        ini = os.path.join(D, "lab", "php.ini-production-%s" % v)
        if not os.path.exists(ini):
            sh(["docker", "rm", "-f", ctr])
            sh(["docker", "create", "--name", ctr, img])
            sh(["docker", "cp", ctr + ":/usr/local/etc/php/php.ini-production", ini])
            sh(["docker", "rm", "-f", ctr])
        port = 18900 + int(v.split(".")[-1])
        sh(["docker", "rm", "-f", ctr])
        sh(["docker", "run", "-d", "--name", ctr, "-p", "127.0.0.1:%d:80" % port,
            "-v", os.path.join(D, "lab/conf/000-default.conf") + ":/etc/apache2/sites-enabled/000-default.conf",
            "-v", os.path.join(D, "lab/www") + ":/var/www/html:ro",
            "-v", ini + ":/usr/local/etc/php/php.ini:ro",
            img])
        ok = False
        for _ in range(120):
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=2) as f:
                    ok = f.status == 200
                    break
            except Exception:
                time.sleep(0.5)
        row = {"image_id": sh(["docker", "image", "inspect", img, "--format", "{{.Id}}"]).stdout.strip(),
               "ini_sha256": sh(["sha256sum", ini]).stdout.split()[0] if os.path.exists(ini) else ""}
        row["php"] = sh(["docker", "exec", ctr, "php", "-v"]).stdout.splitlines()[:1]
        if not ok:
            row["error"] = "not_ready"
        else:
            for label, parts, big in (("860", 860, 78), ("920", 920, 78), ("840", 840, 78)):
                ap = os.path.join(D, "bodies", "a1-p%d.bin" % parts)
                if not os.path.exists(ap):
                    sh([sys.executable, os.path.join(PURE, "mk_a1.py"), "--out", ap,
                        "--parts", str(parts), "--big", str(big)])
                save = os.path.join(D, "out", "probe_ini_%s_%s.resp" % (v, label))
                t0 = time.time()
                sh([sys.executable, os.path.join(PURE, "chunked_send.py"), "--port", str(port),
                    "--body-file", ap, "--path", "/index.php" + Q,
                    "--timeout", "300", "--save-response", save])
                el = round(time.time() - t0, 2)
                b = open(save, "rb").read() if os.path.exists(save) else b""
                row["status_p" + label] = b.split(b"\r\n", 1)[0].decode("latin1", "replace") if b else "no-response"
                row["bytes_p" + label] = len(b)
                row["elapsed_p" + label] = el
        sh(["docker", "rm", "-f", ctr])
        sh(["docker", "rmi", img])
        data[v] = row
        json.dump(data, open(out, "w"), indent=1)
        print(v, row.get("status_p860"), row.get("bytes_p860"), row.get("elapsed_p860"),
              "| 920", row.get("status_p920"), row.get("bytes_p920"), flush=True)


if __name__ == "__main__":
    main()
