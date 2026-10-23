#!/usr/bin/env python3
"""Probe the stock A1 body on every 8.4.x official image (cheap, resumable)."""
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
    out = os.path.join(D, "receipts", "a1_probe_all.json")
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
        sh(["docker", "rm", "-f", ctr])
        sh(["docker", "run", "-d", "--name", ctr, "-p", "127.0.0.1:%d:80" % (18900 + int(v.split(".")[-1])),
            "-v", os.path.join(D, "lab/conf/000-default.conf") + ":/etc/apache2/sites-enabled/000-default.conf",
            "-v", os.path.join(D, "lab/www") + ":/var/www/html:ro",
            img])
        port = 18900 + int(v.split(".")[-1])
        ok = False
        for _ in range(120):
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=2) as f:
                    ok = f.status == 200
                    break
            except Exception:
                time.sleep(0.5)
        row = {"image_id": sh(["docker", "image", "inspect", img, "--format", "{{.Id}}"]).stdout.strip()}
        row["php"] = sh(["docker", "exec", ctr, "php", "-v"]).stdout.splitlines()[:1]
        if not ok:
            row["error"] = "not_ready"
        else:
            save = os.path.join(D, "out", "probe_a1_%s.resp" % v)
            os.makedirs(os.path.join(D, "out"), exist_ok=True)
            sh([sys.executable, os.path.join(PURE, "chunked_send.py"), "--port", str(port),
                "--body-file", os.path.join(D, "bodies/a1.bin"), "--path", "/index.php" + Q,
                "--timeout", "300", "--save-response", save])
            b = open(save, "rb").read() if os.path.exists(save) else b""
            row["status"] = b.split(b"\r\n", 1)[0].decode("latin1", "replace") if b else "no-response"
            row["bytes"] = len(b)
            row["body_tail"] = b[-220:].decode("latin1", "replace")
            # second probe at higher parts (920) to see the parse boundary
            ap = os.path.join(D, "bodies", "a1-p920.bin")
            if not os.path.exists(ap):
                sh([sys.executable, os.path.join(PURE, "mk_a1.py"), "--out", ap,
                    "--parts", "920", "--big", "78"])
            save2 = os.path.join(D, "out", "probe_a1p920_%s.resp" % v)
            sh([sys.executable, os.path.join(PURE, "chunked_send.py"), "--port", str(port),
                "--body-file", ap, "--path", "/index.php" + Q,
                "--timeout", "300", "--save-response", save2])
            b2 = open(save2, "rb").read() if os.path.exists(save2) else b""
            row["status_p920"] = b2.split(b"\r\n", 1)[0].decode("latin1", "replace") if b2 else "no-response"
            row["bytes_p920"] = len(b2)
        sh(["docker", "rm", "-f", ctr])
        sh(["docker", "rmi", img])
        data[v] = row
        json.dump(data, open(out, "w"), indent=1)
        print(v, row.get("status"), row.get("bytes"), row.get("status_p920"), row.get("bytes_p920"), flush=True)


if __name__ == "__main__":
    main()
