#!/usr/bin/env python3
"""Calibration probe: restart target, warmup GET, send one body, dump PS state of the child that served it."""
import argparse, json, os, re, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo"

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def send_chunked(port, path, body_file, timeout=180, save=""):
    cmd = [sys.executable, os.path.join(REPO, "pure", "chunked_send.py"), "--port", str(port),
           "--body-file", body_file, "--path", path, "--timeout", str(timeout)]
    if save: cmd += ["--save-response", save]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout.strip()
    m = re.search(r"resp=(\d+) status='([^']*)'", out)
    return (int(m.group(1)), m.group(2)) if m else (-1, out)

def reset_log(container):
    sh(f"docker exec -u root {container} sh -c ': > /var/log/apache2/p2s-access.log'")

def last_pid(container):
    r = sh(f"docker exec -u root {container} cat /var/log/apache2/p2s-access.log")
    pids = [ln.split()[0] for ln in r.stdout.strip().splitlines() if ln.strip()]
    return pids[-1] if pids else None

def dump(container, pid):
    r = sh(f"docker exec -u root {container} gdb -q -p {pid} -batch -x /tmp/dump_state.gdb")
    out = r.stdout + r.stderr
    st = {}
    m = re.search(r"STATE .*", out)
    if m:
        for k, v in re.findall(r"(\w+)=(\S+)", m.group(0)):
            st[k] = v
    m = re.search(r"IDLEN (\S+)", out)
    if m: st["idlen"] = m.group(1)
    m = re.search(r"IDMEM (\S+)", out)
    if m: st["idmem"] = m.group(1)
    if not st: st["raw"] = out[-2000:]
    return st

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--gen", default="", help="shell command to generate body into $OUT")
    ap.add_argument("--body", default="", help="existing body file")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--no-restart", action="store_true")
    ap.add_argument("--json", default="")
    ap.add_argument("--gdb", default="dump_state.gdb")
    args = ap.parse_args()
    W = os.environ.get("W", "/tmp/opencode/research/modphp_109619_20261023T010232Z")
    body = args.body or os.path.join(W, "work", "probe_a1.bin")
    if args.gen:
        r = sh(args.gen.replace("$OUT", body))
        if r.returncode: print("GEN FAILED", r.stdout, r.stderr); return 2
    if not args.no_restart:
        sh(f"docker restart {args.container}")
        time.sleep(1.2)
        try:
            s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
            s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n"); s.recv(1024); s.close()
        except OSError: pass
    sh(f"docker exec -i -u root {args.container} sh -c 'cat > /tmp/dump_state.gdb' < {HERE}/{args.gdb}")
    reset_log(args.container)
    n, status = send_chunked(args.port, args.path, body)
    time.sleep(0.15)
    pid = last_pid(args.container)
    st = dump(args.container, pid) if pid else {"error": "no pid"}
    res = {"body_bytes": os.path.getsize(body), "resp_bytes": n, "status": status, "pid": pid, **st}
    print(json.dumps(res, sort_keys=True))
    if args.json:
        open(args.json, "a").write(json.dumps(res, sort_keys=True) + "\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
