#!/bin/bash
# probe A: CLIENT-ABORT mid-upload (close socket during the stall => parser
# sees truncated body / connection drop). Check: workers alive, no segv, any
# leftover machinery state. Uses nginx->fpm on the REAL stack (unauth).
set -u
BASE=/tmp/opencode/realapps/side
python3 - <<'PY'
import socket, sys, time
sys.path.insert(0, "/tmp/opencode/realapps/side")
from staged_618 import build

for name, port, path, sid in [("MW", 28840, "/index.php", "abort-mw1"),
                              ("WP", 28841, "/index.php", "abort-wp1")]:
    p1, t = build(sid, b"id", 0)
    head = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary=B7kQpoc618\r\n"
            f"Content-Length: {len(p1)+len(t)}\r\n"
            f"Connection: close\r\n\r\n").encode()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(head + p1)
        time.sleep(0.8)
        s.close()  # abrupt disconnect DURING the stall (before tail)
    except Exception as e:
        print(f"{name}: connect/send error {type(e).__name__}")
    print(f"{name}: aborted mid-upload ({name == 'MW' and '28840' or port})")
time.sleep(2)
PY
echo "=== probe A done; fpm workers now: $(pgrep -c php-fpm) ==="
for sid in abort-mw1 abort-wp1; do
  for d in wiki wp; do
    f=/tmp/opencode/realapps/sessions/$d/sess_$sid
    [ -f "$f" ] && echo "leftover $f: $(stat -c%s "$f") bytes: $(head -c 120 "$f")"
  done
done