#!/usr/bin/env python3
"""Minimal HTTP/1.1 keep-alive client with chunked POST bodies; pins a chain to one prefork child."""
import socket, re, sys, time

class Conn:
    def __init__(self, host, port, timeout=300):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout); self.buf = b""
    def request(self, method, path, body=None, chunked=False, extra=None, ctype=None):
        hdr = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, self.host if hasattr(self,'host') else "x")
        hdr = "%s %s HTTP/1.1\r\nHost: h\r\n" % (method, path)
        if ctype: hdr += "Content-Type: %s\r\n" % ctype
        if body is not None:
            if chunked:
                hdr += "Transfer-Encoding: chunked\r\n"
            else:
                hdr += "Content-Length: %d\r\n" % len(body)
        if extra:
            for k, v in extra.items(): hdr += "%s: %s\r\n" % (k, v)
        hdr += "\r\n"
        out = bytearray(hdr.encode())
        if body is not None:
            if chunked:
                for i in range(0, len(body), 65536):
                    piece = body[i:i+65536]
                    out += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
                out += b"0\r\n\r\n"
            else:
                out += body
        self.s.sendall(out)
        return self.read_response()
    def read_response(self, maxbody=8<<20):
        # headers
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(65536)
            if not d: return {"closed": True, "raw": bytes(self.buf)}
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = lines[0].decode("latin1")
        h = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                h[k.strip().lower().decode()] = v.strip().decode("latin1")
        body = b""
        if "content-length" in h:
            n = int(h["content-length"])
            while len(self.buf) < n:
                d = self.s.recv(65536)
                if not d: break
                self.buf += d
            body, self.buf = self.buf[:n], self.buf[n:]
        elif h.get("transfer-encoding","").lower() == "chunked":
            while True:
                while b"\r\n" not in self.buf:
                    d = self.s.recv(65536)
                    if not d: break
                    self.buf += d
                ln, self.buf = self.buf.split(b"\r\n", 1)
                n = int(ln.split(b";")[0], 16)
                if n == 0:
                    while not self.buf.startswith(b"\r\n"):
                        d = self.s.recv(65536)
                        if not d: break
                        self.buf += d
                    self.buf = self.buf[2:] if self.buf.startswith(b"\r\n") else self.buf
                    break
                while len(self.buf) < n+2:
                    d = self.s.recv(65536)
                    if not d: break
                    self.buf += d
                body += self.buf[:n]; self.buf = self.buf[n+2:]
        closed = h.get("connection","").lower() == "close"
        return {"status": status, "headers": h, "body": body, "closed": closed}
    def close(self):
        try: self.s.close()
        except Exception: pass

if __name__ == "__main__":
    c = Conn("127.0.0.1", int(sys.argv[1]))
    r = c.request("GET", "/index.php")
    print(r["status"], len(r["body"]), "closed", r["closed"])
    c.close()
