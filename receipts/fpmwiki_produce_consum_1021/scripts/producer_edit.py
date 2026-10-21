#!/usr/bin/env python3
"""Producer driver: anon edit POST (token scrape + wpSave) at variable body size.

Replicates the known 5.7MB receipt shape: bootstrap session cookie -> csrf token
scrape via api.php -> multipart POST to /index.php?title=Sandbox&action=submit
with wpTextbox1 = 'A'*n, wpEditToken, wpSave.

Usage: producer_edit.py <text_bytes> <label> <outdir>
"""
import http.client
import json
import re
import sys
from pathlib import Path

HOST, PORT = "127.0.0.1", 28840
HDR = {"Host": "127.0.0.1:28840", "User-Agent": "producer-run/1.0", "Connection": "close"}


def req(method, path, body=None, ctype=None, cookie=None, timeout=45):
    h = dict(HDR)
    if cookie:
        h["Cookie"] = cookie
    if ctype:
        h["Content-Type"] = ctype
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    setc = r.getheader("Set-Cookie")
    conn.close()
    return r.status, data, setc


def main():
    n = int(sys.argv[1])
    label = sys.argv[2]
    outdir = Path(sys.argv[3])
    outdir.mkdir(parents=True, exist_ok=True)

    # 1. bootstrap anon session cookie
    st, data, setc = req("GET", "/index.php?title=Main_Page")
    m = re.search(r"mwdb_session=([A-Za-z0-9]+)", setc or "")
    cookie = f"mwdb_session={m.group(1)}" if m else None
    print(f"[bootstrap] GET /index.php -> {st} cookie={'yes' if cookie else 'NO'}")

    # 2. csrf token scrape
    st, data, _ = req("GET", "/api.php?action=query&meta=tokens&format=json", cookie=cookie)
    tok = ""
    try:
        tok = json.loads(data)["query"]["tokens"]["csrftoken"]
    except Exception as e:
        print(f"[token] status={st} parse_fail={e} body[:200]={data[:200]!r}")
    print(f"[token] status={st} token={tok!r}")

    # 3. multipart edit POST, wpTextbox1 = 'A'*n
    b = b"----PRODBOUND123"
    parts = []
    fields = {
        "wpTextbox1": b"A" * n,
        "wpEditToken": tok.encode(),
        "wpSummary": b"producer",
        "wpSave": b"Save page",
        "wpStarttime": b"20261021000000",
        "wpEdittime": b"20261021000000",
        "title": b"Sandbox",
    }
    for name, val in fields.items():
        parts.append(
            b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name.encode()
            + b"\"\r\n\r\n" + val + b"\r\n"
        )
    parts.append(b"--" + b + b"--\r\n")
    body = b"".join(parts)
    (outdir / f"{label}-request.bin").write_bytes(body)
    try:
        st, data, _ = req(
            "POST", "/index.php?title=Sandbox&action=submit", body=body,
            ctype=f"multipart/form-data; boundary={b.decode()}", cookie=cookie, timeout=45,
        )
        print(f"[edit] status={st} body_bytes={len(data)}")
        (outdir / f"{label}-response.bin").write_bytes(data)
        # marker scan
        for marker in (b"Allowed memory", b"content-too-big", b"errorbox", b"Fatal error"):
            if marker in data:
                i = data.find(marker)
                print(f"[edit] marker {marker!r} @ {i}: {data[max(0,i-80):i+120]!r}")
    except Exception as e:
        print(f"[edit] EXC {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
