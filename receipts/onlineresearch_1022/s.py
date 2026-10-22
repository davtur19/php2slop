#!/usr/bin/env python3
import sys, os, re, json, time, hashlib, urllib.parse, subprocess

D = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(D, "raw")
os.makedirs(RAW, exist_ok=True)

def fetch(url, timeout=60):
    h = hashlib.sha1(url.encode()).hexdigest()[:16]
    p = os.path.join(RAW, h + ".txt")
    if os.path.exists(p) and os.path.getsize(p) > 200:
        return open(p, encoding="utf-8", errors="ignore").read()
    r = subprocess.run(["curl", "-s", "--max-time", str(timeout),
                        "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
                        url], capture_output=True, text=True)
    txt = r.stdout
    open(p, "w", encoding="utf-8").write(txt)
    return txt

def ddg(q, n=25):
    u = "https://r.jina.ai/https://html.duckduckgo.com/html/?q=" + urllib.parse.quote_plus(q)
    txt = fetch(u, 90)
    out = []
    for m in re.finditer(r'##\s*\[([^\]]+)\]\((https://duckduckgo\.com/l/\?uddg=[^\)]+)\)', txt):
        title, link = m.group(1), m.group(2)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
        real = qs.get("uddg", [""])[0]
        out.append((title.strip(), real))
    seen, res = set(), []
    for t, u2 in out:
        if u2 in seen: continue
        seen.add(u2); res.append((t, u2))
        if len(res) >= n: break
    return res, txt

if __name__ == "__main__":
    q = " ".join(sys.argv[1:])
    res, txt = ddg(q)
    print(f"QUERY: {q}")
    if not res:
        print("NO RESULTS PARSED; bytes=", len(txt))
        print(txt[:600])
    for i, (t, u) in enumerate(res, 1):
        print(f"[{i}] {t}\n    {u}")
