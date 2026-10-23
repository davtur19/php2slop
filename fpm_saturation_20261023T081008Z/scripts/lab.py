#!/usr/bin/env python3
"""FPM saturation lab client.

Subcommands:
  single  : one raw HTTP request, print code/bytes/seconds
  burst   : N truly-parallel requests (all sockets opened first), optional mix
  slow    : N concurrent slow-header / slow-body / chunked / huge-CL connections
  status  : poll an FPM status URL forever, append JSONL
  probe   : poll a fast endpoint forever, append latency JSONL
"""
import argparse, asyncio, json, os, signal, socket, sys, threading, time
from urllib.request import urlopen

HOST = "127.0.0.1"

# ---------- helpers ----------
def parse_code(data: bytes) -> int:
    if not data:
        return 0
    try:
        line = data.split(b"\r\n", 1)[0].decode("latin1")
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return int(parts[1])
    except Exception:
        pass
    return 0

async def read_all(reader, timeout):
    out = bytearray()
    try:
        while True:
            b = await asyncio.wait_for(reader.read(65536), timeout)
            if not b:
                break
            out += b
            if len(out) > 4 << 20:  # cap response capture
                break
    except (asyncio.TimeoutError, ConnectionResetError, OSError, asyncio.IncompleteReadError):
        pass
    return bytes(out)

def build_headers(host, port, path, body, extra, method="POST", chunked=False):
    h = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n"
    for k, v in (extra or {}).items():
        h += f"{k}: {v}\r\n"
    if chunked:
        h += 'Content-Type: multipart/form-data; boundary=CCCCCCCCCC\r\nTransfer-Encoding: chunked\r\n'
    elif body is not None:
        h += f"Content-Length: {len(body)}\r\n"
    h += "\r\n"
    return h.encode()

async def send_request(reader, writer, host, port, path, body, extra=None,
                       timeout=180, method="POST", rate=0, send_delay=0.0):
    """Send request on an already-open connection and read response.
    rate>0 -> trickle body bytes/sec. send_delay: wait before sending anything."""
    rec = {"t0": time.time(), "sent": 0}
    if send_delay:
        await asyncio.sleep(send_delay)
    hdr = build_headers(host, port, path, body, extra, method=method)
    rtask = None
    try:
        writer.write(hdr)
        await writer.drain()
        rtask = asyncio.create_task(read_all(reader, timeout))
        if body is not None:
            mv = memoryview(body)
            n = len(mv)
            off = 0
            if rate and rate > 0:
                chunk = max(256, int(rate * 0.1))
                interval = chunk / rate
                while off < n:
                    try:
                        writer.write(mv[off:off + chunk]); off += chunk
                        await writer.drain()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break
                    await asyncio.sleep(interval)
            else:
                CH = 65536
                while off < n:
                    try:
                        writer.write(mv[off:off + CH]); off += CH
                        await writer.drain()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break
            rec["sent"] = off
        data = await rtask
    except Exception as e:
        rec["error"] = type(e).__name__
        data = b""
        if rtask:
            try:
                data = await rtask
            except Exception:
                data = b""
    finally:
        try:
            writer.close()
        except Exception:
            pass
    rec["code"] = parse_code(data)
    rec["resp_bytes"] = len(data)
    rec["dt"] = round(time.time() - rec["t0"], 4)
    rec["head"] = data[:64].decode("latin1", "replace")
    body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
    rec["body"] = body[:512].decode("latin1", "replace")
    return rec

# ---------- single ----------
async def cmd_single(a):
    body = open(a.file, "rb").read() if a.file else None
    reader, writer = await asyncio.open_connection(HOST, a.port)
    extra = {"Content-Type": "multipart/form-data; boundary=CCCCCCCCCC"} if body is not None else {}
    r = await send_request(reader, writer, HOST, a.port, a.path, body, extra, a.timeout)
    print(json.dumps(r))
    if a.out:
        open(a.out, "a").write(json.dumps(r) + "\n")

# ---------- burst ----------
async def cmd_burst(a):
    # manifest: list of (path, file or None)
    items = []
    if a.mix:
        for spec in a.mix.split(","):
            name, cnt = spec.split(":")
            cnt = int(cnt)
            f = None if name == "none" else os.path.join(a.bodies, name + ".bin")
            items += [(a.path, f)] * cnt
    elif a.manifest:
        for line in open(a.manifest):
            line = line.strip()
            if not line:
                continue
            p, f = line.split(",", 1)
            items.append((p, f if f and f != "-" else None))
    if a.n and len(items) > a.n:
        items = items[:a.n]
    n = len(items)
    bcache = {}
    for _, f in items:
        if f and f not in bcache:
            bcache[f] = open(f, "rb").read()

    sem = asyncio.Semaphore(a.connect_parallel) if a.connect_parallel else None
    conns = [None] * n

    async def connect_one(i):
        if sem:
            async with sem:
                try:
                    return await asyncio.wait_for(asyncio.open_connection(HOST, a.port), a.timeout)
                except Exception as e:
                    return e
        try:
            return await asyncio.wait_for(asyncio.open_connection(HOST, a.port), a.timeout)
        except Exception as e:
            return e

    res = await asyncio.gather(*[connect_one(i) for i in range(n)])
    good = []
    failed = []
    for i, r in enumerate(res):
        if isinstance(r, Exception):
            failed.append({"i": i, "connect_error": type(r).__name__})
        else:
            conns[i] = r
            good.append(i)
    # fire all sends in one loop turn
    t_fire = time.time()
    tasks = []
    for i in good:
        reader, writer = conns[i]
        path, f = items[i]
        body = bcache[f] if f else None
        extra = {"Content-Type": "multipart/form-data; boundary=CCCCCCCCCC"} if body is not None else {}
        if a.cookie:
            name, val = a.cookie.split("=", 1)
            if "{i}" in val:
                val = val.replace("{i}", str(i))
            extra["Cookie"] = f"{name}={val}"
        elif a.cookie_name:
            extra["Cookie"] = f"{a.cookie_name}=s{i:032d}"
        tasks.append(send_request(reader, writer, HOST, a.port, path, body, extra, a.timeout))
    results = await asyncio.gather(*tasks)
    out = []
    for i, r in zip(good, results):
        r["i"] = i
        r["file"] = os.path.basename(items[i][1]) if items[i][1] else None
        r["rel"] = round(r["t0"] - t_fire, 4)
        out.append(r)
    out += failed
    out.sort(key=lambda x: x.get("i", 0))
    if a.out:
        with open(a.out, "w") as fh:
            for r in out:
                fh.write(json.dumps(r) + "\n")
    codes = {}
    for r in out:
        codes[str(r.get("code"))] = codes.get(str(r.get("code")), 0) + 1
    dts = sorted(r["dt"] for r in out if "dt" in r)
    def pct(p):
        return dts[min(len(dts) - 1, int(len(dts) * p))] if dts else None
    summary = {"n": n, "connected": len(good), "codes": codes,
               "dt_p50": pct(0.5), "dt_p95": pct(0.95), "dt_max": dts[-1] if dts else None,
               "fire_epoch": t_fire}
    print(json.dumps(summary))
    if a.summary:
        open(a.summary, "w").write(json.dumps(summary, indent=2) + "\n")

# ---------- slow ----------
async def slow_one(idx, a, barrier):
    rec = {"i": idx, "t0": time.time(), "sent": 0, "code": 0}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(HOST, a.port), 15)
    except Exception as e:
        rec["error"] = "connect:" + type(e).__name__
        return rec
    try:
        if a.mode == "header":
            writer.write((f"POST {a.path} HTTP/1.1\r\nHost: {HOST}:{a.port}\r\n"
                          f"Content-Type: multipart/form-data; boundary=CCCCCCCCCC\r\n"
                          f"Content-Length: 1000\r\nX-Pad: ").encode())
            await writer.drain()
            await barrier.wait()
            t_end = time.time() + a.hold
            while time.time() < t_end:
                try:
                    writer.write(b"a"); await writer.drain(); rec["sent"] += 1
                except (BrokenPipeError, ConnectionResetError, OSError):
                    rec["error"] = "write_closed"; break
                await asyncio.sleep(a.interval)
        else:
            if a.mode == "chunked":
                hdr = build_headers(HOST, a.port, a.path, None, None, chunked=True)
            else:
                cl = a.cl
                hdr = (f"POST {a.path} HTTP/1.1\r\nHost: {HOST}:{a.port}\r\n"
                       f"Content-Type: multipart/form-data; boundary=CCCCCCCCCC\r\n"
                       f"Content-Length: {cl}\r\nConnection: close\r\n\r\n").encode()
            writer.write(hdr)
            await writer.drain()
            await barrier.wait()
            t_end = time.time() + a.hold
            chunk = max(512, int(a.rate * a.interval))
            total_cap = a.cl if a.mode != "chunked" else a.cl
            while time.time() < t_end and rec["sent"] < total_cap:
                try:
                    if a.mode == "chunked":
                        piece = b"a" * chunk
                        writer.write(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
                    else:
                        writer.write(b"a" * chunk)
                    await writer.drain()
                    rec["sent"] += chunk
                except (BrokenPipeError, ConnectionResetError, OSError):
                    rec["error"] = "write_closed"; break
                await asyncio.sleep(a.interval)
            if a.finish and not rec.get("error"):
                # complete the declared body / terminate chunked stream
                try:
                    if a.mode == "chunked":
                        writer.write(b"0\r\n\r\n")
                    else:
                        remain = a.cl - rec["sent"]
                        while remain > 0:
                            k = min(remain, 65536)
                            writer.write(b"a" * k); remain -= k
                            rec["sent"] += k
                            await writer.drain()
                    data = await read_all(reader, a.timeout)
                    rec["code"] = parse_code(data)
                    rec["resp_bytes"] = len(data)
                except Exception as e:
                    rec["error"] = "finish:" + type(e).__name__
        if not a.finish:
            # keep the connection open for the whole hold, then close abruptly
            await asyncio.sleep(0.05)
    finally:
        try:
            writer.close()
        except Exception:
            pass
    rec["dt"] = round(time.time() - rec["t0"], 3)
    return rec

async def cmd_slow(a):
    barrier = asyncio.Barrier(a.n) if hasattr(asyncio, "Barrier") else None
    if barrier is None:
        # fallback simple gate
        class Gate:
            def __init__(self, n):
                self.n = n; self.c = 0; self.ev = asyncio.Event()
            async def wait(self):
                self.c += 1
                if self.c >= self.n:
                    self.ev.set()
                try:
                    await asyncio.wait_for(self.ev.wait(), 10)
                except asyncio.TimeoutError:
                    pass
        barrier = Gate(a.n)
    res = await asyncio.gather(*[slow_one(i, a, barrier) for i in range(a.n)])
    if a.out:
        with open(a.out, "w") as fh:
            for r in res:
                fh.write(json.dumps(r) + "\n")
    dts = sorted(r["dt"] for r in res)
    codes = {}
    for r in res:
        codes[str(r.get("code"))] = codes.get(str(r.get("code")), 0) + 1
    print(json.dumps({"n": a.n, "mode": a.mode, "cl": a.cl, "hold": a.hold,
                      "codes": codes, "dt_max": dts[-1] if dts else None,
                      "errors": sum(1 for r in res if r.get("error"))}))

# ---------- samplers ----------
def cmd_status(a):
    end = time.time() + a.dur if a.dur else None
    with open(a.out, "a") as fh:
        while True:
            t = time.time()
            rec = {"t": t}
            try:
                with urlopen(a.url, timeout=a.timeout) as r:
                    rec["body"] = json.loads(r.read().decode())
            except Exception as e:
                rec["err"] = type(e).__name__
            fh.write(json.dumps(rec) + "\n"); fh.flush()
            if end and t >= end:
                break
            time.sleep(a.interval)

def cmd_probe(a):
    end = time.time() + a.dur if a.dur else None
    with open(a.out, "a") as fh:
        while True:
            t0 = time.time()
            rec = {"t": t0}
            try:
                with urlopen(f"http://{HOST}:{a.port}{a.path}", timeout=a.timeout) as r:
                    r.read()
                    rec["code"] = r.status
            except Exception as e:
                rec["err"] = type(e).__name__
            rec["dt"] = round(time.time() - t0, 4)
            fh.write(json.dumps(rec) + "\n"); fh.flush()
            if end and time.time() >= end:
                break
            time.sleep(a.interval)

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("single"); s.add_argument("--port", type=int, required=True)
    s.add_argument("--path", default="/index.php"); s.add_argument("--file", default="")
    s.add_argument("--timeout", type=float, default=120); s.add_argument("--out", default="")
    s.set_defaults(fn=cmd_single)

    b = sub.add_parser("burst"); b.add_argument("--port", type=int, required=True)
    b.add_argument("--path", default="/index.php"); b.add_argument("--mix", default="")
    b.add_argument("--manifest", default=""); b.add_argument("--bodies", default="bodies")
    b.add_argument("--n", type=int, default=0); b.add_argument("--timeout", type=float, default=180)
    b.add_argument("--connect-parallel", type=int, default=0)
    b.add_argument("--cookie", default=""); b.add_argument("--cookie-name", default="")
    b.add_argument("--out", default=""); b.add_argument("--summary", default="")
    b.set_defaults(fn=cmd_burst)

    w = sub.add_parser("slow"); w.add_argument("--port", type=int, required=True)
    w.add_argument("--path", default="/logprobe.php")
    w.add_argument("--mode", choices=["header", "body", "huge", "chunked"], default="body")
    w.add_argument("--n", type=int, default=200); w.add_argument("--cl", type=int, default=2_000_000)
    w.add_argument("--rate", type=float, default=100_000)   # bytes/sec per connection
    w.add_argument("--interval", type=float, default=0.1)
    w.add_argument("--hold", type=float, default=20)
    w.add_argument("--finish", action="store_true")
    w.add_argument("--timeout", type=float, default=120)
    w.add_argument("--out", default="")
    w.set_defaults(fn=cmd_slow)

    st = sub.add_parser("status"); st.add_argument("--url", required=True)
    st.add_argument("--interval", type=float, default=0.25); st.add_argument("--dur", type=float, default=0)
    st.add_argument("--timeout", type=float, default=1.0); st.add_argument("--out", required=True)
    st.set_defaults(fn=cmd_status)

    pr = sub.add_parser("probe"); pr.add_argument("--port", type=int, required=True)
    pr.add_argument("--path", default="/index.php"); pr.add_argument("--interval", type=float, default=0.2)
    pr.add_argument("--dur", type=float, default=0); pr.add_argument("--timeout", type=float, default=10)
    pr.add_argument("--out", required=True)
    pr.set_defaults(fn=cmd_probe)

    a = ap.parse_args()
    if asyncio.iscoroutinefunction(a.fn):
        asyncio.run(a.fn(a))
    else:
        a.fn(a)

if __name__ == "__main__":
    main()
