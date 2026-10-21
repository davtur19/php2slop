#!/usr/bin/env python3
"""cgi_boundary.py - measure the memory_limit boundary for the multipart arm.

Spawns the 8.5.10 php-cgi (ASAN build, USE_ZEND_ALLOC=1 so memory_limit is
enforced) with a chosen memory_limit / post_max_size and feeds the stock
multipart body on stdin. Binary-searches the smallest memory_limit (byte
granularity) that completes without the "Allowed memory size" fatal.

The point: quantify the headroom rule for M2, i.e. how much memory the
multipart filename handling needs on top of the request body size.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

BOUNDARY = b"NATIVEOUTPUTEXACT"
FATAL = re.compile(rb"Allowed memory size of (\d+) bytes exhausted(?: \(tried to allocate (\d+) bytes\))?")
WARN = re.compile(rb"(?:PHP )?Warning:[^\r\n<]*")


def field(name, value):
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + value + b"\r\n")


def file_part(index, filename):
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="upload'
            + str(index).encode() + b'"; filename="' + filename + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\nX\r\n")


def arm_body(sid, length, parts=20):
    body = field(b"PHPSESSID", sid.encode())
    body += field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for i in range(parts):
        n = 9 if i == 0 else length
        body += file_part(i, b"F" * n)
    return body + b"--" + BOUNDARY + b"--\r\n"


def run(binary, workdir, sessdir, limit, post_max, length, parts, timeout=120):
    body = arm_body("cgboundary", length, parts)
    env = {
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": "multipart/form-data; boundary=" + BOUNDARY.decode(),
        "CONTENT_LENGTH": str(len(body)),
        "SCRIPT_FILENAME": os.path.join(workdir, "index.php"),
        "SCRIPT_NAME": "/index.php",
        "REQUEST_URI": "/index.php",
        "QUERY_STRING": "",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REDIRECT_STATUS": "1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "HTTP_COOKIE": "PHPSESSID=cgboundary",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:allocator_may_return_null=1",
        "USE_ZEND_ALLOC": "1",
    }
    argv = [binary, "-n",
            "-d", "session.save_path=" + sessdir,
            "-d", "upload_tmp_dir=" + sessdir + "/tmp",
            "-d", "sys_temp_dir=" + sessdir + "/tmp",
            "-d", "session.upload_progress.enabled=0",
            "-d", "session.use_strict_mode=0",
            "-d", "session.use_only_cookies=1",
            "-d", "session.gc_probability=0",
            "-d", "display_errors=1",
            "-d", "log_errors=0",
            "-d", "error_reporting=-1",
            "-d", "memory_limit=" + str(limit),
            "-d", "post_max_size=" + str(post_max),
            "-d", "max_file_uploads=" + str(parts)]
    os.makedirs(sessdir + "/tmp", exist_ok=True)
    try:
        p = subprocess.run(argv, input=body, env=env, capture_output=True, timeout=timeout)
        out, err, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        out, err, rc = e.stdout or b"", e.stderr or b"", "TIMEOUT"
    blob = out + b"\n" + err
    m = FATAL.search(blob)
    w = WARN.findall(blob)
    return {
        "limit": limit, "body_len": len(body), "rc": rc,
        "oom": ({"limit": int(m.group(1)), "tried": int(m.group(2)) if m.group(2) else None}
                if m else None),
        # PHP refuses to *lower* memory_limit below current usage and keeps the
        # previous (higher) value; such a run does not prove the limit is enough.
        "set_limit_failed": b"Failed to set m" in out,
        "warnings": [x.decode("latin-1") for x in w][:5],
        "stdout_len": len(out), "stdout_sha256": hashlib.sha256(out).hexdigest(),
        "script_ran": out.rstrip().endswith(b"S:0") or b"S:0" in out,
        "stdout_preview": out[:220].decode("latin-1", "replace"),
    }


def first_surviving(binary, workdir, sessdir, lo, hi, post_max, length, parts, log):
    """Binary search smallest limit in [lo,hi] that does not OOM."""
    r = run(binary, workdir, sessdir, hi, post_max, length, parts)
    if r["oom"]:
        raise SystemExit(f"upper bound {hi} still OOMs for length {length}: {r}")
    # find the boundary with byte granularity
    while lo < hi:
        mid = (lo + hi) // 2
        r = run(binary, workdir, sessdir, mid, post_max, length, parts)
        log.append({"length": length, "tested_limit": mid, "oom": bool(r["oom"]),
                    "tried": (r["oom"] or {}).get("tried")})
        if r["oom"]:
            lo = mid + 1
        else:
            hi = mid
    return lo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="/home/davide/ailocal/php/zerodays_1020/build_asan/sapi/cgi/php-cgi")
    ap.add_argument("--workdir", default="/tmp/opencode/mitigation_1021/htdocs")
    ap.add_argument("--sessdir", default="/tmp/opencode/mitigation_1021/results/cgi_boundary_sessions")
    ap.add_argument("--out", default="/tmp/opencode/mitigation_1021/results/cgi_boundary.json")
    ap.add_argument("--lengths", default="1024,65536,262144,786432")
    ap.add_argument("--parts", type=int, default=20)
    ap.add_argument("--post-max", type=int, default=64 * 1024 * 1024)
    ap.add_argument("--lo", type=int, default=1024 * 1024)
    a = ap.parse_args()

    lengths = [int(x) for x in a.lengths.split(",")]
    log, results = [], []
    for L in lengths:
        body_len = len(arm_body("cgboundary", L, a.parts))
        lo, hi = a.lo, 512 * 1024 * 1024
        min_ok = first_surviving(a.binary, a.workdir, a.sessdir, lo, hi,
                                 a.post_max, L, a.parts, log)
        # verify the two sides of the boundary
        below = run(a.binary, a.workdir, a.sessdir, min_ok - 1, a.post_max, L, a.parts)
        at = run(a.binary, a.workdir, a.sessdir, min_ok, a.post_max, L, a.parts)
        res = {
            "filename_len": L, "parts": a.parts, "body_len": body_len,
            "min_ok_limit": min_ok, "min_ok_limit_mib": round(min_ok / 1048576, 3),
            "limit_minus_body": min_ok - body_len,
            "below_oom": below["oom"], "below_rc": below["rc"],
            "at_set_limit_failed": at["set_limit_failed"],
            "below_set_limit_failed": below["set_limit_failed"],
            "at_oom": at["oom"], "at_rc": at["rc"],
            "at_script_ran": at["script_ran"],
            "at_stdout_preview": at["stdout_preview"],
        }
        results.append(res)
        print(json.dumps(res, sort_keys=True), flush=True)

    json.dump({"binary": a.binary, "post_max_size": a.post_max,
               "results": results, "search_log": log},
              open(a.out, "w"), indent=1, sort_keys=True)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
