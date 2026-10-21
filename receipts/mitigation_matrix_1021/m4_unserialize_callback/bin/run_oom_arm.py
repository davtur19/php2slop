#!/usr/bin/env python3
"""l6 orthogonality check: stock 4.98 MB arm against the pinned-empty callback pool.

Pool l6: memory_limit=8M, php_admin_value[unserialize_callback_func]="" (see conf/fpm.conf).
The arm's multipart allocation is independent of the callback; the worker must exit 70.
"""
import hashlib
import json
import os
import sys

D = "/tmp/opencode/m4_test_1021"
sys.path.insert(0, os.path.join(D, "bin"))
import fcgi  # noqa: E402

B = b"NATIVEOUTPUTEXACT"
SID = "m4oom6"


def field(name, value):
    return (b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + name
            + b"\"\r\n\r\n" + value + b"\r\n")


def fpart(i, filename):
    return (b"--" + B + b"\r\nContent-Disposition: form-data; name=\"upload"
            + str(i).encode() + b"\"; filename=\"" + filename
            + b"\"\r\nContent-Type: application/octet-stream\r\n\r\nX\r\n")


def arm_body():
    body = field(b"PHPSESSID", SID.encode()) + field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for i in range(20):
        n = 9 if i == 0 else 262144
        body += fpart(i, b"F" * n)
    return body + b"--" + B + b"--\r\n"


def main():
    body = arm_body()
    p = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_FILENAME": f"{D}/www/plain/index.php",
        "SCRIPT_NAME": "/index.php",
        "REQUEST_URI": "/index.php",
        "DOCUMENT_ROOT": f"{D}/www/plain",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "localhost",
        "REMOTE_ADDR": "127.0.0.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "CONTENT_TYPE": "multipart/form-data; boundary=NATIVEOUTPUTEXACT",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_COOKIE": f"PHPSESSID={SID}",
    }
    r = fcgi.request("127.0.0.1", 29036, p, body=body)
    st, headers, bd = fcgi.split_http(r["stdout"])
    rec = {
        "step": "oom_arm_8M_with_callback_pinned_empty",
        "port": 29036,
        "body_len_sent": len(body),
        "fastcgi_error": r["error"],
        "status_line": st,
        "response_body_len": len(bd),
        "response_body_sha256": hashlib.sha256(bd).hexdigest(),
        "response_body": bd.decode("utf-8", "replace"),
        "stderr": r["stderr"].decode("utf-8", "replace"),
        "duration_s": r["duration_s"],
    }
    with open(os.path.join(D, "results", "transcripts", "l6_oom_arm.http"), "wb") as fh:
        fh.write(r["stdout"] + b"\n--- STDERR ---\n" + r["stderr"])
    with open(os.path.join(D, "results", "m4_oom_arm.json"), "w") as fh:
        json.dump(rec, fh, indent=2)
    print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    main()
