#!/usr/bin/env python3
"""M4 lane driver: php_admin_value[unserialize_callback_func]="" vs user-writable
.autoload lever under PHP 8.5.10 FPM.

Loopback only.  One private php-fpm master, six pools (l0-l5), pm.max_requests=0 so
worker identity is stable.  Every request is recorded as raw FastCGI STDOUT plus a
JSON row (status, body, marker before/after, session file before/after, access-log pid).
"""
import hashlib
import json
import os
import re
import sys
import time

D = "/tmp/opencode/m4_test_1021"
sys.path.insert(0, os.path.join(D, "bin"))
import fcgi  # noqa: E402

BOUND = "m4boundary"
LANES = [
    # tag, port, docroot, autoload dir, pin description
    ("l0", 29030, "base", "autoload_plain", "none (no .user.ini; PHP defaults)"),
    ("l1", 29031, "plain", "autoload_plain", "none (docroot .user.ini sets callback)"),
    ("l2", 29032, "plain", "autoload_plain", "php_admin_value[unserialize_callback_func]=\"\""),
    ("l3", 29033, "plain", "autoload_plain", "callback=\"\" + include_path=\".\""),
    ("l4", 29034, "auto", "autoload_auto", "none (docroot .user.ini, auto_start=1)"),
    ("l5", 29035, "auto", "autoload_auto", "callback=\"\" (auto_start=1)"),
]
RES = os.path.join(D, "results")
TRANSCRIPT = os.path.join(RES, "transcripts")
os.makedirs(TRANSCRIPT, exist_ok=True)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def params(doc, script, method="GET", extra=None):
    p = {
        "REQUEST_METHOD": method,
        "SCRIPT_FILENAME": f"{D}/www/{doc}/{script}",
        "SCRIPT_NAME": f"/{script}",
        "REQUEST_URI": f"/{script}",
        "DOCUMENT_ROOT": f"{D}/www/{doc}",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "localhost",
        "REMOTE_ADDR": "127.0.0.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
    }
    if extra:
        p.update(extra)
    return p


def tiny_upload_body():
    b = BOUND.encode()
    return (b"--" + b + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nMMM\r\n'
            b"--" + b + b"\r\n"
            b'Content-Disposition: form-data; name="f0"; filename="f0.bin"\r\n\r\nUUUUUUUU\r\n'
            b"--" + b + b"--\r\n")


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def rec(lane, step, r, doc, marker, sess_path, extra=None):
    st, headers, body = fcgi.split_http(r["stdout"])
    marker_bytes = read(marker) if os.path.exists(marker) else b""
    sess_before = extra.pop("_sess_before") if extra and "_sess_before" in extra else None
    sess_after = read(sess_path) if os.path.exists(sess_path) else b""
    row = {
        "lane": lane[0],
        "port": lane[1],
        "docroot": doc,
        "pin": lane[4],
        "step": step,
        "fastcgi_error": r["error"],
        "status_line": st,
        "body": body.decode("utf-8", "replace"),
        "body_len": len(body),
        "body_sha256": sha(body),
        "stderr": r["stderr"].decode("utf-8", "replace"),
        "marker_path": marker,
        "marker_after": os.path.exists(marker),
        "marker_bytes": marker_bytes.decode("utf-8", "replace"),
        "session_path": sess_path,
        "session_after_len": len(sess_after),
        "session_after_sha256": sha(sess_after) if sess_after else "",
        "session_after_head": sess_after[:200].decode("utf-8", "replace"),
        "duration_s": r["duration_s"],
        "ts": r["ts"],
    }
    if sess_before is not None:
        row["session_before_len"] = len(sess_before)
        row["session_before_sha256"] = sha(sess_before)
        row["session_before_text"] = sess_before.decode("utf-8", "replace")[:200]
    if extra:
        row.update(extra)
    # access-log pid (last line written for this pool)
    access = os.path.join(D, "logs", f"{lane[0]}.access.log")
    if os.path.exists(access):
        lines = [l for l in read(access).decode("utf-8", "replace").splitlines() if l.strip()]
        row["access_log_tail"] = lines[-1] if lines else ""
        row["access_log_pid"] = lines[-1].split("|")[0] if lines else ""
    return row


def run_get(lane, doc, script, sid=None, sess_path=None, extra=None, step="get"):
    marker = os.path.join(D, lane[3], "marker.txt")
    if os.path.exists(marker):
        os.unlink(marker)
    ex = dict(extra or {})
    if sid:
        ex["HTTP_COOKIE"] = f"PHPSESSID={sid}"
    r = fcgi.request("127.0.0.1", lane[1], params(doc, script, "GET", ex))
    row = rec(lane, step, r, doc, marker, sess_path or os.path.join(D, "sessions", lane[0], "unused"))
    raw = os.path.join(TRANSCRIPT, f"{lane[0]}_{step}.http")
    with open(raw, "wb") as fh:
        fh.write(r["stdout"] + b"\n--- STDERR ---\n" + r["stderr"])
    return row


def main():
    rows = []
    for lane in LANES:
        tag, port, doc, ad, _pin = lane
        # 1. effective INI probe
        rows.append(run_get(lane, doc, "probe.php", step="probe_ini"))
        # 2. script-level unserialize()
        if os.path.exists(os.path.join(D, "www", doc, "d.php")):
            rows.append(run_get(lane, doc, "d.php", step="script_unserialize"))
        # 2b. already-defined class gadget (pin cannot block internal classes)
        if os.path.exists(os.path.join(D, "www", doc, "dpre.php")):
            pm = os.path.join(D, "predefined_marker.txt")
            if os.path.exists(pm):
                os.unlink(pm)
            r = fcgi.request("127.0.0.1", port, params(doc, "dpre.php", "GET"))
            st, headers, body = fcgi.split_http(r["stdout"])
            with open(os.path.join(TRANSCRIPT, f"{tag}_script_unserialize_predefined.http"), "wb") as fh:
                fh.write(r["stdout"] + b"\n--- STDERR ---\n" + r["stderr"])
            rows.append({
                "lane": tag, "port": port, "docroot": doc, "pin": lane[4],
                "step": "script_unserialize_predefined_class",
                "fastcgi_error": r["error"], "status_line": st,
                "body": body.decode("utf-8", "replace"), "body_len": len(body),
                "body_sha256": sha(body), "stderr": r["stderr"].decode("utf-8", "replace"),
                "marker_path": pm, "marker_after": os.path.exists(pm),
                "marker_bytes": read(pm).decode("utf-8", "replace") if os.path.exists(pm) else "",
                "session_path": "", "session_after_len": 0, "session_after_sha256": "",
                "session_after_head": "", "duration_s": r["duration_s"], "ts": r["ts"],
            })
        # 3. pre-script decode: upload-progress startup update (base/plain docroots)
        if doc in ("base", "plain"):
            sid = f"m4up{tag[-1]}"
            sp = os.path.join(D, "sessions", tag, f"sess_{sid}")
            with open(sp, "w") as fh:
                fh.write('upload_progress_MMM|O:2:"D2":0:{}')
            before = read(sp)
            marker = os.path.join(D, ad, "marker.txt")
            if os.path.exists(marker):
                os.unlink(marker)
            b = tiny_upload_body()
            ex = {
                "CONTENT_TYPE": f"multipart/form-data; boundary={BOUND}",
                "CONTENT_LENGTH": str(len(b)),
                "HTTP_COOKIE": f"PHPSESSID={sid}",
            }
            r = fcgi.request("127.0.0.1", port,
                             params(doc, "index.php", "POST", ex), body=b)
            row = rec(lane, "pre_script_upload_progress", r, doc, marker, sp,
                      extra={"_sess_before": before})
            raw = os.path.join(TRANSCRIPT, f"{tag}_pre_script_upload_progress.http")
            with open(raw, "wb") as fh:
                fh.write(r["stdout"] + b"\n--- STDERR ---\n" + r["stderr"])
            rows.append(row)
        # 4. pre-script decode: session.auto_start at RINIT (auto docroot)
        if doc == "auto":
            sid = f"m4auto{tag[-1]}"
            sp = os.path.join(D, "sessions", tag, f"sess_{sid}")
            with open(sp, "w") as fh:
                fh.write('m4key|O:2:"D2":0:{}')
            before = read(sp)
            marker = os.path.join(D, ad, "marker.txt")
            if os.path.exists(marker):
                os.unlink(marker)
            r = fcgi.request("127.0.0.1", port,
                             params(doc, "index.php", "GET", {"HTTP_COOKIE": f"PHPSESSID={sid}"}))
            row = rec(lane, "pre_script_session_auto_start", r, doc, marker, sp,
                      extra={"_sess_before": before})
            raw = os.path.join(TRANSCRIPT, f"{tag}_pre_script_session_auto_start.http")
            with open(raw, "wb") as fh:
                fh.write(r["stdout"] + b"\n--- STDERR ---\n" + r["stderr"])
            rows.append(row)

    out = os.path.join(RES, "m4_results.jsonl")
    with open(out, "w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"wrote {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
