#!/usr/bin/env python3
"""measure.py - battery for the "block uploads entirely" mitigation lanes.

Every case snapshots, per lane:
  * FPM error log (fatal / warnings)
  * FPM access log (was the request accepted by a worker?)
  * nginx access + error log
  * session directory (file created? upload_progress payload?)
  * worker PIDs before/after (did the worker die / get respawned?)
  * FPM master log (worker exit notices)

Writes results/lanes.jsonl (one row per case) and results/ini/<lane>.txt.
"""
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

BASE = "/tmp/opencode/no_upload_mitigation_1021"
BIN = os.path.join(BASE, "bin")
sys.path.insert(0, BIN)
import narm  # noqa: E402

RESULTS = os.path.join(BASE, "results")
OOM_RE = narm.OOM_RE
FATAL_RE = re.compile(r"Fatal error[^\r\n<]*")
UNKNOWN0_RE = re.compile(r"in Unknown on line 0")
WARN_RE = re.compile(r"(Warning|Notice|Deprecated)[^\r\n<]*")

SID = narm.ARM_SID  # b"armsess1021" (11 chars: keeps the arm byte-exact)

LANES = {
    "U0": {
        "port": 29060, "pool": "u0", "sess": f"{BASE}/sessions/u0",
        "err": f"{BASE}/logs/fpm_u0.error.log", "acc": f"{BASE}/logs/fpm_u0.access.log",
        "ngx": f"{BASE}/logs/u0.access.log", "ngxerr": f"{BASE}/logs/u0.error.log",
        "edge": "client_max_body_size 8m; no multipart rule (control)",
        "php": "memory_limit=8M, stock upload INI",
    },
    "U1": {
        "port": 29061, "pool": "u1", "sess": f"{BASE}/sessions/u1",
        "err": f"{BASE}/logs/fpm_u1.error.log", "acc": f"{BASE}/logs/fpm_u1.access.log",
        "ngx": f"{BASE}/logs/u1.access.log", "ngxerr": f"{BASE}/logs/u1.error.log",
        "edge": "client_max_body_size 8m; no multipart rule",
        "php": "php_admin_flag[file_uploads]=off, memory_limit=8M (php-fpm)",
    },
    "U1cgi": {
        "port": 29067, "pool": None, "pidfile": f"{BASE}/run/php-cgi_u1cgi.pid",
        "sess": f"{BASE}/sessions/u1cgi",
        "err": f"{BASE}/logs/cgi_u1cgi.error.log", "acc": f"{BASE}/logs/cgi_u1cgi.access.log",
        "ngx": f"{BASE}/logs/u1cgi.access.log", "ngxerr": f"{BASE}/logs/u1cgi.error.log",
        "edge": "client_max_body_size 8m; no multipart rule",
        "php": "php-cgi -d file_uploads=0, memory_limit=8M",
    },
    "U2": {
        "port": 29062, "pool": "u2", "sess": f"{BASE}/sessions/u2",
        "err": f"{BASE}/logs/fpm_u2.error.log", "acc": f"{BASE}/logs/fpm_u2.access.log",
        "ngx": f"{BASE}/logs/u2.access.log", "ngxerr": f"{BASE}/logs/u2.error.log",
        "edge": "client_max_body_size 8m; no multipart rule",
        "php": "php_admin_flag[enable_post_data_reading]=off, memory_limit=8M",
    },
    "U3": {
        "port": 29063, "pool": "u3", "sess": f"{BASE}/sessions/u3",
        "err": f"{BASE}/logs/fpm_u3.error.log", "acc": f"{BASE}/logs/fpm_u3.access.log",
        "ngx": f"{BASE}/logs/u3.access.log", "ngxerr": f"{BASE}/logs/u3.error.log",
        "edge": 'map $http_content_type -> if ($u3_reject) { return 415; } (all methods)',
        "php": "memory_limit=8M, stock upload INI",
    },
    "U3b": {
        "port": 29068, "pool": "u3b", "sess": f"{BASE}/sessions/u3b",
        "err": f"{BASE}/logs/fpm_u3b.error.log", "acc": f"{BASE}/logs/fpm_u3b.access.log",
        "ngx": f"{BASE}/logs/u3b.access.log", "ngxerr": f"{BASE}/logs/u3b.error.log",
        "edge": 'map "$request_method:$http_content_type" -> 415 only for POST/PUT/PATCH multipart',
        "php": "memory_limit=8M, stock upload INI",
    },
    "U4": {
        "port": 29064, "pool": "u4", "sess": f"{BASE}/sessions/u4",
        "err": f"{BASE}/logs/fpm_u4.error.log", "acc": f"{BASE}/logs/fpm_u4.access.log",
        "ngx": f"{BASE}/logs/u4.access.log", "ngxerr": f"{BASE}/logs/u4.error.log",
        "edge": "client_max_body_size 128k only (no multipart rule)",
        "php": "memory_limit=8M, stock upload INI",
    },
    "U5": {
        "port": 29065, "pool": "u5", "sess": f"{BASE}/sessions/u5",
        "err": f"{BASE}/logs/fpm_u5.error.log", "acc": f"{BASE}/logs/fpm_u5.access.log",
        "ngx": f"{BASE}/logs/u5.access.log", "ngxerr": f"{BASE}/logs/u5.error.log",
        "edge": "client_max_body_size 8m; no multipart rule",
        "php": "php_admin_value[max_file_uploads]=0, memory_limit=8M",
    },
    "U6": {
        "port": 29066, "pool": "u6", "sess": f"{BASE}/sessions/u6",
        "err": f"{BASE}/logs/fpm_u6.error.log", "acc": f"{BASE}/logs/fpm_u6.access.log",
        "ngx": f"{BASE}/logs/u6.access.log", "ngxerr": f"{BASE}/logs/u6.error.log",
        "edge": "client_max_body_size 8m; no multipart rule",
        "php": "php_admin_value[post_max_size]=0, memory_limit=8M",
    },
}

ROWS = []


# ---------------------------------------------------------------- plumbing
def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


def read_new(p, off):
    try:
        with open(p, "rb") as f:
            f.seek(off)
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def sess_state(d):
    out = {}
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        p = os.path.join(d, n)
        try:
            with open(p, "rb") as f:
                data = f.read()
            out[n] = {"size": len(data), "upg": b"upload_progress_" in data}
        except OSError:
            pass
    return out


def worker_pids(lane):
    L = LANES[lane]
    if L.get("pidfile"):
        try:
            pid = int(open(L["pidfile"]).read().strip())
            os.kill(pid, 0)
            return [pid]
        except (OSError, ValueError):
            return []
    if not L.get("pool"):
        return []
    try:
        ps = subprocess.check_output(["ps", "-eo", "pid=,args="], text=True)
    except subprocess.CalledProcessError:
        return []
    tag = "php-fpm: pool " + L["pool"]
    pids = []
    for line in ps.splitlines():
        line = line.strip()
        if not line:
            continue
        pid, _, args = line.partition(" ")
        if tag in args:
            pids.append(int(pid))
    return sorted(pids)


def parse_response(raw):
    if not raw:
        return {"status": None, "headers": {}, "body": ""}
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    m = re.match(rb"HTTP/\d\.\d (\d{3})", lines[0]) if lines else None
    if m:
        status = int(m.group(1))
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs.setdefault(k.strip().lower().decode("latin1"), v.strip().decode("latin1"))
    return {"status": status, "headers": hdrs,
            "body": rest.decode("utf-8", "replace")}


def request(port, method="POST", path="/index.php", body=b"",
            content_type="multipart/form-data; boundary=" + narm.BOUNDARY.decode(),
            cookie=None, extra_headers=None, chunked=False, timeout=120.0):
    t0 = time.time()
    hdrs = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}",
            "Connection: close", "User-Agent: no-upload-battery/1"]
    if content_type:
        hdrs.append("Content-Type: " + content_type)
    if cookie:
        hdrs.append("Cookie: " + cookie)
    for k, v in (extra_headers or {}).items():
        hdrs.append(f"{k}: {v}")
    if chunked:
        hdrs.append("Transfer-Encoding: chunked")
    else:
        hdrs.append("Content-Length: %d" % len(body))
    req = ("\r\n".join(hdrs) + "\r\n\r\n").encode()

    sent = 0
    send_error = None
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    chunks = []
    try:
        s.sendall(req)
        try:
            if chunked:
                step = 64 * 1024
                for i in range(0, len(body), step):
                    part = body[i:i + step]
                    s.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
                    sent += len(part)
                s.sendall(b"0\r\n\r\n")
            else:
                step = 64 * 1024
                for i in range(0, len(body), step):
                    part = body[i:i + step]
                    s.sendall(part)
                    sent += len(part)
        except (BrokenPipeError, ConnectionResetError) as e:
            send_error = type(e).__name__
        while True:
            try:
                b = s.recv(65536)
            except (ConnectionResetError, socket.timeout) as e:
                send_error = send_error or type(e).__name__
                break
            if not b:
                break
            chunks.append(b)
    finally:
        s.close()
    raw = b"".join(chunks)
    r = parse_response(raw)
    return {"port": port, "method": method, "path": path, "body_len": len(body),
            "chunked": chunked, "bytes_sent": sent, "send_error": send_error,
            "http_status": r["status"], "resp_headers": r["headers"],
            "resp_len": len(raw), "resp_body": r["body"],
            "resp_body_head": r["body"][:800],
            "resp_sha256": hashlib.sha256(raw).hexdigest(),
            "duration_s": round(time.time() - t0, 3)}


def pre(lane):
    L = LANES[lane]
    return {"err": size(L["err"]), "acc": size(L["acc"]), "ngx": size(L["ngx"]),
            "ngxerr": size(L["ngxerr"]), "sess": sess_state(L["sess"]),
            "workers": worker_pids(lane),
            "master": size(f"{BASE}/logs/php-fpm-master.log")}


def clear_sid(lane, sid):
    p = os.path.join(LANES[lane]["sess"], "sess_" + sid)
    try:
        os.unlink(p)
    except OSError:
        pass


def post_case(lane, tag, extra, pre_state, note=""):
    time.sleep(0.2)  # let FPM flush access/error lines
    L = LANES[lane]
    err = read_new(L["err"], pre_state["err"])
    acc = read_new(L["acc"], pre_state["acc"])
    ngx = read_new(L["ngx"], pre_state["ngx"])
    ngxerr = read_new(L["ngxerr"], pre_state["ngxerr"])
    master = read_new(f"{BASE}/logs/php-fpm-master.log", pre_state["master"])
    now = sess_state(L["sess"])
    new_sess = {k: v for k, v in now.items() if k not in pre_state["sess"]}
    changed = {k: v for k, v in now.items()
               if k in pre_state["sess"] and v != pre_state["sess"][k]}
    workers_after = worker_pids(lane)
    oom = OOM_RE.search(err)
    fatal = FATAL_RE.search(err)
    unknown0 = UNKNOWN0_RE.search(err)
    body = extra.get("resp_body") or ""
    row = {
        "tag": tag, "lane": lane, "note": note,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "config": {"edge": L["edge"], "php": L["php"]},
        "port": extra.get("port"), "method": extra.get("method"),
        "path": extra.get("path"),
        "body_len": extra.get("body_len"),
        "chunked": extra.get("chunked"),
        "bytes_sent": extra.get("bytes_sent"),
        "send_error": extra.get("send_error"),
        "http_status": extra.get("http_status"),
        "resp_len": extra.get("resp_len"),
        "resp_sha256": extra.get("resp_sha256"),
        "resp_body_head": body[:800],
        "script_output": body.startswith("S:") or body.startswith("R:"),
        "php_fatal_in_log": bool(fatal),
        "php_fatal_is_unknown_line0": bool(unknown0),
        "php_fatal_line": fatal.group(0) if fatal else None,
        "oom_line": oom.group(0) if oom else None,
        "oom_limit": int(oom.group(1)) if oom else None,
        "oom_tried": (int(oom.group(2)) if (oom and oom.group(2)) else None),
        "php_warnings": WARN_RE.findall(err)[:6],
        "resp_warnings": WARN_RE.findall(body)[:6],
        "fpm_access_lines": len([x for x in acc.splitlines() if x.strip()]),
        "fpm_access_tail": acc.strip().splitlines()[-1] if acc.strip() else None,
        "nginx_access_lines": len([x for x in ngx.splitlines() if x.strip()]),
        "nginx_access_tail": ngx.strip().splitlines()[-1] if ngx.strip() else None,
        "nginx_error_delta": ngxerr.strip()[:400],
        "master_log_delta": master.strip()[:400],
        "new_session_files": sorted(new_sess.keys()),
        "new_session_has_upload_progress": any(v["upg"] for v in new_sess.values()),
        "changed_session_has_upload_progress": any(v["upg"] for v in changed.values()),
        "workers_before": pre_state["workers"],
        "workers_after": workers_after,
        "worker_changed": pre_state["workers"] != workers_after,
        "err_delta_chars": len(err),
        "acc_delta_chars": len(acc),
    }
    ROWS.append(row)
    with open(os.path.join(RESULTS, "lanes.jsonl"), "a") as f:
        f.write(json.dumps(row) + "\n")
    print(json.dumps({k: row[k] for k in
                      ("tag", "lane", "body_len", "http_status", "resp_len",
                       "php_fatal_is_unknown_line0", "oom_tried",
                       "fpm_access_lines", "new_session_files",
                       "worker_changed", "send_error")}, default=str))
    return row


def case(lane, tag, body, path="/index.php", method="POST", content_type=None,
         cookie=None, chunked=False, extra_headers=None, sid=None, note=""):
    L = LANES[lane]
    if sid:
        clear_sid(lane, sid)
    p = pre(lane)
    r = request(L["port"], method=method, path=path, body=body,
                content_type=content_type if content_type is not None
                else ("multipart/form-data; boundary=" + narm.BOUNDARY.decode()),
                cookie=cookie, chunked=chunked, extra_headers=extra_headers)
    return post_case(lane, tag, r, p, note=note)


def probe(lane):
    L = LANES[lane]
    r = request(L["port"], method="GET", path="/probe.php", body=b"",
                content_type=None, timeout=30)
    out = os.path.join(RESULTS, "ini", f"{lane}.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write(r["resp_body"])
    print("== probe", lane, "status", r["http_status"])
    print(r["resp_body"])
    return r["resp_body"]


# ---------------------------------------------------------------- bodies
def arm_body():
    return narm.arm_body(SID)


def small_multipart(sid=b"smallfiled001", token=True, nfiles=1, fname=b"a.bin"):
    body = narm.field(b"PHPSESSID", sid)
    if token:
        body += narm.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for i in range(nfiles):
        body += (b"--" + narm.BOUNDARY + b"\r\n"
                 + b'Content-Disposition: form-data; name="f' + str(i).encode()
                 + b'"; filename="' + fname + b'"\r\n'
                 b"Content-Type: application/octet-stream\r\n\r\n"
                 + b"Y" * 1000 + b"\r\n")
    return body + b"--" + narm.BOUNDARY + b"--\r\n"


def dense_small_body(target=120_000, parts=4):
    """Body under the 128k edge cap but dense in filename bytes."""
    per = (target - 1500) // parts - 120
    b = narm.field(b"PHPSESSID", b"densesid001")
    b += narm.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for i in range(parts):
        b += (b"--" + narm.BOUNDARY + b"\r\n"
              + b'Content-Disposition: form-data; name="d' + str(i).encode()
              + b'"; filename="' + b"F" * per + b'"\r\n'
              b"Content-Type: application/octet-stream\r\n\r\nX\r\n")
    return b + b"--" + narm.BOUNDARY + b"--\r\n"


def urlencoded(v=b"hello"):
    from urllib.parse import urlencode
    return urlencode({"v": v.decode()}).encode()


# ---------------------------------------------------------------- phases
def phase_baseline():
    probe("U0")
    case("U0", "U0_arm_stock_4983500", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="baseline reproduction of the OOM arm")
    case("U0", "U0_small_multipart_sanity", small_multipart(),
         cookie="PHPSESSID=smallfiled001", sid="smallfiled001",
         note="lane works end-to-end: parser + script output")


def phase_u1():
    probe("U1")
    case("U1", "U1_arm_file_uploads_off", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="file_uploads=0 vs byte-exact arm")
    case("U1", "U1_small_multipart_file_uploads_off", small_multipart(),
         cookie="PHPSESSID=smallfiled001", sid="smallfiled001",
         note="$_FILES / warning behaviour with file_uploads=0")


def phase_u1cgi():
    probe("U1cgi")
    case("U1cgi", "U1cgi_arm_file_uploads_off", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="file_uploads=0 via php-cgi (cross-SAPI confirmation)")


def phase_u2():
    probe("U2")
    case("U2", "U2_arm_enable_post_data_reading_off", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="enable_post_data_reading=0 vs byte-exact arm")
    case("U2", "U2_urlencoded_post", urlencoded(),
         path="/post.php", content_type="application/x-www-form-urlencoded",
         note="tradeoff: normal POST endpoint with POST parsing disabled")
    case("U2", "U2_small_multipart", small_multipart(),
         cookie="PHPSESSID=smallfiled001", sid="smallfiled001",
         note="multipart body under no-parse regime")


def phase_u3():
    probe("U3")
    case("U3", "U3_arm_multipart_415", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="coarse edge rule must answer 415 before PHP")
    case("U3", "U3_urlencoded_post_ok", urlencoded(),
         path="/post.php", content_type="application/x-www-form-urlencoded",
         note="legit urlencoded POST must still work")
    case("U3", "U3_get_no_body", b"", method="GET", path="/probe.php",
         content_type=None, note="legit GET unaffected")
    case("U3", "U3_get_with_multipart_ct_header", b"", method="GET",
         path="/probe.php", content_type="multipart/form-data; boundary=x",
         note="GET carrying a multipart CT header (no body)")
    case("U3", "U3_legit_multipart_upload", narm.legit_body(),
         path="/upload.php", cookie="PHPSESSID=legitu3",
         note="tradeoff: real upload endpoint rejected by the rule")


def phase_u3b():
    probe("U3b")
    case("U3b", "U3b_arm_multipart_415", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="refined rule (POST/PUT/PATCH only) vs arm")
    case("U3b", "U3b_urlencoded_post_ok", urlencoded(),
         path="/post.php", content_type="application/x-www-form-urlencoded",
         note="legit urlencoded POST")
    case("U3b", "U3b_get_with_multipart_ct_header", b"", method="GET",
         path="/probe.php", content_type="multipart/form-data; boundary=x",
         note="GET with multipart CT header must be unaffected by refined rule")
    case("U3b", "U3b_legit_multipart_upload", narm.legit_body(),
         path="/upload.php", note="tradeoff: upload endpoints still blocked")


def phase_u4():
    probe("U4")
    case("U4", "U4_arm_413_128k", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="128k cap alone vs 4.98MB arm")
    small = small_multipart(sid=b"smallu4sid01")
    case("U4", "U4_small_multipart_with_progress_%d" % len(small), small,
         cookie="PHPSESSID=smallu4sid01", sid="smallu4sid01",
         note="tiny multipart still reaches the parser? (fatal at 8M?)")
    dense = dense_small_body()
    case("U4", "U4_dense_small_%d" % len(dense), dense,
         cookie="PHPSESSID=densesid001", sid="densesid001",
         note="filename-dense body just under 128k at 8M")
    big = b"X" * 130_000
    case("U4", "U4_body_130000_413", big, content_type="application/octet-stream",
         note="cap boundary: 130000 B > 128k")
    case("U4", "U4_legit_upload_1435", narm.legit_body(), path="/upload.php",
         note="legit small upload under the cap still works")


def phase_u5():
    probe("U5")
    case("U5", "U5_arm_max_file_uploads_0", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="max_file_uploads=0 vs byte-exact arm")
    case("U5", "U5_two_files_warning", small_multipart(sid=b"maxfiles0001", nfiles=2),
         cookie="PHPSESSID=maxfiles0001", sid="maxfiles0001",
         note="warning text / $_FILES count with max_file_uploads=0")


def phase_u6():
    probe("U6")
    case("U6", "U6_arm_post_max_size_0", arm_body(),
         cookie="PHPSESSID=" + SID.decode(), sid=SID.decode(),
         note="post_max_size=0 semantics: does it disable POST or mean unlimited?")
    case("U6", "U6_urlencoded_post", urlencoded(),
         path="/post.php", content_type="application/x-www-form-urlencoded",
         note="post_max_size=0 vs a normal urlencoded POST")


PHASES = {"baseline": phase_baseline, "u1": phase_u1, "u1cgi": phase_u1cgi,
          "u2": phase_u2, "u3": phase_u3, "u3b": phase_u3b, "u4": phase_u4,
          "u5": phase_u5, "u6": phase_u6}

if __name__ == "__main__":
    for name in sys.argv[1:] or list(PHASES):
        print("== phase", name, "==", flush=True)
        PHASES[name]()
    print("== done, rows:", len(ROWS))
