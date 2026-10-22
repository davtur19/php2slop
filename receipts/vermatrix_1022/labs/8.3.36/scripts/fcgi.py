#!/usr/bin/env python3
"""Minimal FastCGI client over TCP for the private FPM lab on 127.0.0.1:28865."""
import socket, struct, time, sys

HOST = '127.0.0.1'
PORT = 28872
DOCROOT = None

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7


def _lenenc(n):
    if n < 128:
        return struct.pack('B', n)
    return struct.pack('>I', n | 0x80000000)


def nv(name, value):
    if isinstance(name, str):
        name = name.encode()
    if isinstance(value, str):
        value = value.encode()
    return _lenenc(len(name)) + _lenenc(len(value)) + name + value


def record(rtype, reqid, content=b''):
    pad = (-len(content)) % 8
    return struct.pack('>BBHHBB', 1, rtype, reqid, len(content), pad, 0) + content + b'\x00' * pad


def params_blob(params):
    return b''.join(nv(k, v) for k, v in params.items())


def base_params(script, body_len, content_type=None, cookie=None, php_value=None, php_admin_value=None):
    p = {
        'GATEWAY_INTERFACE': 'CGI/1.1',
        'SERVER_SOFTWARE': 'fpmgadget-lab',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': DOCROOT + '/' + script,
        'SCRIPT_NAME': '/' + script,
        'DOCUMENT_ROOT': DOCROOT,
        'REMOTE_ADDR': '127.0.0.1',
        'CONTENT_LENGTH': str(body_len),
        'REQUEST_URI': '/' + script,
    }
    if content_type:
        p['CONTENT_TYPE'] = content_type
    if cookie:
        p['HTTP_COOKIE'] = cookie
    if php_value:
        p['PHP_VALUE'] = php_value
    if php_admin_value:
        p['PHP_ADMIN_VALUE'] = php_admin_value
    return p


def read_records(s, deadline):
    buf = b''
    out = bytearray()
    err = bytearray()
    end = False
    while not end:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise TimeoutError('fcgi response timeout')
        s.settimeout(remaining)
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            raise TimeoutError('fcgi response timeout')
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 8:
            ver, rtype, reqid, clen, plen, _ = struct.unpack('>BBHHBB', buf[:8])
            if len(buf) < 8 + clen + plen:
                break
            content = buf[8:8 + clen]
            buf = buf[8 + clen + plen:]
            if rtype == FCGI_STDOUT:
                out += content
            elif rtype == FCGI_STDERR:
                err += content
            elif rtype == FCGI_END_REQUEST:
                end = True
    return bytes(out), bytes(err)


def request(script, body=b'', content_type='application/x-www-form-urlencoded',
            cookie=None, php_value=None, php_admin_value=None, timeout=60,
            extra_params=None):
    reqid = 1
    params = base_params(script, len(body), content_type, cookie, php_value, php_admin_value)
    if extra_params:
        params.update(extra_params)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((HOST, PORT))
    t0 = time.time()
    s.sendall(record(FCGI_BEGIN_REQUEST, reqid, struct.pack('>HB5x', 1, 0)))
    s.sendall(record(FCGI_PARAMS, reqid, params_blob(params)))
    s.sendall(record(FCGI_PARAMS, reqid, b''))
    for i in range(0, len(body), 65535):
        s.sendall(record(FCGI_STDIN, reqid, body[i:i + 65535]))
    s.sendall(record(FCGI_STDIN, reqid, b''))
    out, err = read_records(s, t0 + timeout)
    s.close()
    return {'stdout': out, 'stderr': err, 'elapsed': time.time() - t0,
            'aborted': False, 'status': out.split(b'\r\n', 1)[0].decode('latin1') if out else ''}


def init(docroot, host='127.0.0.1', port=28865):
    global DOCROOT, HOST, PORT
    DOCROOT = docroot
    HOST = host
    PORT = port


if __name__ == '__main__':
    init(sys.argv[1])
    script = sys.argv[2] if len(sys.argv) > 2 else 'probe.php'
    print(repr(request(script)))
