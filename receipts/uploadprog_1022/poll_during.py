#!/usr/bin/env python3
"""Poll the session file while one big multipart upload is being parsed.

Usage: poll_during.py SID PATH KEYLEN FILEDATA OUT
"""
import http.client, sys, os, threading, time, random, string, json

PORT = 28893
SESS = '/tmp/opencode/research/realchain_20261022T015900Z/www/wp-content/uploads/sessions/sess_'
sid, path, keylen, filedata, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
sessfile = SESS + sid
observations = []
stop = threading.Event()


def poll():
    while not stop.is_set():
        try:
            s = os.stat(sessfile)
            with open(sessfile, 'rb') as f:
                d = f.read(64)
            observations.append({'t': time.time(), 'size': s.st_size,
                                 'head': d[:40].decode('latin1', 'replace')})
        except FileNotFoundError:
            observations.append({'t': time.time(), 'size': -1})
        time.sleep(0.001)


th = threading.Thread(target=poll)
th.start()

b = '----poll' + ''.join(random.choice(string.ascii_letters) for _ in range(8))
body = bytearray()
body.extend(('--' + b + '\r\n').encode())
body.extend(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n')
body.extend(b'K' * keylen)
body.extend(b'\r\n')
body.extend(('--' + b + '\r\n').encode())
body.extend(b'Content-Disposition: form-data; name="f"; filename="f.bin"\r\nContent-Type: application/octet-stream\r\n\r\n')
body.extend(b'y' * filedata)
body.extend(b'\r\n')
body.extend(('--' + b + '--\r\n').encode())
h = {'Content-Type': 'multipart/form-data; boundary=' + b,
     'Content-Length': str(len(body)), 'Cookie': 'PHPSESSID=' + sid}
t0 = time.time()
c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=180)
c.request('POST', path, bytes(body), h)
r = c.getresponse()
d = r.read()
c.close()
t1 = time.time()
stop.set()
th.join()
sizes = sorted({o['size'] for o in observations})
nonzero = [o for o in observations if o['size'] > 0]
res = {'sid': sid, 'path': path, 'keylen': keylen, 'filedata': filedata,
       'body_len': len(body), 'http': r.status, 'resp_len': len(d),
       'elapsed': round(t1 - t0, 3), 'samples': len(observations),
       'distinct_sizes': sizes[:20], 'nonzero_samples': len(nonzero),
       'first_nonzero': nonzero[:3], 'last_nonzero': nonzero[-3:]}
print(json.dumps(res, indent=1))
open(out, 'w').write(json.dumps(res, indent=1))
