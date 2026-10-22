#!/usr/bin/env python3
import http.client,sys,os,random,string
PORT=28895
def multipart(sid,key,path='/lab_noop.php',file_bytes=b'x'):
    b='----stocklab'+''.join(random.choice(string.ascii_letters+string.digits) for _ in range(16))
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
    part('PHPSESSID',sid.encode())
    part('PHP_SESSION_UPLOAD_PROGRESS',key if isinstance(key,bytes) else key.encode())
    if file_bytes is not None: part('f',file_bytes,filename='f.bin',ctype='application/octet-stream')
    out.extend(('--'+b+'--\r\n').encode())
    h={'Content-Type':'multipart/form-data; boundary='+b,'Content-Length':str(len(out)),'Cookie':'PHPSESSID='+sid}
    c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=120)
    c.request('POST',path,bytes(out),h); r=c.getresponse(); data=r.read(); c.close()
    return r.status,dict(r.getheaders()),data
if __name__=='__main__':
    sid=sys.argv[1]; key=(sys.argv[2].encode() if len(sys.argv)>2 else b'x')
    path=sys.argv[3] if len(sys.argv)>3 else '/lab_noop.php'
    st,h,d=multipart(sid,key,path)
    print('status',st,'len',len(d),'body',d[:200])
