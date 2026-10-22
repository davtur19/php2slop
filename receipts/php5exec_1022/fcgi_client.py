#!/usr/bin/env python3
import socket, struct, sys, os, argparse

FCGI_BEGIN_REQUEST=1; FCGI_ABORT_REQUEST=2; FCGI_END_REQUEST=3
FCGI_PARAMS=4; FCGI_STDIN=5; FCGI_STDOUT=6; FCGI_STDERR=7; FCGI_DATA=8; FCGI_GET_VALUES=9

def enc_len(n):
    if n < 128: return bytes([n])
    return struct.pack('>I', n | 0x80000000)

def enc_pair(k,v):
    kb=k.encode() if isinstance(k,str) else k
    vb=v.encode() if isinstance(v,str) else v
    return enc_len(len(kb))+enc_len(len(vb))+kb+vb

def rec(t, rid, content=b''):
    pad = (-len(content)) % 8
    return struct.pack('>BBHHBB', 1, t, rid, len(content), pad, 0)+content+b'\0'*pad

def read_records(sock):
    buf=b''
    out=[]; err=[]
    while True:
        hdr=b''
        while len(hdr)<8:
            c=sock.recv(8-len(hdr))
            if not c: return out,err
            hdr+=c
        ver,typ,rid,clen,plen,res=struct.unpack('>BBHHBB',hdr)
        body=b''
        while len(body)<clen:
            c=sock.recv(clen-len(body))
            if not c: return out,err
            body+=c
        if plen:
            p=b''
            while len(p)<plen:
                c=sock.recv(plen-len(p))
                if not c: break
                p+=c
        if typ==FCGI_STDOUT: out.append(body)
        elif typ==FCGI_STDERR: err.append(body)
        elif typ==FCGI_END_REQUEST: return b''.join(out), b''.join(err)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--port',type=int,required=True)
    ap.add_argument('--script',required=True)
    ap.add_argument('--method',default='GET')
    ap.add_argument('--body-file',default=None)
    ap.add_argument('--content-type',default=None)
    ap.add_argument('--query',default='')
    ap.add_argument('--cookie',default=None)
    ap.add_argument('--param',action='append',default=[])
    ap.add_argument('--timeout',type=float,default=5.0)
    a=ap.parse_args()
    body=b''
    if a.body_file:
        with open(a.body_file,'rb') as f: body=f.read()
    params=[
        ('GATEWAY_INTERFACE','CGI/1.1'),
        ('SERVER_SOFTWARE','p5lab'),
        ('SERVER_PROTOCOL','HTTP/1.1'),
        ('REQUEST_METHOD',a.method),
        ('SCRIPT_FILENAME',a.script),
        ('SCRIPT_NAME','/'+os.path.basename(a.script)),
        ('DOCUMENT_ROOT',os.path.dirname(a.script)),
        ('REQUEST_URI','/'+os.path.basename(a.script)+('?'+a.query if a.query else '')),
        ('QUERY_STRING',a.query),
        ('REMOTE_ADDR','127.0.0.1'),
        ('SERVER_NAME','127.0.0.1'),
        ('SERVER_PORT',str(a.port)),
        ('CONTENT_LENGTH',str(len(body))),
    ]
    if a.content_type: params.append(('CONTENT_TYPE',a.content_type))
    if a.cookie: params.append(('HTTP_COOKIE',a.cookie))
    for p in a.param:
        k,_,v=p.partition('=')
        params.append((k,v))
    s=socket.create_connection(('127.0.0.1',a.port),timeout=a.timeout)
    s.settimeout(a.timeout)
    s.sendall(rec(FCGI_BEGIN_REQUEST,1,struct.pack('>HB5s',1,0,b'\0'*5)))
    prm=b''.join(enc_pair(k,v) for k,v in params)
    # split params into <=65535 chunks
    for i in range(0,len(prm),65535):
        s.sendall(rec(FCGI_PARAMS,1,prm[i:i+65535]))
    s.sendall(rec(FCGI_PARAMS,1,b''))
    for i in range(0,len(body),65535):
        s.sendall(rec(FCGI_STDIN,1,body[i:i+65535]))
    s.sendall(rec(FCGI_STDIN,1,b''))
    out,err=read_records(s)
    sys.stdout.buffer.write(out)
    if err:
        sys.stderr.buffer.write(b'\n--- FCGI STDERR ---\n'+err)
    s.close()

if __name__=='__main__':
    main()
