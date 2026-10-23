#!/usr/bin/env python3
"""Pinned worker chain: 4 sleepers, producer OOM, consumer upload-progress. Measure timings."""
import json, os, subprocess, sys, time, threading, socket, re
R=open('/tmp/opencode/fpm_aslr_run').read().strip()
WEB=int(sys.argv[1]); FPM_PIDFILE=sys.argv[2]; SID=sys.argv[3]; TAG=sys.argv[4]
MODE=sys.argv[5] if len(sys.argv)>5 else "decode"   # decode|encode
OUT=R+"/evidence/req"; os.makedirs(OUT,exist_ok=True)
ERRLOG=R+"/lab/logs/"+sys.argv[6] if len(sys.argv)>6 else R+"/lab/logs/fpm-stock-error.log"
ACC=R+"/lab/logs/"+sys.argv[7] if len(sys.argv)>7 else R+"/lab/logs/fpm-stock-access.log"
def children():
    return [int(x) for x in subprocess.run(["ps","--ppid",str(int(open(FPM_PIDFILE).read().strip())),"-o","pid="],capture_output=True,text=True).stdout.split()]
def http(method,path,timeout=40,body=None,ctype=None):
    s=socket.create_connection(("127.0.0.1",WEB),timeout=timeout)
    hdr=f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{WEB}\r\nConnection: close\r\n"
    if body is not None: hdr+=f"Content-Length: {len(body)}\r\nContent-Type: {ctype}\r\n"
    t0=time.time(); s.sendall(hdr.encode()+b"\r\n"+(body or b""))
    data=b""; first=None
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            if first is None: first=time.time()-t0
            data+=c
    except socket.timeout: pass
    s.close()
    return {"code":(re.match(rb"HTTP/1.1 (\d+)",data).group(1).decode() if re.match(rb"HTTP/1.1 (\d+)",data) else "000"),
            "t_first":round(first,4) if first else None,"t_total":round(time.time()-t0,4),
            "bytes":len(data),"body":data.split(b"\r\n\r\n",1)[-1][:200].decode("latin1","replace")}
def multipart(sid,pad=None,extra=None):
    b="----bgBoundary7MA4YWxkTrZu0gW"
    parts=[]
    def field(n,v):
        parts.append(f"--{b}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n".encode()); parts.append(v if isinstance(v,bytes) else v.encode()); parts.append(b"\r\n")
    field("PHPSESSID",sid)
    field("PHP_SESSION_UPLOAD_PROGRESS","bgupload")
    if pad is not None: field("pad",pad)
    if extra: 
        for n,v in extra: field(n,v)
    parts.append(f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n".encode()); parts.append(b"A"); parts.append(f"\r\n--{b}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={b}"
res={"tag":TAG,"web":WEB,"children_before":children(),"t0":time.time()}
res["children_before"]=children()
sleeper_results=[]
def sleeper(i):
    sleeper_results.append([i,http("GET",f"/slow.php?s=20",timeout=30)])
ts=[threading.Thread(target=sleeper,args=(i,)) for i in range(4)]
for t in ts: t.start()
time.sleep(2.5)
res["children_after_sleepers"]=children()
# producer
prod = http("GET","/producer_oom.php?n=8000000" if MODE=="decode" else "/producer_ser_oom.php?n=300000",timeout=40)
res["producer"]=prod; res["t_producer_done"]=time.time()
time.sleep(0.05)
body,ctype=multipart(SID)
cons=http("POST","/consumer.php",timeout=40,body=body,ctype=ctype)
res["consumer"]=cons; res["t_consumer_done"]=time.time()
time.sleep(0.2)
res["children_after_consumer"]=children()
log=open(ERRLOG).read() if os.path.exists(ERRLOG) else ""
res["fpm_log_tail"]=log.splitlines()[-12:]
acc=open(ACC).read() if os.path.exists(ACC) else ""
res["access_tail"]=acc.splitlines()[-12:]
# wait for respawn, ping
time.sleep(1.0)
res["children_after_1s"]=children()
ping=http("GET","/ping.php",timeout=10) if MODE=="decode" else None
res["ping"]=ping
res["children_after_ping"]=children()
for t in ts: t.join()
res["sleepers"]=[x[1]["code"] for x in sleeper_results]
json.dump(res,open(f"{OUT}/{TAG}.json","w"),indent=1)
print(json.dumps({k:res[k] for k in ["children_before","children_after_sleepers","producer","consumer","children_after_consumer","children_after_1s","ping","sleepers"]},indent=1))
