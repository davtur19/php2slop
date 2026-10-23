#!/usr/bin/env python3
import subprocess, time, threading, sys, os
port=sys.argv[1]; sid=sys.argv[2]; outdir=sys.argv[3]; run=sys.argv[4]
os.makedirs(outdir,exist_ok=True)
master=open(f"{run}/lab/run/"+("fpm-8512.pid" if port=="29330" else "fpm-stock.pid")).read().strip()
def sleeper(i):
    subprocess.run(["curl","-sS","--max-time","25","-o",f"{outdir}/slow{i}.body","-w","%{http_code}",f"http://127.0.0.1:{port}/slow.php?s=15"],capture_output=True,text=True)
ts=[threading.Thread(target=sleeper,args=(i,)) for i in range(4)]
for t in ts: t.start()
time.sleep(2.0)
print("children_after_sleepers:", subprocess.run(["bash","-c",f"ps --ppid {master} -o pid= | wc -l"],capture_output=True,text=True).stdout.strip())
t0=time.time()
p=subprocess.run(["curl","-sS","--max-time","30","-o",f"{outdir}/producer_oom.body","-w","%{http_code}",f"http://127.0.0.1:{port}/producer_oom.php?n=8000000"],capture_output=True,text=True)
print("producer_code:",p.stdout.strip(),"dt=%.3f"%(time.time()-t0))
time.sleep(0.05)
c=subprocess.run([f"{run}/scripts/consumer_req.py","--port",port,"--sid",sid,"--outdir",outdir,"--tag","consumer_after_oom"],capture_output=True,text=True)
lines=c.stdout.splitlines()
print("consumer_status_line:", lines[0] if lines else "(none)")
for l in lines:
    if l.startswith("CONSUMER"): print("consumer_body:", l)
for t in ts: t.join()
