#!/usr/bin/env python3
import subprocess, time, threading, socket, sys, os
RUN=sys.argv[1]
outs=[]
def sleeper(i):
    r=subprocess.run(["curl","-sS","--max-time","25","-o",f"{RUN}/evidence/stock/slow{i}.body","-w","%{http_code}",f"http://127.0.0.1:29320/slow.php?s=15"],capture_output=True,text=True)
    outs.append((i,r.stdout.strip()))
os.makedirs(f"{RUN}/evidence/stock",exist_ok=True)
ts=[threading.Thread(target=sleeper,args=(i,)) for i in range(4)]
for t in ts: t.start()
time.sleep(2.0)
print("children_after_sleepers:", subprocess.run(["bash","-c","ps --ppid $(cat %s/lab/run/fpm-stock.pid) -o pid= | wc -l"%RUN],capture_output=True,text=True).stdout.strip())
# producer
t0=time.time()
p=subprocess.run(["curl","-sS","--max-time","30","-o",f"{RUN}/evidence/stock/producer_oom.body","-w","%{http_code}",f"http://127.0.0.1:29320/producer_oom.php?n=8000000"],capture_output=True,text=True)
print("producer_code:",p.stdout.strip(),"dt=%.3f"%(time.time()-t0))
# consumer immediately
time.sleep(0.05)
c=subprocess.run([f"{RUN}/scripts/consumer_req.py","--port","29320","--sid","stocksid1","--outdir",f"{RUN}/evidence/stock","--tag","consumer_after_oom"],capture_output=True,text=True)
print("consumer_resp_first_line:", c.stdout.splitlines()[0] if c.stdout else "(none)")
for t in ts: t.join()
print("sleeper_codes:", outs)
