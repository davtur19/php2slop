#!/usr/bin/env python3
import json, os, subprocess, sys, time, threading, urllib.request, shutil
R=open('/tmp/opencode/fpm_aslr_run').read().strip()
MAPS=R+"/bin/maps.py"; OUT=R+"/evidence/maps"
def children(pid):
    return [int(x) for x in subprocess.run(["ps","--ppid",str(pid),"-o","pid="],capture_output=True,text=True).stdout.split()]
def snap(tag,master,raw=True):
    recs=[]
    for p in [master]+children(master):
        try: recs.append(json.loads(subprocess.run(["python3",MAPS,str(p)],capture_output=True,text=True).stdout))
        except Exception as e: recs.append({"pid":p,"error":str(e)})
        if raw:
            try: shutil.copy(f"/proc/{p}/maps", f"{OUT}/raw_{tag}_{p}.map")
            except OSError: pass
    json.dump(recs,open(f"{OUT}/{tag}.json","w"),indent=1); return recs
def req(port,path,timeout=30):
    t0=time.time()
    try:
        r=urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",timeout=timeout); b=r.read().decode("latin1","replace"); c=r.status
    except Exception as e: b=str(e); c=getattr(e,"code",0)
    return c,b.strip()[:120],round(time.time()-t0,3)
def exercise(port,n,secs,tag):
    res=[]
    def one(i): res.append([i]+list(req(port,f"/slow.php?s={secs}",timeout=secs+25)))
    ts=[threading.Thread(target=one,args=(i,)) for i in range(n)]
    [t.start() for t in ts]; time.sleep(1.5)
    recs=snap(tag,MASTER); [t.join() for t in ts]
    return recs,sorted(res)
MASTER=int(sys.argv[1]); PORT=int(sys.argv[2]); LABEL=sys.argv[3]; NCYC=int(sys.argv[4]) if len(sys.argv)>4 else 2
summ=[]
summ.append({"phase":"baseline","master":MASTER,"children":children(MASTER)})
snap(f"{LABEL}_baseline",MASTER)
for c in range(1,NCYC+1):
    recs,res=exercise(PORT,10,4,f"{LABEL}_c{c}_inflight")
    summ.append({"cycle":c,"phase":"inflight","pids":[r.get("pid") for r in recs],"codes":[r[1] for r in res]})
    time.sleep(6); snap(f"{LABEL}_c{c}_idle",MASTER)
    kids=children(MASTER); kill=kids[::2][:5]
    for k in kill:
        try: os.kill(k,9)
        except ProcessLookupError: pass
    time.sleep(0.6); newch=children(MASTER)
    summ.append({"cycle":c,"phase":"respawn","killed":kill,"children_0.6s":newch})
    recs,res=exercise(PORT,10,4,f"{LABEL}_c{c}_re_inflight")
    summ.append({"cycle":c,"phase":"resp_inflight","pids":[r.get("pid") for r in recs],"codes":[r[1] for r in res]})
    time.sleep(6); snap(f"{LABEL}_c{c}_re_idle",MASTER)
json.dump(summ,open(f"{OUT}/summary_{LABEL}.json","w"),indent=1)
print(json.dumps(summ)[-2500:])
