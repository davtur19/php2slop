#!/usr/bin/env python3
import json, os, subprocess, sys, time, threading, socket, urllib.request

MAPS = "/tmp/opencode/research/fpm_aslr_20261023T073345Z/bin/maps.py"

def children(pid):
    out = subprocess.run(["ps","--ppid",str(pid),"-o","pid="],capture_output=True,text=True).stdout
    return [int(x) for x in out.split()]

def snap(tag, master, outdir):
    pids = [master] + children(master)
    recs = []
    for p in pids:
        try:
            recs.append(json.loads(subprocess.run(["python3",MAPS,str(p)],capture_output=True,text=True).stdout))
        except Exception as e:
            recs.append({"pid":p,"error":str(e)})
    path = os.path.join(outdir, tag + ".json")
    json.dump(recs, open(path,"w"), indent=1)
    return recs

def req(port, path, timeout=30):
    t0=time.time()
    try:
        r=urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout)
        body=r.read().decode("latin1","replace"); code=r.status
    except Exception as e:
        body=str(e); code=getattr(e,"code",0)
    return code, body.strip().replace("\n"," | "), time.time()-t0

def exercise(port, n, secs, outdir, tag):
    res=[]
    def one(i):
        res.append((i,)+req(port, f"/slow.php?s={secs}", timeout=secs+20))
    ts=[threading.Thread(target=one,args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    time.sleep(1.0)
    recs = snap(tag+"_inflight", MASTER, outdir)
    [t.join() for t in ts]
    return recs, sorted(res)

MASTER=int(sys.argv[1]); PORT=int(sys.argv[2]); LABEL=sys.argv[3]; CYC=int(sys.argv[4]) if len(sys.argv)>4 else 3
OUT=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),"evidence","maps")
os.makedirs(OUT,exist_ok=True)
summary=[]
summary.append({"cycle":0,"phase":"baseline","master":MASTER,"children":children(MASTER)})
snap("baseline",MASTER,OUT)
for c in range(1,CYC+1):
    t0=time.time()
    recs,res = exercise(PORT,5,3,OUT,f"c{c}")
    summary.append({"cycle":c,"phase":"inflight","n":len(recs),"pids":[r.get("pid") for r in recs],"req":res,"dt":round(time.time()-t0,2)})
    time.sleep(4)
    snap(f"c{c}_idle",MASTER,OUT)
    kids=children(MASTER); old=set(kids)
    for k in kids:
        try: os.kill(k,9)
        except ProcessLookupError: pass
    time.sleep(0.35)
    kids2=children(MASTER)
    time.sleep(0.2)
    summary.append({"cycle":c,"phase":"killed","killed":sorted(old),"before_035s":sorted(kids2),"after":sorted(children(MASTER))})
    # exercise respawned workers
    time.sleep(0.5)
    recs2,res2 = exercise(PORT,5,3,OUT,f"c{c}_re")
    summary.append({"cycle":c,"phase":"respawn_inflight","pids":[r.get("pid") for r in recs2],"req":res2})
    time.sleep(4)
json.dump(summary,open(os.path.join(OUT,f"summary_{LABEL}.json"),"w"),indent=1)
print(json.dumps(summary,indent=1)[-4000:])
