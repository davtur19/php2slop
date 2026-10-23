#!/usr/bin/env python3
import json, os, sys
def hx(x): return None if x is None else hex(x)
def parse(pid):
    try:
        lines=open(f"/proc/{pid}/maps").read().splitlines()
    except OSError as e:
        return {"pid":pid,"error":str(e)}
    files={}; heap=None; stack=None; anon_rw=[]
    try: exe=os.path.basename(os.readlink(f"/proc/{pid}/exe"))
    except OSError: exe=None
    for ln in lines:
        f=ln.split(None,5)
        if len(f)<5: continue
        rng,perm,off,dev,ino=f[:5]
        path=f[5] if len(f)>5 else ""
        try:
            lo,hi=[int(x,16) for x in rng.split("-")]
        except ValueError: continue
        if path=="[heap]": heap=[lo,hi]; continue
        if path=="[stack]": stack=[lo,hi]; continue
        if path.startswith("["): continue
        if path:
            if path not in files or lo<files[path][0]: files[path]=(lo,int(off,16))
        if perm=="rw-p": anon_rw.append([lo,hi])
    big=sorted([[r[0],r[1]-r[0]] for r in anon_rw if r[1]-r[0]>=512*1024])
    chunks=[x[0] for x in big if 2*1024*1024 <= x[1] < 8*1024*1024]
    return {"pid":pid,"exe":exe,
            "bases":{os.path.basename(p):hx(b) for p,(b,o) in files.items()},
            "heap":[hx(x) for x in heap] if heap else None,
            "stack":[hx(x) for x in stack] if stack else None,
            "zend_chunks_2m":[hx(x) for x in chunks],"big_anon_rw":[[hx(a),b] for a,b in big],
            "anon_rw_count":len(anon_rw),
            "anon_rw_min":hx(min((r[0] for r in anon_rw),default=None)),
            "anon_rw_max":hx(max((r[1] for r in anon_rw),default=None))}
if __name__=="__main__":
    for pid in sys.argv[1:]: print(json.dumps(parse(int(pid))))
