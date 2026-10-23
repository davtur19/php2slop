#!/usr/bin/env python3
"""Scan A1 tail counts for a version; record post-A1 state."""
import argparse, json, os, subprocess, sys, time, socket
HERE=os.path.dirname(os.path.abspath(__file__))
W=os.environ.get("W","/tmp/opencode/research/modphp_109619_20261023T010232Z")
REPO="/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo"

def sh(c,**kw): return subprocess.run(c,shell=True,capture_output=True,text=True,**kw)

def probe(container, port, gen, key, out):
    body=os.path.join(W,"work","scan_%s.bin"%key)
    r=sh(gen.replace("$OUT",body))
    if r.returncode: return {"key":key,"gen_error":r.stderr[-300:]}
    r=sh(f"python3 {HERE}/probe_state.py --container {container} --port {port} --body {body}")
    try: st=json.loads(r.stdout.strip().splitlines()[-1])
    except Exception: st={"raw":(r.stdout+r.stderr)[-400:]}
    st["key"]=key
    open(out,"a").write(json.dumps(st,sort_keys=True)+"\n")
    return st

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--container",required=True); ap.add_argument("--port",type=int,required=True)
    ap.add_argument("--gen",required=True,help="template with $OUT; use {tail} and {big} placeholders")
    ap.add_argument("--tails",default="0-40")
    ap.add_argument("--bigs",default="78")
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    def rng(s):
        if "-" in s and ":" not in s:
            a,b=s.split("-"); return list(range(int(a),int(b)+1))
        return [int(x) for x in s.split(",")]
    ok=[]
    for big in rng(args.bigs):
      for tail in rng(args.tails):
        gen=args.gen.replace("{tail}",str(tail)).replace("{big}",str(big))
        st=probe(args.container,args.port,gen,"t%d_b%d"%(tail,big),args.out)
        sc=st.get("send_cookie"); status=st.get("status"); idoff=st.get("idoff")
        hit = sc=="1" and status=="2" and idoff not in (None,"NULL")
        if hit: ok.append((tail,big,idoff))
        print("tail=%s big=%s -> sc=%s status=%s idoff=%s %s"%(tail,big,sc,status,idoff,"HIT" if hit else ""),flush=True)
        if len(ok)>=3: break
      if len(ok)>=3: break
    print("HITS",ok)

if __name__=="__main__": sys.exit(main())
