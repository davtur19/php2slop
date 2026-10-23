#!/usr/bin/env python3
"""Sweep A2 filler count; measure hsv offset / ref rc / ZendMM page state."""
import json, os, subprocess, sys, time
D="/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
sys.path.insert(0, os.path.join(D,"scripts"))
import chain84 as C
CNAME="m109-d8424pkg"; PORT=18740; LOG="/var/log/apache2/p2s-access.log"
def sh(cmd): return subprocess.run(cmd, capture_output=True, text=True)
def lines(): return sh(["docker","exec",CNAME,"sh","-c","cat %s 2>/dev/null"%LOG]).stdout.splitlines()
def state(pid):
    r=sh(["docker","exec",CNAME,"gdb","-batch","-q","-p",str(pid),"-x","/tmp/deb_mm.gdb"])
    out={}
    for l in r.stdout.splitlines():
        if l.startswith(("MMSTATE","PSSTATE","REF ","PAGE","CHUNK","BIN ","FREELIST")):
            out.setdefault("lines",[]).append(l)
            if l.startswith("PSSTATE"):
                for kv in l.split()[1:]:
                    k,v=kv.split("=",1); out[k]=v
    return out
fillers=[int(x) for x in sys.argv[1:]] or [0,1,2,3,4,5,6,8,10,12,16,20,24,32]
sh(["docker","cp",os.path.join(D,"scripts/deb_mm.gdb"),CNAME+":/tmp/deb_mm.gdb"])
res=[]
for f in fillers:
    sh(["docker","restart",CNAME]); time.sleep(1.6)
    n=len(lines())
    body=C.a2_body(fillers=f)
    resp=C.send_plain(PORT,"/index.php",body)
    time.sleep(0.35)
    lg=lines()[n:]
    pid=int(lg[-1].split()[0]) if lg else None
    st=state(pid) if pid else {}
    rec={"fillers":f,"pid":pid,"status":resp.split(b"\r\n",1)[0].decode("latin1"),
         "hsvoff":st.get("hsvoff"),"hsvtype":st.get("hsvtype"),"rc":st.get("rc"),
         "page":None,"ref":None}
    for l in st.get("lines",[]):
        if l.startswith("PAGE"): rec["page"]=l
        if l.startswith("REF "): rec["ref"]=l
    res.append(rec)
    print("fillers=%-3d pid=%s %s hsvoff=%s type=%s %s page=%s" % (
        f,pid,rec["status"],rec["hsvoff"],rec["hsvtype"],rec["ref"],rec["page"]), flush=True)
json.dump(res, open(os.path.join(D,"out/debshift.json"),"w"), indent=1)
