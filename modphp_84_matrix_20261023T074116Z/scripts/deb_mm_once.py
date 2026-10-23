#!/usr/bin/env python3
import os, subprocess, sys, time
D="/tmp/opencode/research/modphp_84_matrix_20261023T074116Z"
sys.path.insert(0, os.path.join(D,"scripts"))
import chain84 as C
CNAME="m109-d8424pkg"; PORT=18740; LOG="/var/log/apache2/p2s-access.log"
def sh(cmd): return subprocess.run(cmd, capture_output=True, text=True)
def lines(): return sh(["docker","exec",CNAME,"sh","-c","cat %s 2>/dev/null"%LOG]).stdout.splitlines()
print("restart", flush=True)
sh(["docker","restart",CNAME]); time.sleep(2.0)
n=len(lines())
body=C.a2_body()
print("a2 bytes", len(body), flush=True)
r=C.send_plain(PORT, "/index.php", body)
time.sleep(0.5)
lg=lines()[n:]
print("A2 resp", r.split(b"\r\n",1)[0], "log", lg, flush=True)
pid=int(lg[-1].split()[0]) if lg else None
print("pid", pid, flush=True)
sh(["docker","cp",os.path.join(D,"scripts/deb_mm.gdb"),CNAME+":/tmp/deb_mm.gdb"])
p=sh(["docker","exec",CNAME,"gdb","-batch","-q","-p",str(pid),"-x","/tmp/deb_mm.gdb"])
out=p.stdout
for l in out.splitlines():
    if l.startswith(("MMSTATE","PSSTATE","REF ","PAGE","  map","FREEMAP","CHUNK","BIN ","FREELIST","NO_HSV")):
        print(l, flush=True)
print("--- stderr tail", p.stderr.strip().splitlines()[-3:], flush=True)
