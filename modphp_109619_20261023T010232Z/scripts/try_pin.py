import sys, time
sys.path.insert(0,"/tmp/opencode/research/modphp_109619_20261023T010232Z/scripts")
from pin import Conn
port=int(sys.argv[1]); a1=sys.argv[2]; b1=sys.argv[3]
a=open(a1,'rb').read(); b=open(b1,'rb').read()
c=Conn("127.0.0.1", port, timeout=300)
t=time.time(); r1=c.request("POST","/index.php?q0000000=v",a,chunked=True,ctype="multipart/form-data; boundary="+"C"*10)
print("A1", r1.get("status"), len(r1.get("body",b"")), "closed",r1.get("closed"), "%.2fs"%(time.time()-t))
if r1.get("closed"):
    print("connection closed after A1 -> no pinning"); sys.exit(1)
t=time.time(); r2=c.request("POST","/index.php",b,chunked=True,ctype="multipart/form-data; boundary="+"C"*10)
body=r2.get("body",b"")
print("B1", r2.get("status"), len(body), "closed",r2.get("closed"), "%.2fs"%(time.time()-t))
print("has Set-Cookie:", b"Set-Cookie: PHPSESSID=" in body)
c.close()
