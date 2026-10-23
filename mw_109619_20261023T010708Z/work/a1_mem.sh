#!/bin/bash
set -u
C=$1; P=$2; A=$3; O=$4
T=$(cat /tmp/opencode/.mw109619_current)
mkdir -p "$O"
docker restart "$C" >/dev/null; sleep 2.5
PID=$(docker exec "$C" ps -o pid,user,args -C apache2 | awk '$2=="www-data"{print $1; exit}')
echo "CHILD $PID"
docker exec -i "$C" sh -c 'cat > /tmp/mem.gdb' <<'GDB'
set pagination off
set confirm off
break php_url_encode
commands
  silent
  printf "URLENCODE len=%lu\n", $rsi
  if $rsi <= 128
    printf "MEMUSAGE %lu\n", (unsigned long) zend_memory_usage(0)
    bt 4
  end
  continue
end
continue
GDB
docker exec -d "$C" sh -c "gdb -q -p $PID -batch -x /tmp/mem.gdb > /tmp/mem.out 2>&1"
sleep 1
docker exec "$C" cat /proc/$PID/status | grep TracerPid
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
    while True:
        c=s.recv(65536)
        if not c: break
        out.extend(c)
except OSError: pass
s.close()
print("A1", out.split(b"\r\n",1)[0].decode('latin1','replace'), len(out))
PY
sleep 1
docker exec "$C" sh -c 'kill -INT $(pidof gdb) 2>/dev/null || true'
sleep 0.5
echo "== gdb output =="
docker exec "$C" cat /tmp/mem.out
