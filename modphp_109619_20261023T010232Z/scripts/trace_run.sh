#!/bin/bash
# usage: trace_run.sh container port body [timeout]
set -u
C=$1; P=$2; B=$3; T=${4:-30}
W=/tmp/opencode/research/modphp_109619_20261023T010232Z
OUT=$W/work/trace_$C
rm -rf $OUT; mkdir -p $OUT
docker exec -i -u root $C sh -c 'cat > /tmp/trace_a1.gdb' < $W/scripts/trace_a1.gdb
PIDS=$(docker exec -u root $C sh -c "ps -eo pid,user,comm | awk '\$2==\"www-data\"{print \$1}'")
echo "children: $PIDS"
i=0
for pid in $PIDS; do
  ( timeout $T docker exec -u root $C gdb -q -p $pid -batch -x /tmp/trace_a1.gdb > $OUT/$pid.out 2>&1 ) &
  i=$((i+1))
done
sleep 2
python3 /tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure/chunked_send.py --port $P --body-file $B --path "/index.php?q0000000=v" --timeout 60 --save-response $OUT/resp.bin
sleep 1.5
pkill -f "gdb -q -p" 2>/dev/null
for pid in $PIDS; do
  echo "=== child $pid"
  grep -E "INIT|SEND_COOKIE|UPDATE|OOM|^#[0-9]" $OUT/$pid.out | head -40
done
