#!/usr/bin/env bash
EXP=/home/davide/ailocal/php/zerodays_1020/build_asan
export LD_LIBRARY_PATH=/tmp/opencode/realapps/onig-6.9.10/src/.libs:/tmp/opencode/realapps/icu-out/lib
export USE_ZEND_ALLOC=1
export ASAN_OPTIONS=abort_on_error=0:exitcode=21:malloc_context_size=10
rm -rf /tmp/opencode/realapps/sess_gdb; mkdir -p /tmp/opencode/realapps/sess_gdb
gdb -q -batch -x /tmp/opencode/realapps/side/php2shell/runs/diag9_gdb.cmd \
  --args $EXP/sapi/cli/php -S 127.0.0.1:28847 -d memory_limit=8M -d session.upload_progress.enabled=1 \
  -d session.upload_progress.cleanup=0 \
  -t /tmp/opencode/realapps/asanroot \
  > /tmp/opencode/realapps/side/php2shell/runs/diag9_gdb.log 2>&1 &
GP=$!
for i in 1 2 3 4 5 6; do
  sleep 3
  OUT=$(curl -s -m 4 http://127.0.0.1:28847/index.php 2>/dev/null)
  echo "t+$((i*3))s precheck: ${OUT:0:40} rc=$?"
  [ -n "$OUT" ] && break
done
python3 /tmp/opencode/realapps/side/php2shell/runs/diag7_driver28847.py 2>/dev/null || { sed 's/28846/28847/' /tmp/opencode/realapps/side/php2shell/runs/diag6_driver.py > /tmp/opencode/realapps/side/php2shell/runs/diag7_driver28847.py; python3 /tmp/opencode/realapps/side/php2shell/runs/diag7_driver28847.py; }
sleep 6
GPALIVE=$(kill -0 $GP 2>/dev/null && echo yes || echo no)
echo "gdb_alive=$GPALIVE"
[ "$GPALIVE" = "yes" ] && kill -INT $GP; sleep 2; kill -9 $GP 2>/dev/null
echo "=== gdb log hits ==="
grep -E "INIT\]|DEST\]|SEGV|Signal|Inferior|Program" /tmp/opencode/realapps/side/php2shell/runs/diag9_gdb.log | head -36
echo "=== last lines ==="
tail -8 /tmp/opencode/realapps/side/php2shell/runs/diag9_gdb.log
