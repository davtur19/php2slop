#!/usr/bin/env bash
EXP=/home/davide/ailocal/php/zerodays_1020/build_asan
export LD_LIBRARY_PATH=/tmp/opencode/realapps/onig-6.9.10/src/.libs:/tmp/opencode/realapps/icu-out/lib
export USE_ZEND_ALLOC=1
export ASAN_OPTIONS=abort_on_error=0:exitcode=21:malloc_context_size=10
rm -f /tmp/sess_abcdefgh
gdb -q -batch -x "$S2/diag9_gdb.cmd" \
  --args $EXP/sapi/cli/php -S 127.0.0.1:28848 -d memory_limit=8M -d session.upload_progress.enabled=1 \
  -d session.upload_progress.cleanup=0 \
  -t /tmp/opencode/realapps/asanroot \
  > /tmp/opencode/realapps/side/php2shell/runs/diag10_gdb.log 2>&1 &
GP=$!
for i in 1 2 3 4 5; do sleep 3; OUT=$(curl -s -m 4 http://127.0.0.1:28848/index.php 2>/dev/null); [ -n "$OUT" ] && break; done
sed 's/28846/28848/' /tmp/opencode/realapps/side/php2shell/runs/diag6_driver.py > /tmp/opencode/realapps/side/php2shell/runs/diag10_driver.py
python3 /tmp/opencode/realapps/side/php2shell/runs/diag10_driver.py
sleep 6
GPALIVE=$(kill -0 $GP 2>/dev/null && echo yes || echo no)
echo "gdb_alive=$GPALIVE"
[ "$GPALIVE" = "yes" ] && kill -INT $GP; sleep 2; kill -9 $GP 2>/dev/null
echo "=== events =="
grep -E "Accepted|Closing|\[FRESH\]|\[REUSE\]|\[DESTROY\]|SEGV|Signal" /tmp/opencode/realapps/side/php2shell/runs/diag10_gdb.log | head -50
echo "=== on-disk sess file =="
ls -la /tmp/sess_abcdefgh 2>/dev/null
