#!/usr/bin/env bash
EXP=/home/davide/ailocal/php/zerodays_1020/build_asan
export LD_LIBRARY_PATH=/tmp/opencode/realapps/onig-6.9.10/src/.libs:/tmp/opencode/realapps/icu-out/lib
export USE_ZEND_ALLOC=1
export ASAN_OPTIONS=abort_on_error=0:exitcode=21:malloc_context_size=10
gdb -q -batch -x /tmp/opencode/realapps/side/php2shell/runs/diag6_gdb.cmd \
  --args $EXP/sapi/cli/php -S 127.0.0.1:28846 -d memory_limit=8M -d session.upload_progress.enabled=1 \
  -d session.upload_progress.cleanup=0 -d session.save_path=/tmp/opencode/realapps/sess_gdb \
  -t /tmp/opencode/realapps/asanroot \
  > /tmp/opencode/realapps/side/php2shell/runs/diag7_gdb.log 2>&1 &
GP=$!
sleep 7
python3 /tmp/opencode/realapps/side/php2shell/runs/diag6_driver.py
sleep 8
GPALIVE=$(kill -0 $GP 2>/dev/null && echo yes || echo no)
echo "gdb_alive=$GPALIVE"
if [ "$GPALIVE" = "yes" ]; then kill -INT $GP; fi
sleep 2
kill -9 $GP 2>/dev/null
echo "=== gdb log (filtered) ==="
grep -E "INIT\]|DEST\]|Breakpoint|SEGV|Inferior|Program|exited" /tmp/opencode/realapps/side/php2shell/runs/diag7_gdb.log | head -30
