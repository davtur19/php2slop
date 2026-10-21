#!/usr/bin/env bash
EXP=/home/davide/ailocal/php/zerodays_1020/build_asan
export LD_LIBRARY_PATH=/tmp/opencode/realapps/onig-6.9.10/src/.libs:/tmp/opencode/realapps/icu-out/lib
run_one() {
  if [ -n "$2" ]; then export USE_ZEND_ALLOC="$2"; else unset USE_ZEND_ALLOC; fi
  export ASAN_OPTIONS=abort_on_error=0:exitcode=21:log_path=/tmp/opencode/realapps/logs/asanf:malloc_context_size=12
  rm -f /tmp/opencode/realapps/logs/asanf.* /tmp/opencode/realapps/logs/asan-phps.log
  setsid $EXP/sapi/cli/php -S 127.0.0.1:28842 -d memory_limit=8M -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0 -t /tmp/opencode/realapps/asanroot >/tmp/opencode/realapps/logs/asan-phps.log 2>&1 &
  sleep 2
  echo "== [$1] USE_ZEND_ALLOC='$2' up:", "$(curl -s -m 5 http://127.0.0.1:28842/index.php)"
  python3 /tmp/opencode/realapps/side/php2shell/runs/diag5_asan.py
  echo "== [$1] ASAN writes:"
  grep -h "AddressSanitizer\|#0\|#1\|#2" /tmp/opencode/realapps/logs/asanf.* 2>/dev/null | grep -v '^--' | head -12 || true
  if [ -z "$(ls /tmp/opencode/realapps/logs/asanf.* 2>/dev/null)" ]; then echo none; fi
  kill $(pgrep -f 'sapi/cli/php -S') 2>/dev/null; sleep 1
}
run_one alloc_malloc 0
run_one alloc_mm 1
echo DONE
