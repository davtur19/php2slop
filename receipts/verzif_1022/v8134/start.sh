#!/bin/bash
set -e
LAB="$(cd "$(dirname "$0")" && pwd)"
BIN="/tmp/opencode/research/veroff_20261021_215718/build/php-8.1.34/sapi/fpm/php-fpm"
unset USE_ZEND_ALLOC USE_TRACKED_ALLOC ASAN_OPTIONS ZEND_ALLOC_PRINT_LEAKS LD_PRELOAD
mkdir -p "$LAB/run" "$LAB/log" "$LAB/sessions"
rm -f "$LAB/run/php-fpm.pid"
( cd "$LAB" && exec setarch "$(uname -m)" -R "$BIN" --fpm-config "$LAB/conf/fpm.conf" ) >"$LAB/log/master.out" 2>&1
sleep 1
MASTER=$(cat "$LAB/run/php-fpm.pid")
CHILD=""
for i in $(seq 1 25); do
  CHILD=$(pgrep -P "$MASTER" | head -1)
  [ -n "$CHILD" ] && break
  sleep 0.2
done
echo "master=$MASTER child=$CHILD"
echo "$MASTER" > "$LAB/run/master.pid"
echo "$CHILD" > "$LAB/run/child.pid"
