#!/bin/bash
set -e
LAB=/tmp/opencode/research/g6zif_20261021T222434Z
BIN=/home/davide/ailocal/php/zerodays_1020/build_plainpie/sapi/fpm/php-fpm
unset USE_ZEND_ALLOC USE_TRACKED_ALLOC ASAN_OPTIONS ZEND_ALLOC_PRINT_LEAKS
mkdir -p "$LAB/run" "$LAB/log" "$LAB/sessions"
rm -f "$LAB/run/php-fpm.pid"
( cd "$LAB" && exec setarch "$(uname -m)" -R "$BIN" --fpm-config "$LAB/conf/fpm.conf" )   >"$LAB/log/master.out" 2>&1
sleep 1
MASTER=$(cat "$LAB/run/php-fpm.pid")
CHILD=$(pgrep -P "$MASTER" | head -1)
echo "master=$MASTER child=$CHILD"
tr '\0' '\n' < "/proc/$CHILD/environ" | grep -E "USE_ZEND_ALLOC|USE_TRACKED_ALLOC|ASAN_OPTIONS|LD_PRELOAD" || true
echo "$MASTER" > "$LAB/run/master.pid"
echo "$CHILD" > "$LAB/run/child.pid"
