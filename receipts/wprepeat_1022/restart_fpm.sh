#!/bin/bash
set -euo pipefail
STACK=/tmp/opencode/research/realchain_20261022T015900Z
CONF=$STACK/conf/fpm.conf
PIDF=$STACK/run/php-fpm.pid
SOCK=$STACK/run/php-fpm.sock
BIN=/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
LIB=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib
if [ -f "$PIDF" ]; then
  old=$(cat "$PIDF" 2>/dev/null || true)
  if [ -n "${old:-}" ] && [ -d "/proc/$old" ]; then
    if tr '\0' ' ' < "/proc/$old/cmdline" 2>/dev/null | grep -q "realchain_20261022T015900Z/conf/fpm.conf"; then
      echo "stopping old master $old"
      kill -TERM "$old" 2>/dev/null || true
      for i in $(seq 1 150); do kill -0 "$old" 2>/dev/null || break; sleep 0.2; done
      if kill -0 "$old" 2>/dev/null; then echo "force killing $old"; kill -KILL "$old" 2>/dev/null || true; sleep 0.5; fi
    else
      echo "pid file $old is not the realchain master; leaving it"
    fi
  fi
fi
rm -f "$SOCK" "$PIDF"
env LD_LIBRARY_PATH="$LIB" "$BIN" --fpm-config "$CONF"
for i in $(seq 1 150); do [ -s "$PIDF" ] && break; sleep 0.1; done
master=$(cat "$PIDF")
child=""
for i in $(seq 1 150); do
  child=$(pgrep -P "$master" -f 'php-fpm: pool wp' | head -1 || true)
  [ -n "${child:-}" ] && break
  sleep 0.1
done
echo "master=$master worker=${child:-none}"
ss -ltnp 2>/dev/null | grep 28893 || true
