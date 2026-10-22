#!/usr/bin/env bash
set -eu
LAB=/tmp/opencode/research/drupal_fpm_20261022T013000Z
BIN=/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
export LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib
pidfile="$LAB/run/php-fpm.pid"
stop() {
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill -QUIT "$pid" 2>/dev/null || true
      for i in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
      done
      if kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid" 2>/dev/null || true; sleep 0.5; fi
      if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; sleep 0.5; fi
    fi
  fi
  rm -f "$pidfile" "$LAB/run/php-fpm-lab.sock" "$LAB/run/php-fpm-drupal.sock"
}
start() {
  rm -f "$pidfile" "$LAB/run/php-fpm-lab.sock" "$LAB/run/php-fpm-drupal.sock"
  "$BIN" -y "$LAB/conf/fpm.conf"
  for i in $(seq 1 50); do
    [ -s "$pidfile" ] && [ -S "$LAB/run/php-fpm-lab.sock" ] && break
    sleep 0.2
  done
  pid=$(cat "$pidfile")
  echo "master=$pid"
  ps -o pid,ppid,stat,lstart,cmd -p "$pid"
}
case "${1:-}" in
  stop) stop ;;
  start) start ;;
  restart) stop; start ;;
  status)
    pid=$(cat "$pidfile" 2>/dev/null || echo 0)
    ps -o pid,ppid,stat,etime,cmd -p "$pid" || true
    ps -eo pid,ppid,stat,cmd | awk -v m="$pid" '$2==m{print}'
    ;;
  *) echo "usage: $0 start|stop|restart|status" >&2; exit 2 ;;
esac
