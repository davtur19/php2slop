#!/bin/sh
# usage: workers.sh <container>
c="$1"
docker exec "$c" sh -c '
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  cmd=$(tr "\0" " " < $p/cmdline 2>/dev/null)
  [ -n "$cmd" ] || continue
  echo "$pid $cmd"
done' | grep -E "php-fpm" | sort -n
