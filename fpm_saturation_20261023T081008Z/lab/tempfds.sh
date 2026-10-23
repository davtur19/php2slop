#!/bin/sh
n=0; t=0
for fd in /proc/[0-9]*/fd/[0-9]*; do
  l=$(readlink "$fd" 2>/dev/null) || continue
  case "$l" in
    *client_temp*)
      p=${fd%/fd/*}; f=${fd##*/}
      s=$(stat -Lc %s "$p/fd/$f" 2>/dev/null)
      n=$((n+1)); t=$((t+${s:-0}))
      ;;
  esac
done
echo "$n $t"
