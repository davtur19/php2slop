#!/bin/bash
# measure.sh <label> <binary>
label="$1"; bin="$2"
[ -f "$bin" ] || { echo -e "$label\tMISSING\t$bin"; exit 0; }
ft=$(file -b "$bin" | tr '\t' ' ')
etype=$(readelf -h "$bin" 2>/dev/null | awk -F: '/Type:/{gsub(/^ +/,"",$2);print $2}')
load0=$(readelf -lW "$bin" 2>/dev/null | awk '$1=="LOAD"{print $3; exit}')
stack=$(readelf -lW "$bin" 2>/dev/null | awk '/GNU_STACK/{print $7" "$8}')
relro=$(readelf -lW "$bin" 2>/dev/null | grep -q GNU_RELRO && echo yes || echo no)
bindnow=$(readelf -dW "$bin" 2>/dev/null | grep -q 'BIND_NOW\|FLAGS.*NOW' && echo yes || echo no)
flag1=$(readelf -dW "$bin" 2>/dev/null | awk '/FLAGS_1/{print}')
pie=$(echo "$flag1" | grep -q PIE && echo yes || echo no)
symtab=$(readelf -SW "$bin" 2>/dev/null | grep -q '\.symtab' && echo yes || echo no)
canary=$(nm -D "$bin" 2>/dev/null | grep -c '__stack_chk_fail')
fortify=$(nm -D "$bin" 2>/dev/null | grep -cE '__memcpy_chk|__sprintf_chk|__snprintf_chk')
interp=$(readelf -lW "$bin" 2>/dev/null | awk '/interpreter/{print $NF}' | tr -d ']')
ver=$("$bin" -v 2>/dev/null | head -1)
[ -z "$ver" ] && ver="(cannot exec)"
sapi=$("$bin" -v 2>/dev/null | sed -n '2p')
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
 "$label" "$(basename "$bin")" "$ver" "$etype" "$load0" "$stack" "$relro" "$bindnow" "$pie" "$symtab" "canary=$canary" "fortify=$fortify" "$interp"
