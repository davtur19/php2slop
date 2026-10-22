#!/bin/bash
set -u
D=/tmp/opencode/research/wprepeat_20261022T004227Z
STACK=/tmp/opencode/research/realchain_20261022T015900Z
W="$1"; SID="$2"; TAG="$3"
LOG="$D/run1/${TAG}.gdb"
RESP="$D/run1/${TAG}.resp"
stdbuf -oL -eL gdb -q -batch -x "$D/gdb/leak.cmd" -p "$W" > "$LOG" 2>&1 &
GPID=$!
sleep 2
if ! kill -0 "$GPID" 2>/dev/null; then echo "gdb exited early"; tail -20 "$LOG"; exit 2; fi
python3 "$D/scripts_trigger.py" "$SID" x /hextrigger.php > "$RESP" 2>&1 || true
for i in $(seq 1 300); do kill -0 "$GPID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$GPID" 2>/dev/null; then echo "gdb still running; killing"; kill -9 "$GPID" 2>/dev/null; fi
wait "$GPID" 2>/dev/null
echo "=== leak gdb"; grep -E 'DECODE|SREAL|SETVAR|SIGSEGV|SIGABRT|LEAK_TWO|ARMED' "$LOG"
echo "=== trigger resp"; cat "$RESP"
