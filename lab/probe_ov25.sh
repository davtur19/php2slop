#!/bin/bash
# probe B: 25-file body (stock max_file_uploads=20) through the CGI jig.
# Validates machinery handling of files beyond the limit (events still fired).
set -u
BASE=/tmp/opencode/realapps/side
CGI="$1"; SID="$2"
BODY="$BASE/tmp/ov25_$SID.bin"
python3 - "$BODY" "$SID" <<'PY'
import sys
sys.path.insert(0, "/tmp/opencode/realapps/side")
from gen_shape import part_header, BOUND
sid = sys.argv[2]
out = part_header("field", "PHP_SESSION_UPLOAD_PROGRESS")
out += b"ov25\r\n"
for i in range(25):
    out += part_header("file", f"file{i}", f"F{i}" + "x" * 40)
    out += b"U" * 64 + b"\r\n"
out += b"--" + BOUND.encode() + b"--\r\n"
open(sys.argv[1], "wb").write(out)
print("body bytes:", len(out))
PY
rm -f "$BASE/sess/sess_$SID"
TOT=$(stat -c%s "$BODY")
env REDIRECT_STATUS=200 REQUEST_METHOD=POST \
    CONTENT_TYPE='multipart/form-data; boundary=BOUND' \
    CONTENT_LENGTH=$TOT SCRIPT_FILENAME="$BASE/empty.php" QUERY_STRING='' \
    HTTP_COOKIE="PHPSESSID=$SID" GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 \
    SERVER_NAME=lab "$CGI" -d cgi.force_redirect=0 -d "session.save_path=$BASE/sess" \
    -d session.upload_progress.cleanup=0 \
    < "$BODY" > "$BASE/ov25_$SID.out" 2> "$BASE/ov25_$SID.err"
RC=$?
SZ=$(stat -c%s "$BASE/sess/sess_$SID" 2>/dev/null || echo NO)
AH=$(grep -c AddressSanitizer "$BASE/ov25_$SID.err" 2>/dev/null || true)
NFILES=$(grep -o 'file_name' "$BASE/sess/sess_$SID" 2>/dev/null | wc -l)
NERR=$(grep -o 'error";i:[0-9]*' "$BASE/sess/sess_$SID" 2>/dev/null | grep -c 'i:[1-9]')
echo "ov25 sid=$SID exit=$RC sess=$SZ file_name=$NFILES with_error=$NERR asan_hit=$AH"
