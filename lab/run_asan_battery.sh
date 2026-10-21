#!/bin/bash
# ASAN battery: run every attack shape against ASAN php-cgi; any UAF => report.
set -u
BASE=/tmp/opencode/realapps/side
CGI=/home/davide/ailocal/php/zerodays_1020/install_asan/bin/php-cgi
[ -x "$CGI" ] || { echo "ASAN php-cgi missing"; exit 1; }
mkdir -p "$BASE/asan_reports"
export ASAN_OPTIONS='detect_leaks=0:log_path=/tmp/opencode/realapps/side/asan_reports/redir_color:allocator_may_return_null=1'
export ASAN_OPTIONS='detect_leaks=0:allocator_may_return_null=1'   # log to stderr instead, simpler
EP=$BASE/empty.php

run_one() {
  local b=$1 clen=$2 sid=$3 pref=$4
  rm -f "$BASE/sess/sess_$sid"
  env REDIRECT_STATUS=200 REQUEST_METHOD=POST \
      CONTENT_TYPE='multipart/form-data; boundary=BOUND' \
      CONTENT_LENGTH=$clen \
      SCRIPT_FILENAME=$EP QUERY_STRING='' HTTP_COOKIE="PHPSESSID=$sid" \
      GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 SERVER_NAME=lab \
      $CGI -d cgi.force_redirect=0 -d session.save_path=$BASE/sess \
      < "$b" > "$pref.out" 2> "$pref.err"
  local rc=$?
  local sz
  sz=$(stat -c%s "$BASE/sess/sess_$sid" 2>/dev/null || echo NOFILE)
  printf '%-6s exit=%-4s sessfile=%-6s errB=%s\n' "$pref" "$rc" "$sz" "$(stat -c%s $pref.err)"
}

echo "=== fast shapes ==="
run_one "$BASE/body_S1.bin" 123399 mach-shape-001 "$BASE/asan_S1"
run_one "$BASE/body_S2.bin"  3185  mach-shape-002 "$BASE/asan_S2"
run_one "$BASE/body_S4.bin"   239  mach-shape-004 "$BASE/asan_S4"
run_one "$BASE/body_S5.bin" 31281  mach-shape-005 "$BASE/asan_S5"

echo "=== paced S3 (40k/s) with machinery plant first (S4 content on same sid) ==="
python3 "$BASE/slowfeed.py" "$BASE/body_S3.bin" 40000 | \
  env REDIRECT_STATUS=200 REQUEST_METHOD=POST \
      CONTENT_TYPE='multipart/form-data; boundary=BOUND' \
      CONTENT_LENGTH=1209300 \
      SCRIPT_FILENAME=$EP QUERY_STRING='' HTTP_COOKIE='PHPSESSID=mach-shape-003' \
      GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 SERVER_NAME=lab \
      $CGI -d cgi.force_redirect=0 -d session.save_path=$BASE/sess \
      > "$BASE/asan_S3.out" 2> "$BASE/asan_S3.err"
echo "S3 exit=$? err=$(stat -c%s $BASE/asan_S3.err) sess=$(stat -c%s $BASE/sess/sess_mach-shape-003 2>/dev/null)"

echo "=== greps of any asan reports ==="
grep -c 'AddressSanitizer' "$BASE"/asan_*.err 2>/dev/null
ls -la "$BASE/asan_reports/" 2>/dev/null
