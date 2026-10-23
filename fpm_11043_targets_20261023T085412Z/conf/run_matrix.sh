#!/bin/bash
# Run the public PoC's QSL detection against every (PHP version, config) cell.
D=/tmp/opencode/research/fpm_11043_targets_20261023T085412Z
OUT=$D/logs/matrix_qsl
mkdir -p "$OUT"
cd "$D/poc/phuip-fpizdam" || exit 1

declare -A NAME=(
  [1]=stock-snippet-WP [2]=wordpress-recommended [3]=mediawiki-recommended
  [4]=stock-snippet-MW [5]=wp-recommended-plus-PATHINFO
  [7]=fpm-docs-WP [8]=fpm-docs-MW
)
# version: base host offset
for pair in "7.3.9:19101" "7.3.10:19111" "7.3.11:19121" "7.2.23:19131" "7.2.24:19141" "8.4.26:19151"; do
  ver=${pair%%:*}; base=${pair##*:}
  for slot in 1 2 3 4 5 7 8; do
    url="http://127.0.0.1:$((base + slot - 1))/index.php"
    log="$OUT/${ver}_${NAME[$slot]}.txt"
    echo "### $ver $url" | tee "$log"
    timeout 240 ./phuip-fpizdam --only-qsl "$url" >>"$log" 2>&1
    echo "rc=$?" >>"$log"
    grep -E 'Base status|probably vulnerable|no qsl candidates|returned error' "$log" | tail -3
  done
done
