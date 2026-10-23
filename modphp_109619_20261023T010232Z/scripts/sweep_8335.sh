#!/usr/bin/env bash
# Sweep 8.3.35 A1 burners (parts=859) looking for send_cookie=1 (END-phase OOM)
cd /tmp/opencode/research/modphp_109619_20261023T010232Z
P=/tmp/opencode/research/9bie_update_20261022T115026Z/code/repo/pure
QS="/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
for B in $(seq 20 55); do
  echo "### burners=$B"
  timeout 120 python3 scripts/probe_state.py --container m109-8335 --port 18703 \
    --path "$QS" --gen "python3 $P/mk_a1.py --out \$OUT --parts 859 --burners $B" 2>&1 | tail -1
done
echo DONE
