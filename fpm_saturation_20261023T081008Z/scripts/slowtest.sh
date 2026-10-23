#!/usr/bin/env bash
# usage: slowtest.sh NAME WEBPORT WEBCTR MODE CL RATE HOLD N PATH [FINISH]
set -u
BASE=$(cat /tmp/opencode/.fpm_sat_current); cd "$BASE"
NAME=$1; PORT=$2; CTR=$3;
LOGDIR="$BASE/logs/${CTR#fsat-}" MODE=$4; CL=$5; RATE=$6; HOLD=$7; N=$8; PATHQ=$9; FINISH=${10:-}
OUT="evidence/$NAME"; mkdir -p "$OUT"; rm -f "$OUT"/status.jsonl "$OUT"/probe.jsonl "$OUT"/estab.txt "$OUT"/tempfds.txt "$OUT"/slow.jsonl
STATUS_URL=${STATUS_URL:-http://127.0.0.1:18822/status?json}
NL="$LOGDIR/access.log"
FPMACC=${FPMACC:-$BASE/logs/fpm5/access.log}
FPMC=${FPMC:-fsat-fpm5}
docker exec "$FPMC" sh -c 'rm -f /tmp/reqlog.txt' 2>/dev/null
wc -l < "$NL" > "$OUT/nginx_before.n"; wc -l < "$FPMACC" > "$OUT/fpmacc_before.n"
curl -s -m 5 "$STATUS_URL" > "$OUT/status_before.json"
docker logs "$FPMC" > "$OUT/fpm_before.log" 2>&1
python3 scripts/lab.py status --url "$STATUS_URL" --interval 0.5 --timeout 1.5 --out "$OUT/status.jsonl" & SPID=$!
python3 scripts/lab.py probe --port "$PORT" --path /index.php --interval 0.2 --timeout 5 --out "$OUT/probe.jsonl" & PPID2=$!
( while true; do ss -Htn state established "( sport = :$PORT )" 2>/dev/null | wc -l; sleep 0.4; done > "$OUT/estab.txt" ) & SSID=$!
( while true; do docker exec -u nginx "$CTR" sh /var/www/html/tempfds.sh 2>/dev/null; sleep 0.5; done > "$OUT/tempfds.txt" ) & DSID=$!
if [ "$FINISH" = "finish" ]; then FIN="--finish"; else FIN=""; fi
python3 scripts/lab.py slow --port "$PORT" --path "$PATHQ" --mode "$MODE" --cl "$CL" --rate "$RATE" --hold "$HOLD" --n "$N" $FIN --out "$OUT/slow.jsonl" | tee "$OUT/slow_stdout.txt"
kill $SPID $PPID2 $SSID $DSID 2>/dev/null; wait 2>/dev/null
docker logs "$FPMC" > "$OUT/fpm_after.log" 2>&1
curl -s -m 10 "$STATUS_URL" > "$OUT/status_after.json"
echo "=== FPM status before/after (accepted delta, high-water) ==="
python3 - "$OUT" <<'PY'
import json,sys
out=sys.argv[1]
b=json.load(open(out+'/status_before.json')); a=json.load(open(out+'/status_after.json'))
print('accepted_conn_delta', a.get('accepted conn',0)-b.get('accepted conn',0))
for k in ['max listen queue','max active processes','max children reached','slow requests']:
    print(f'{k}: before={b.get(k)} after={a.get(k)}')
print('listen queue after', a.get('listen queue'))
# in-test samples
rs=[json.loads(l) for l in open(out+'/status.jsonl')]
oks=[r['body'] for r in rs if 'body' in r]
act=[x.get('active processes') for x in oks]
print('status samples ok=%d err=%d active_min=%s active_max=%s' % (len(oks),len(rs)-len(oks),min(act) if act else None,max(act) if act else None))
PY
echo "=== probe latency ==="; python3 - "$OUT" <<'PY'
import json,sys
rs=[json.loads(l) for l in open(sys.argv[1]+'/probe.jsonl')]
ds=sorted(r['dt'] for r in rs if 'dt' in r); errs=sum(1 for r in rs if 'err' in r)
def p(q): return ds[min(len(ds)-1,int(len(ds)*q))] if ds else 0
print('n=%d err=%d p50=%.3f p95=%.3f max=%.3f' % (len(rs),errs,p(.5),p(.95),ds[-1] if ds else 0))
PY
echo "=== estab max=$(sort -n "$OUT/estab.txt" | tail -1) temp_fds_max=$(awk '{print $1}' "$OUT/tempfds.txt" | sort -n | tail -1) temp_buffered_max_bytes=$(awk '{print $2}' "$OUT/tempfds.txt" | sort -n | tail -1) ==="
echo "=== reqlog entries: $(docker exec "$FPMC" sh -c 'wc -l < /tmp/reqlog.txt 2>/dev/null' || echo 0) ==="
echo "=== fpm logprobe access: now=$(grep -c '/logprobe' "$FPMACC" || true) ==="
echo "=== exits delta=$(( $(grep -c 'exited with code 70' "$OUT/fpm_after.log") - $(grep -c 'exited with code 70' "$OUT/fpm_before.log") )) signals=$(diff <(cat "$OUT/fpm_before.log") <(cat "$OUT/fpm_after.log") | grep -cE 'signal 11|SIGSEGV|corrupted') ==="
echo "=== nginx codes ==="
python3 - "$OUT" "$NL" <<'PY'
import sys,collections
out,nl=sys.argv[1],sys.argv[2]
b=int(open(out+'/nginx_before.n').read())
lines=open(nl).read().splitlines()[b:]
c=collections.Counter(l.split()[6] for l in lines if len(l.split())>6)
print('logged',len(lines),dict(c))
open(out+'/nginx_delta.txt','w').write('\n'.join(lines))
PY
echo "=== temp dir now: $(docker exec "$CTR" sh -c 'du -sb /var/cache/nginx/client_temp 2>/dev/null | cut -f1') ==="
