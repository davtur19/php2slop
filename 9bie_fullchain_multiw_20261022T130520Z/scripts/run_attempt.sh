#!/bin/bash
# One full-chain attempt on the stock 5-worker target, with post-hoc evidence
# capture. The attack driver itself is blind; this wrapper only snapshots logs
# and PIDs after the driver returns.
set -u
D=$(cat /tmp/opencode/.fullchain_mw_current)
N=$1
MODE=${2:-restart}
CONT=${3:-p2s-mw-18610}
PORT=${4:-18610}
NB1=${NB1:-5}
NA2=${NA2:-5}
NB2=${NB2:-5}
CR=${CHAIN_RETRIES:-1}
ROUTE=${ROUTE:-broadcast}
RN=${ROUTE_N:-5}
TS=$(date -u +%FT%TZ)
LOGD=$D/receipts/logs/attempt_r$N
mkdir -p "$LOGD"
{
  echo "=== attempt $N mode=$MODE start=$TS ==="
  echo "--- workers before ---"
  docker top "$CONT" -o pid,ppid,user,rss,args
} > "$LOGD/workers_before.txt" 2>&1
echo "{\"attempt\":$N,\"mode\":\"$MODE\",\"start\":\"$TS\"}" > "$LOGD/meta.json"

ARGS=(--port "$PORT"
      --repo /tmp/opencode/research/9bie_update_20261022T115026Z/code/repo
      --a1 "$D/bodies/a1.bin" --b1 "$D/bodies/b1_800k.bin"
      --outdir "$D/work/attempt_r$N" --attempt "$N"
      --marker "9BIE_MW_20261022T130520Z_A$N"
      --n-b1 "$NB1" --n-a2 "$NA2" --n-b2 "$NB2" --chain-retries "$CR"
      --route "$ROUTE" --route-n "$RN" --health --timeout 300)
if [ "$MODE" = restart ]; then
  ARGS+=(--restart "$CONT")
else
  # Keep --restart for post-attempt proof reads/removal, but skip the restart.
  ARGS+=(--restart "$CONT" --no-restart)
fi
python3 "$D/scripts/chain_blind.py" "${ARGS[@]}" > "$D/receipts/attempt_r$N.stdout" 2>&1
RC=$?
echo "driver_rc=$RC" >> "$LOGD/meta.json"
sleep 1.5
{
  echo "--- workers after ---"
  docker top "$CONT" -o pid,ppid,user,rss,args
  echo "--- container ---"
  docker ps --filter "name=$CONT" --format '{{.Names}} {{.Status}}'
} > "$LOGD/workers_after.txt" 2>&1
docker logs --since "$TS" "$CONT" > "$LOGD/docker.log" 2>&1
docker exec "$CONT" cat /var/log/apache2/p2s-access.log > "$LOGD/p2s-access.log" 2>&1
docker exec "$CONT" ls -la /out > "$LOGD/out_listing.txt" 2>&1
docker inspect "$CONT" --format 'RestartCount={{.RestartCount}} StartedAt={{.State.StartedAt}}' > "$LOGD/container_state.txt" 2>&1
echo "rc=$RC"
exit $RC
