#!/usr/bin/env bash
# Launch N independent fresh 5-child stock prefork pools on loopback ports,
# run one blind chain attempt per pool (default), and aggregate the evidence.
#
# Containers are named p8426_<port>, carry p8426.repro=1 and p8426.kit=<kit>,
# and are the only containers this script will stop or remove.
set -euo pipefail
umask 022

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KIT_ID=$(tr -d '\r\n' < "$ROOT/KIT_ID")

N=20
BASE_PORT=18080
ATTEMPTS=1
JOBS=""
OUT=""
ACTION=run
YES=0
STRICT=0
CLEANUP_AFTER=0

die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }
info() { echo "==> $*"; }

usage() {
    cat <<EOF
Usage: ./run_parallel.sh [options]

  --n N              number of independent pools (default 20)
  --base-port P      first loopback port (default 18080; ports P..P+N-1)
  --attempts N       chain attempts per pool (default 1; use 20 to reproduce
                     the blind 20-attempt protocol, expected 1 success/pool)
  --jobs N           max concurrently running pools (default N)
  --output DIR       output directory (default ./out/parallel_<UTC>)
  --strict           exit nonzero if any pool produced no proof
  --cleanup-after    remove kit containers after aggregation (pool data kept)
  --stop             stop all p8426 kit containers for this kit, then exit
  --cleanup          remove all p8426 kit containers for this kit (needs --yes)
  --yes              confirm --cleanup
  --help             this text

Only containers labeled p8426.repro=1 and p8426.kit=$KIT_ID, and named
p8426_<digits>, are eligible for --stop/--cleanup.  Images, volumes and
pool data are never removed by this script.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --n) [[ $# -ge 2 ]] || die "--n needs a value"; N=$2; shift 2 ;;
        --base-port) [[ $# -ge 2 ]] || die "--base-port needs a value"; BASE_PORT=$2; shift 2 ;;
        --attempts) [[ $# -ge 2 ]] || die "--attempts needs a value"; ATTEMPTS=$2; shift 2 ;;
        --jobs) [[ $# -ge 2 ]] || die "--jobs needs a value"; JOBS=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || die "--output needs a value"; OUT=$2; shift 2 ;;
        --strict) STRICT=1; shift ;;
        --cleanup-after) CLEANUP_AFTER=1; YES=1; shift ;;
        --stop) ACTION=stop; shift ;;
        --cleanup) ACTION=cleanup; shift ;;
        --yes) YES=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[[ "$N" =~ ^[0-9]+$ ]] || die "--n must be numeric"
(( N >= 1 && N <= 100 )) || die "--n must be 1..100"
[[ "$BASE_PORT" =~ ^[0-9]+$ ]] || die "--base-port must be numeric"
(( BASE_PORT >= 1 && BASE_PORT + N - 1 <= 65535 )) || die "port range is invalid"
[[ "$ATTEMPTS" =~ ^[0-9]+$ ]] || die "--attempts must be numeric"
(( ATTEMPTS >= 1 )) || die "--attempts must be >= 1"
JOBS=${JOBS:-$N}
[[ "$JOBS" =~ ^[0-9]+$ ]] || die "--jobs must be numeric"
(( JOBS >= 1 )) || die "--jobs must be >= 1"
(( JOBS <= N )) || JOBS=$N

owned_names() {
    docker ps -a \
        --filter "label=p8426.repro=1" \
        --filter "label=p8426.kit=$KIT_ID" \
        --format '{{.Names}}' 2>/dev/null | grep -E '^p8426_[0-9]+$' || true
}

check_owned() {
    local name=$1 repro kit
    repro=$(docker inspect -f '{{index .Config.Labels "p8426.repro"}}' "$name" 2>/dev/null || true)
    kit=$(docker inspect -f '{{index .Config.Labels "p8426.kit"}}' "$name" 2>/dev/null || true)
    [[ "$repro" == "1" && "$kit" == "$KIT_ID" ]] || {
        warn "skipping $name: labels no longer match this kit"
        return 1
    }
}

do_stop() {
    local names count=0
    names=$(owned_names)
    if [[ -z "$names" ]]; then
        info "no running p8426 containers for kit $KIT_ID"
        return 0
    fi
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        check_owned "$name" || continue
        docker stop "$name" >/dev/null || warn "failed to stop $name"
        echo "stopped $name"
        count=$((count + 1))
    done <<<"$names"
    info "stopped $count container(s); pool data kept"
}

do_cleanup() {
    local names count=0
    [[ $YES -eq 1 ]] || die "--cleanup requires --yes (it removes containers; pool data is kept)"
    names=$(owned_names)
    if [[ -z "$names" ]]; then
        info "no p8426 containers for kit $KIT_ID"
        return 0
    fi
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        check_owned "$name" || continue
        docker rm -f "$name" >/dev/null || { warn "failed to remove $name"; continue; }
        echo "removed $name"
        count=$((count + 1))
    done <<<"$names"
    info "removed $count container(s); images, volumes and pool data kept"
}

if [[ "$ACTION" == "stop" ]]; then
    do_stop
    exit 0
fi
if [[ "$ACTION" == "cleanup" ]]; then
    do_cleanup
    exit 0
fi

INFO=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${OUT:-$ROOT/out/parallel_$INFO}
mkdir -p "$OUT"
LOGFILE="$OUT/parallel.log"
: > "$OUT/setup_failures.txt"

info "kit=$KIT_ID pools=$N ports=$BASE_PORT..$((BASE_PORT + N - 1)) attempts=$ATTEMPTS jobs=$JOBS"
info "output=$OUT"

setup_one() {
    local port=$1 name="p8426_$1"
    "$ROOT/setup.sh" --port "$port" --name "$name" \
        --pool-dir "$ROOT/pools/$name" >>"$OUT/setup_$port.log" 2>&1
}

launch_one() {
    local port=$1 name="p8426_$1"
    "$ROOT/run_pool.sh" \
        --url "http://127.0.0.1:$port/wp-content/index.php" \
        --marker "KIT$port" \
        --attempts "$ATTEMPTS" \
        --pool-dir "$ROOT/pools/$name" \
        --output "$OUT/pool_$port" \
        >"$OUT/pool_$port.log" 2>&1
}

pids=()
running=0
for ((i = 0; i < N; i++)); do
    port=$((BASE_PORT + i))
    name="p8426_$port"
    if ! setup_one "$port"; then
        echo "$port setup_failed" >> "$OUT/setup_failures.txt"
        warn "setup failed for port $port (see $OUT/setup_$port.log)"
        continue
    fi
    while (( running >= JOBS )); do
        set +e
        wait -n
        rc=$?
        set -e
        running=$((running - 1))
        [[ $rc -eq 0 ]] || true
    done
    launch_one "$port" &
    pids+=($!)
    running=$((running + 1))
done

set +e
wait
set -e

python3 - "$OUT" "$N" "$BASE_PORT" "$ATTEMPTS" "$KIT_ID" <<'PY'
import json, os, sys
out, n, base, attempts, kit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
rows = []
for i in range(n):
    port = base + i
    pool = "p8426_%d" % port
    res_path = os.path.join(out, "pool_%d" % port, "result.json")
    obj = None
    err = ""
    try:
        with open(res_path) as fh:
            obj = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        err = "%s: %s" % (type(exc).__name__, exc)
    if obj is None:
        rows.append({
            "port": port, "container": pool, "marker": "KIT%d" % port,
            "success": False, "result": "no-result", "a1_pid": None,
            "b1_first_pid": None, "leak_pid": None, "leak_bytes": None,
            "a2_pids": [], "proof_child": None, "proof_bytes": None,
            "aborts": 0, "segv": 0, "proof_path": None, "error": err,
            "output": os.path.join(out, "pool_%d" % port),
        })
        continue
    ats = obj.get("attempts") or []
    first = ats[0] if ats else {}
    leak = first.get("derived") or {}
    b1 = first.get("b1") or []
    b1_first = b1[0].get("pid") if b1 else None
    leak_row = next((r for r in b1 if r.get("leak_hit")), None)
    a2 = [r.get("pid") for r in (first.get("a2") or []) if r.get("pid")]
    proof = None
    for r in ats:
        if r.get("success") and r.get("proof"):
            proof = r["proof"]
            break
    proof_child = None
    if proof:
        for r in (first.get("b2") or []):
            if r.get("pid") and r.get("status") == 0:
                proof_child = r["pid"]
        if proof_child is None:
            import re as _re
            for line in (first.get("b2_err") or []):
                m = _re.search(r"child pid ([0-9]+) exit signal Segmentation fault", line)
                if m:
                    proof_child = m.group(1)
                    break
    rows.append({
        "port": port, "container": pool, "marker": obj.get("marker"),
        "success": bool(obj.get("success")),
        "result": "proof" if obj.get("success") else (
            "leak-no-proof" if obj.get("leaks") else "no-leak"),
        "a1_pid": (first.get("a1") or {}).get("pid"),
        "b1_first_pid": b1_first,
        "leak_pid": leak.get("leak_pid"),
        "leak_bytes": (leak_row or {}).get("resp_bytes"),
        "a2_pids": a2,
        "proof_child": proof_child,
        "proof_bytes": (proof or {}).get("bytes"),
        "aborts": obj.get("aborts", 0),
        "segv": obj.get("segv", 0),
        "proof_path": (proof or {}).get("path"),
        "error": err,
        "output": os.path.join(out, "pool_%d" % port),
    })

header = ["port", "container", "marker", "success", "result", "a1_pid",
          "b1_first_pid", "leak_pid", "leak_bytes", "a2_pids", "proof_child",
          "proof_bytes", "aborts", "segv", "proof_path", "error"]
with open(os.path.join(out, "summary.tsv"), "w") as fh:
    fh.write("\t".join(header) + "\n")
    for r in rows:
        vals = []
        for k in header:
            v = r.get(k)
            if isinstance(v, list):
                v = ",".join(str(x) for x in v)
            if v is None:
                v = ""
            vals.append(str(v).replace("\t", " ").replace("\n", " "))
        fh.write("\t".join(vals) + "\n")

proofs = sum(1 for r in rows if r["success"])
leaks = sum(1 for r in rows if r["leak_pid"])
aborts = sum(r["aborts"] for r in rows)
segv = sum(r["segv"] for r in rows)
missing = sum(1 for r in rows if r["result"] == "no-result")
summary = {
    "kit": kit, "n": n, "base_port": base, "attempts_per_pool": attempts,
    "pools": rows,
    "totals": {"pools": n, "proofs": proofs, "leaks": leaks,
               "aborts": aborts, "segv": segv, "no_result": missing,
               "success_rate": (proofs / n) if n else 0.0},
}
with open(os.path.join(out, "summary.json"), "w") as fh:
    json.dump(summary, fh, indent=1, sort_keys=True)
    fh.write("\n")
print("SUMMARY pools=%d proofs=%d leaks=%d aborts=%d segv=%d no_result=%d" % (
    n, proofs, leaks, aborts, segv, missing))
print("TSV  %s" % os.path.join(out, "summary.tsv"))
print("JSON %s" % os.path.join(out, "summary.json"))
PY

if [[ $CLEANUP_AFTER -eq 1 ]]; then
    do_cleanup
fi

if [[ $STRICT -eq 1 ]]; then
    python3 - "$OUT/summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
sys.exit(0 if s["totals"]["proofs"] == s["totals"]["pools"] else 1)
PY
fi

python3 - "$OUT/summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
sys.exit(0 if s["totals"]["proofs"] > 0 else 1)
PY
