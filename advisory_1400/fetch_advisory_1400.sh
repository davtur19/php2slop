#!/bin/bash
# One-shot advisory fetcher (embargo-gated, idempotent).
#
# Context: CVE-2026-109618/109619 disclosure artifacts publish 2026-10-21
# 14:00:00 UTC. Must be launched from the OPERATOR SESSION (any process spawned
# inside a subagent session dies when that session closes — proven twice).
#
# Behaviour:
#  - NO sleep/wait logic. If run before 2026-10-21T14:00:00Z it logs
#    BEFORE_EMBARGO and exits 0 immediately, without touching the network.
#  - Idempotent: existing non-empty artifacts are skipped ("skipped"); every
#    successful fetch appends its sha256 to advisory_1400/manifest.sha256.
#  - Network failures are logged and never fatal (no set -e; other sources
#    are still attempted).
#  - Usage: bash fetch_advisory_1400.sh [outdir]   (outdir optional override)
set -u
OUT=${1:-/tmp/opencode/realapps/side/advisory_1400}
mkdir -p "$OUT"
LOG="$OUT/status.txt"
UA='Mozilla/5.0 (X11; Linux x86_64) advisory-fetcher'
CUTOFF_UTC='2026-10-21T11:45:00Z'   # first monitoring time; commits newer than this are "fix candidates"

log() { echo "[$(date -u +%FT%TZ)] $*" >> "$LOG"; }

# --- embargo gate: absolute epoch of 2026-10-21 14:00:00 UTC, parsed at runtime
EMBARGO_EPOCH=$(date -u -d '2026-10-21 14:00:00' +%s)
now=$(date -u +%s)
if [ "$now" -lt "$EMBARGO_EPOCH" ]; then
  log "BEFORE_EMBARGO now=$(date -u +%FT%TZ) < 2026-10-21T14:00:00Z; nothing fetched, exiting 0"
  exit 0
fi
log "RUN pid=$$ post-embargo one-shot fetch starting (outdir=$OUT)"

fetch() {  # fetch url outfile
  local url="$1" out="$2"
  if [ -s "$out" ]; then
    log "skipped $url -> $out (already present, $(stat -c%s "$out") B)"
    return 0
  fi
  if wget -q --timeout=60 -U "$UA" "$url" -O "$out" 2>>"$LOG" && [ -s "$out" ]; then
    log "OK $url -> $out ($(stat -c%s "$out") B)"
    ( cd "$OUT" && sha256sum "$(basename "$out")" >> manifest.sha256 )
  else
    log "FETCH_FAIL $url -> $out (wget failed or empty body; partial file removed)"
    rm -f "$out"
  fi
}
apifetch() {  # apifetch github_url outfile
  local url="$1" out="$2" code
  if [ -s "$out" ]; then
    log "skipped $url -> $out (already present, $(stat -c%s "$out") B)"
    return 0
  fi
  code=$(curl -s --max-time 40 -A "$UA" -H 'Accept: application/vnd.github+json' \
           -o "$out" -w '%{http_code}' "$url" 2>>"$LOG") || code=000
  if [ "$code" = 200 ] && [ -s "$out" ]; then
    log "OK api $url -> $out ($(stat -c%s "$out") B)"
    ( cd "$OUT" && sha256sum "$(basename "$out")" >> manifest.sha256 )
  else
    log "FETCH_FAIL api $url -> $out http=$code"
    rm -f "$out"
  fi
}
probe() {  # probe url : logs http code (HEAD-style, body discarded), never fatal
  local url="$1" code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -A "$UA" -L "$url" 2>>"$LOG") || code=000
  log "probe $url -> $code"
}

# --- 1) release / security pages
fetch https://www.php.net/releases/8.5.11.php "$OUT/release_8.5.11.html"
fetch "https://www.php.net/ChangeLog-8.php" "$OUT/changelog8.html"

# --- 2) php-src session.c recent commits (main + PHP-8.5 branches)
apifetch "https://api.github.com/repos/php/php-src/commits?path=ext/session/session.c&per_page=15" "$OUT/commits_session_c.json"
apifetch "https://api.github.com/repos/php/php-src/commits?sha=PHP-8.5&path=ext/session/session.c&per_page=15" "$OUT/commits_session_c_85.json"
apifetch "https://api.github.com/repos/php/php-src/tags?per_page=10" "$OUT/tags.json"

# --- 3) tarball location: record URLs + one HEAD to confirm availability
#        (artifact records the LOCATION; the tarball itself is not downloaded)
if [ -s "$OUT/tarball_urls.txt" ]; then
  log "skipped tarball_urls.txt (already present)"
else
  cat > "$OUT/tarball_urls.txt" <<'EOF'
https://www.php.net/distributions/php-8.5.11.tar.gz
https://www.php.net/distributions/php-8.5.11.tar.xz
EOF
  log "OK tarball_urls.txt written (location record; tarball not downloaded)"
fi

# --- 4) unified .diff for any session.c commit committed after the cutoff
#        (max 8; each skipped if its patch file already exists)
python3 - "$OUT" "$CUTOFF_UTC" <<'PY' 2>>"$LOG"
import datetime, hashlib, json, os, sys, urllib.request
out, cutoff_s = sys.argv[1], sys.argv[2]
cutoff = datetime.datetime.fromisoformat(cutoff_s.replace("Z", "+00:00"))
logp = os.path.join(out, "status.txt")
def L(msg):
    line = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%FT%TZ')}] {msg}"
    with open(logp, "a") as f:
        f.write(line + "\n")
UA = {"User-Agent": "advisory-fetcher"}
cands = []
for jf in ("commits_session_c.json", "commits_session_c_85.json"):
    path = os.path.join(out, jf)
    try:
        data = json.load(open(path))
    except Exception as e:
        L(f"DIFF_STEP {jf}: unreadable ({e})")
        continue
    if not isinstance(data, list):
        L(f"DIFF_STEP {jf}: not a list (rate-limited or malformed)")
        continue
    for c in data:
        sha = c.get("sha")
        d = (c.get("commit", {}).get("committer", {}) or {}).get("date", "")
        try:
            when = datetime.datetime.fromisoformat(d)
        except Exception:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        if when >= cutoff:
            cands.append((when, sha[:12], d, jf))
cands.sort(reverse=True)
if not cands:
    L("DIFF_STEP: no post-cutoff session.c commits in the fetched lists")
for when, sha, d, jf in cands[:8]:
    patch = os.path.join(out, f"diff_{sha}.patch")
    if os.path.exists(patch) and os.path.getsize(patch) > 0:
        L(f"skipped diff {sha} (already present)")
        continue
    url = f"https://github.com/php/php-src/commit/{sha}.diff"
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=40) as r:
            blob = r.read()
        open(patch, "wb").write(blob)
        digest = hashlib.sha256(blob).hexdigest()
        with open(os.path.join(out, "manifest.sha256"), "a") as m:
            m.write(f"{digest}  diff_{sha}.patch\n")
        L(f"OK diff {sha} -> diff_{sha}.patch ({len(blob)} B)")
    except Exception as e:
        L(f"FETCH_FAIL diff {sha} ({e})")
PY

# --- 5) local summary of the commit listings (NO network)
python3 - "$OUT" <<'PY' 2>>"$LOG" || log "SUMMARY_FAIL python summary step"
import json, sys, os
out = sys.argv[1]
lines = []
for jf in ("commits_session_c.json", "commits_session_c_85.json"):
    path = os.path.join(out, jf)
    try:
        data = json.load(open(path))
    except Exception as e:
        lines.append(f"{jf}: unreadable ({e})")
        continue
    if not isinstance(data, list):
        lines.append(f"{jf}: not a list (rate-limited or malformed)")
        continue
    lines.append(f"{jf}: {len(data)} entries")
    for c in data[:6]:
        sha = (c.get("sha") or "?")[:12]
        d = c.get("commit", {}).get("committer", {}).get("date", "?")
        msg = c.get("commit", {}).get("message", "").splitlines()
        first = msg[0][:80] if msg else "(no message)"
        lines.append(f"  {d} {sha} {first}")
with open(os.path.join(out, "commits_summary.txt"), "w") as f:
    f.write("\n".join(lines) + "\n")
PY

ls -la "$OUT" >> "$LOG"
log "FETCH_DONE one-shot complete; rerun is safe (idempotent)"
exit 0
