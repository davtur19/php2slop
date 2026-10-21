#!/usr/bin/env python3
"""Analyze advisory fetcher artifacts: extract session.c commits + their diffs.

Usage: analyze_advisory.py [--base /tmp/opencode/realapps/side/advisory_1400]
Looks at commits_{main,85}.json entries with commit.committer.date newer than
the session.c-cutoff (first monitoring time), fetches commit.pad diff, greps
for the machinery lines of interest.
"""
import argparse
import datetime
import json
import os
import sys
import urllib.request

CUTOFF_UTC = datetime.datetime(2026, 10, 21, 11, 45, 0,
                               tzinfo=datetime.timezone.utc)
INTEREST = [
    (3129, "update() stale read"),
    (3144, "next_update recompute"),
    (3151, "SEPARATE_ARRAY(sess_var)"),
    (3155, "zend_hash_update embed"),
    (3256, "outer cache arm"),
    (3280, "add_next_index_zval ownership"),
    (3282, "inner cache arm"),
    (3284, "inner first store"),
    (3295, "FILE_DATA stores"),
    (3296, "outer store"),
    (3315, "FILE_END store"),
    (3328, "SEPARATE_ARRAY(progress->data)"),
    (3330, "END stale store"),
    (3338, "END data dtor"),
]


def gh(url: str) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "advisory-analyzer",
        "Accept": "application/vnd.github.v3+json",
    })
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/tmp/opencode/realapps/side/advisory_1400")
    a = ap.parse_args()
    found = []
    for name in ("commits_session_c.json", "commits_session_c_85.json"):
        p = os.path.join(a.base, name)
        if not os.path.exists(p):
            continue
        try:
            data = json.load(open(p))
        except Exception as e:
            print(f"{name}: unreadable ({e})")
            continue
        if not isinstance(data, list):
            print(f"{name}: not a list (maybe rate-limited or empty)")
            continue
        for c in data:
            d = c.get("commit", {}).get("committer", {}).get("date", "")
            sha = c.get("sha", "")[:12]
            first = (c.get("commit", {}).get("message", "") or "").splitlines()
            msg = (first[0] if first else "")[:100]
            try:
                when = datetime.datetime.fromisoformat(d)
            except Exception:
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=datetime.timezone.utc)
            if when < CUTOFF_UTC:
                continue
            found.append((when, sha, msg, name))
    found.sort()
    if not found:
        print("NO post-cutoff session.c commits found")
        return
    print(f"{len(found)} post-cutoff session.c commit(s):")
    for when, sha, msg, src in found:
        mark = ""
        for line, label in INTEREST:
            if f"{line:#x}" in msg or str(line) in msg:
                mark = f"  <touches {label}>"
        print(f"- {when.isoformat()} {sha} {msg}{mark} [{src}]")
        # fetch unified diff (network failure: log and continue; never fatal)
        try:
            diff = gh(f"https://github.com/php/php-src/commit/{sha}.diff")
        except Exception as e:
            print(f"  FETCH_FAIL diff {sha} ({e})")
            continue
        if not isinstance(diff, bytes) or not diff:
            print(f"  FETCH_FAIL diff {sha} (empty body)")
            continue
        out = os.path.join(a.base, f"diff_{sha}.patch")
        with open(out, "wb") as f:
            f.write(diff)
        txt = diff.decode("utf-8", "replace")
        interesting = [l for l in txt.splitlines()
                       if ("+ " in l or "-" in l) and any(
                           k in l.lower() for k in
                           ("bytes_processed", "rfc1867", "zval_ptr_dtor",
                            "track_init", "separate_array", "add_next_index"))]
        print(f"  saved {out} ({len(diff)} B); key diff lines:")
        for l in interesting[:25]:
            print("   ", l[:160])


if __name__ == "__main__":
    main()
