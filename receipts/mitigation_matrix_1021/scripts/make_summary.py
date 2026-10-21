#!/usr/bin/env python3
"""make_summary.py - render the measured matrix from results.jsonl files."""
import json
import os

BASE = "/tmp/opencode/mitigation_1021"
RESULTS = BASE + "/results"

LANES = [
    ("A_fpm_control", "A", "FPM 8.5.10 control", "28980", "8M", "1", "1", "1"),
    ("B_fpm_mitigated", "B", "FPM 8.5.10 + M1+M2+M3", "28981", "128M", "0", "0", "0"),
    ("C_fpm_m1_only", "C", "FPM 8.5.10 + M1 only", "28983", "8M", "0", "1", "1"),
    ("B2_oversize_12M", "B2", "FPM oversize probe", "28984", "12M", "1", "16M", "1"),
    ("B3_oversize_128M", "B3", "FPM oversize probe", "28985", "128M", "1", "16M", "1"),
    ("B4_unlimited_mem", "B4", "FPM 8.5.10 + M1, memory_limit=-1", "28987", "-1", "0", "8M", "0"),
    ("D_modphp", "D", "mod_php 8.5.10 + M1+M2+M3", "28982", "128M", "0", "0", "0"),
    ("D0_modphp_control", "D0", "mod_php 8.5.10 control", "28986", "8M", "1", "1", "1"),
]


def main():
    out = {"lanes": [], "boundary": []}
    md = ["| lane | step | HTTP | resp bytes | sha256[:12] | OOM tried | fatal in body |",
          "|---|---|---|---|---|---|---|"]
    for dirname, short, desc, port, mem, up, post, disp in LANES:
        path = os.path.join(RESULTS, dirname, "results.jsonl")
        if not os.path.exists(path):
            continue
        rows = [json.loads(line) for line in open(path)]
        rec = {"id": short, "dir": dirname, "desc": desc, "port": port,
               "memory_limit": mem, "upload_progress": up, "post_max_size": post,
               "display_errors": disp, "rows": rows}
        wr = os.path.join(RESULTS, dirname, "worker_receipt.json")
        if os.path.exists(wr):
            rec["worker_receipt"] = json.load(open(wr))
        out["lanes"].append(rec)
        for r in rows:
            tried = r["oom"]["tried"] if r["oom"] else ""
            md.append(f"| {short} | {r['tag']} | {r['http_status']} | {r['resp_len']} | "
                      f"`{r['resp_sha256'][:12]}` | {tried} | "
                      f"{'yes' if r['fatal_lines'] else 'no'} |")

    # consolidate the CGI boundary measurements
    files = ["cgi_boundary_small.json", "cgi_boundary_524.json", "cgi_boundary_786.json"]
    seen = {}
    for fn in files:
        p = os.path.join(RESULTS, fn)
        if not os.path.exists(p):
            continue
        d = json.load(open(p))
        for r in d["results"]:
            seen[r["filename_len"]] = r
    bmd = ["| filename len | 20-part body bytes | min memory_limit that survives | min-1 bytes | body+overhead | ratio |",
           "|---|---|---|---|---|---|"]
    for L in sorted(seen):
        r = seen[L]
        ratio = round(r["min_ok_limit"] / r["body_len"], 2)
        out["boundary"].append(r)
        if r.get("below_set_limit_failed"):
            # PHP refuses to lower memory_limit below startup usage (~2 MiB),
            # so the smallest enforceable limit is reported as an upper bound.
            bmd.append(f"| {L} | {r['body_len']:,} | ≤ {r['min_ok_limit']:,} B "
                       f"({r['min_ok_limit_mib']} MiB, floor) | n/a | "
                       f"+{r['limit_minus_body']:,} B | {ratio}x |")
        else:
            bmd.append(f"| {L} | {r['body_len']:,} | {r['min_ok_limit']:,} B "
                       f"({r['min_ok_limit_mib']} MiB) | {r['min_ok_limit'] - 1:,} B | "
                       f"+{r['limit_minus_body']:,} B | {ratio}x |")

    json.dump(out, open(os.path.join(RESULTS, "matrix_summary.json"), "w"),
              indent=1, sort_keys=True)
    open(os.path.join(RESULTS, "results_table.md"), "w").write("\n".join(md) + "\n")
    open(os.path.join(RESULTS, "boundary_table.md"), "w").write("\n".join(bmd) + "\n")
    print("\n".join(md))
    print()
    print("\n".join(bmd))


if __name__ == "__main__":
    main()
