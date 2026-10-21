#!/usr/bin/env python3
"""make_table.py - render results/lanes.jsonl into results/table.md."""
import json
import os

BASE = "/tmp/opencode/no_upload_mitigation_1021"
ROWS = [json.loads(l) for l in open(os.path.join(BASE, "results", "lanes.jsonl"))]

ORDER = ["U0", "U1", "U1cgi", "U2", "U3", "U3b", "U4", "U5", "U6"]

HEAD = ("| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried "
        "| FPM acc line | new session (upload_progress) | worker changed | note |\n"
        "|---|---|---:|---:|---:|---|---|---|---|---|---|\n")


def cell(v):
    if v is None:
        return "-"
    s = str(v).replace("|", "\\|")
    return s


def main():
    out = ["# No-upload mitigation battery - raw result rows\n",
           "PHP fatal = `Fatal error` in the pool error log.  "
           "OOM = `Allowed memory size ... exhausted` line.  "
           "`FPM acc line` = a PHP-FPM access-log line was written for the request "
           "(pre-RINIT fatals produce none).\n"]
    for lane in ORDER:
        rs = [r for r in ROWS if r["lane"] == lane]
        if not rs:
            continue
        out.append(f"\n## {lane}\n\n")
        out.append(HEAD)
        for r in rs:
            sess = ", ".join(r["new_session_files"]) or "-"
            upg = "yes" if r["new_session_has_upload_progress"] else "no"
            oom = ("%s / %s" % (r["oom_limit"], r["oom_tried"])
                   if r["oom_limit"] else "-")
            fatal = "YES" if r["php_fatal_in_log"] else "no"
            out.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s (%s) | %s | %s |\n" % (
                lane, r["tag"], cell(r["body_len"]), cell(r["http_status"]),
                cell(r["resp_len"]), fatal, oom, cell(r["fpm_access_lines"]),
                cell(sess), upg, "YES" if r["worker_changed"] else "no",
                cell(r["note"])))
    with open(os.path.join(BASE, "results", "table.md"), "w") as f:
        f.writelines(out)
    print("wrote results/table.md (%d rows)" % len(ROWS))


if __name__ == "__main__":
    main()
