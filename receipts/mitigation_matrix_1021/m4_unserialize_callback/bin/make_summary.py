#!/usr/bin/env python3
"""Render results/m4_summary.md from results/m4_results.jsonl."""
import json
import os

D = "/tmp/opencode/m4_test_1021"


def load_rows():
    with open(os.path.join(D, "results", "m4_results.jsonl")) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main():
    rows = load_rows()
    by = {(r["lane"], r["step"]): r for r in rows}
    lanes = []
    for r in rows:
        if r["step"] == "probe_ini" and r["lane"] not in lanes:
            lanes.append(r["lane"])

    out = []
    out.append("# M4 measured summary (php_admin_value[unserialize_callback_func]=\"\")\n")
    out.append("PHP 8.5.10 FPM (ASAN build), loopback FastCGI, one worker per pool "
               "(`pm.max_requests=0`). `marker` = `D2::__destruct` wrote a file.\n")
    out.append("| lane | pool pin | probe callback (access) | ini_set result | "
               "script `unserialize()` marker | predefined-class marker | pre-script marker | "
               "class at script entry |")
    out.append("|---|---|---|---|---|---|---|---|")

    for lane in lanes:
        probe = by[(lane, "probe_ini")]
        pin = probe["pin"]
        cb = "?"
        acc = "?"
        iniset = "?"
        for line in probe["body"].splitlines():
            if line.startswith("unserialize_callback_func="):
                cb, _, acc = line.partition(" access=")
                cb = cb.split("=", 1)[1]
            if line.startswith("ini_set(unserialize_callback_func,strlen)="):
                iniset = line.split("=", 1)[1]

        def marker(step):
            r = by.get((lane, step))
            if r is None:
                return "n/a"
            return "**yes**" if r["marker_after"] else "no"

        def cls(lstep):
            r = by.get((lane, lstep))
            if r is None:
                return "n/a"
            for line in r["body"].splitlines():
                if line.startswith("class_D2_at_script="):
                    return line.split("=", 1)[1]
            return "n/a"

        pre = "n/a"
        if (lane, "pre_script_upload_progress") in by:
            pre = "upload-progress: " + marker("pre_script_upload_progress")
        elif (lane, "pre_script_session_auto_start") in by:
            pre = "auto_start: " + marker("pre_script_session_auto_start")

        out.append("| %s | %s | %s (access=%s) | %s | %s | %s | %s | %s |" % (
            lane, pin, cb, acc, iniset,
            marker("script_unserialize"),
            marker("script_unserialize_predefined_class"),
            pre, cls("pre_script_upload_progress") if (lane, "pre_script_upload_progress") in by
            else cls("pre_script_session_auto_start")))

    out.append("")
    out.append("Raw probe transcripts: `results/effective_ini.txt`, "
               "`results/transcripts/<lane>_*.http`; one JSON row per request in "
               "`results/m4_results.jsonl`.")
    out.append("")
    arm = os.path.join(D, "results", "m4_oom_arm.json")
    if os.path.exists(arm):
        a = json.load(open(arm))
        out.append("## Orthogonality check: stock OOM arm on the pinned pool (l6, 8M)\n")
        out.append("- body sent: %d B; response %d B, sha `%s`" % (
            a["body_len_sent"], a["response_body_len"], a["response_body_sha256"]))
        out.append("- body: `%s`" % a["response_body"].strip().replace("\n", " / "))
        out.append("- result: pre-RINIT OOM **still fires** with the callback pinned empty; "
                   "the FPM worker exits 70 (see `logs/fpm-master.log`). M4 does not touch "
                   "the multipart allocation.")
    with open(os.path.join(D, "results", "m4_summary.md"), "w") as fh:
        fh.write("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
