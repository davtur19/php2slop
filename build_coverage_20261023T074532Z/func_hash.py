#!/usr/bin/env python3
"""Extract named C functions and hash them, to test branch-level source identity
at the granularity of the functions that matter for the 109618/109619 blocker."""
import hashlib
import os
import re
import sys

RUN = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(RUN, "src")

FUNCS = {
    "session.c": ["php_session_rfc1867_callback", "php_session_initialize",
                  "php_session_flush", "php_session_reset_id", "php_session_start"],
    "rfc1867.c": ["php_rfc1867_callback", "rfc1867_post_handler",
                  "multipart_buffer_read", "multipart_buffer_headers"],
}


def extract(text, name):
    for m in re.finditer(r"(?m)^[A-Za-z_][^\n;{}]*\b%s\s*\(" % re.escape(name), text):
        start = m.start()
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        depth = 0
        i = brace
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
            i += 1
    return None


def main():
    branches = {
        "8.5": ["8.5.0", "8.5.5", "8.5.11"],
        "8.3": ["8.3.0", "8.3.10", "8.3.20", "8.3.35"],
        "8.2": ["8.2.0", "8.2.15", "8.2.34"],
        "8.1": ["8.1.0", "8.1.33"],
        "7.4": ["7.4.0", "7.4.33"],
        "7.2": ["7.2.0", "7.2.34"],
        "7.0": ["7.0.0", "7.0.33"],
        "5.6": ["5.6.0", "5.6.40"],
    }
    rows = []
    for br, tags in branches.items():
        for fname, fns in FUNCS.items():
            for fn in fns:
                hs = []
                for t in tags:
                    p = os.path.join(SRC, "%s_%s" % (t, fname))
                    if not os.path.exists(p):
                        hs.append(("MISSING", "-"))
                        continue
                    body = extract(open(p, errors="replace").read(), fn)
                    hs.append((t, hashlib.sha256(body.encode()).hexdigest()[:10]
                               if body else "ABSENT"))
                uniq = sorted({h for _, h in hs if h not in ("ABSENT", "MISSING", "-")})
                verdict = ("identical" if len(uniq) == 1 and all(
                    h not in ("ABSENT", "MISSING") for _, h in hs)
                    else ("all-absent" if uniq == [] else
                          ("varies" if len(uniq) > 1 else "partial")))
                rows.append((br, fname, fn, verdict,
                             " ".join("%s=%s" % (t, h) for t, h in hs)))
    with open(os.path.join(RUN, "logs", "source_functions.txt"), "w") as fh:
        for r in rows:
            fh.write("%-4s %-12s %-32s %-9s %s\n" % r)
            print("%-4s %-12s %-32s %-9s %s" % r)


if __name__ == "__main__":
    main()
