#!/usr/bin/env python3
"""battery.py - ordered measurement phases over the nginx edge lanes."""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import narm
import run_lanes as R

SID = narm.ARM_SID
COOKIE = "PHPSESSID=" + SID.decode()
BASE = "/tmp/opencode/nginx_mitigation_1021"


def arm(token=True, parts=20, length=262144):
    return narm.arm_body(SID, length, parts,
                         token_field=b"PHP_SESSION_UPLOAD_PROGRESS" if token else b"")


def fat_shortnames(n_parts=20, content_len=248900):
    """Same ~4.98 MB body volume, but ordinary short filenames (control for
    'is the OOM about filenames or about body bytes?')."""
    b = narm.field(b"PHPSESSID", SID)
    for i in range(n_parts):
        b += (b"--" + narm.BOUNDARY + b"\r\n"
              + b'Content-Disposition: form-data; name="up' + str(i).encode()
              + b'"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
              + b"X" * content_len + b"\r\n")
    return b + b"--" + narm.BOUNDARY + b"--\r\n"


def late_token_arm(parts=20, length=262144):
    """Token field placed AFTER the file parts (defeats prefix-only inspection)."""
    b = narm.field(b"PHPSESSID", SID)
    for i in range(parts):
        n = 9 if i == 0 else length
        b += narm.file_part(i, b"F" * n)
    b += narm.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")
    return b + b"--" + narm.BOUNDARY + b"--\r\n"


def at_cap_body():
    """Largest giant-filename body still under client_max_body_size 2m."""
    target = 2_090_000
    parts = 8
    per = (target - 1200) // (parts - 1)
    b = narm.arm_body(SID, per, parts)
    while len(b) >= 2_097_152:
        per -= 512
        b = narm.arm_body(SID, per, parts)
    return b


def p1_control():
    R.case("N0", "N0_arm_stock_4983500", arm(), cookie=COOKIE)
    R.case("N0", "N0_arm_notoken_4983404", arm(token=False), cookie=COOKIE)
    fb = fat_shortnames()
    R.case("N0", "N0_fat_shortnames_%d" % len(fb), fb, cookie=COOKIE)
    R.case("N0", "N0_variant_8parts_1836238", arm(parts=8), cookie=COOKIE)
    R.case("N0", "N0_variant_8parts_280k", arm(parts=8, length=280000), cookie=COOKIE)


def p2_n1():
    R.case("N1", "N1_arm_stock_4983500", arm(), cookie=COOKIE)
    R.case("N1", "N1_arm_stock_chunked", arm(), cookie=COOKIE, chunked=True)
    R.case("N1", "N1_variant_8parts_1836238", arm(parts=8), cookie=COOKIE)
    R.case("N1", "N1_variant_8parts_280k", arm(parts=8, length=280000), cookie=COOKIE)
    R.case("N1", "N1_legit_upload", narm.legit_body(), path="/upload.php")
    R.get_case("N1", "N1_probe_ini", path="/probe.php")


def p3_n2():
    R.case("N2", "N2_arm_stock_4983500", arm(), cookie=COOKIE)
    R.case("N2", "N2_variant_6parts", arm(parts=6), cookie=COOKIE)
    R.case("N2", "N2_variant_8parts_1836238", arm(parts=8), cookie=COOKIE)
    R.case("N2", "N2_variant_8parts_280k", arm(parts=8, length=280000), cookie=COOKIE)
    ac = at_cap_body()
    R.case("N2", "N2_at_cap_%d" % len(ac), ac, cookie=COOKIE)


def p4_n4():
    R.case("N4", "N4_legit_small", narm.legit_body(), path="/upload.php")
    R.case("N4", "N4_arm_stock_4983500", arm(), cookie=COOKIE)
    statuses = []
    for i in range(10):
        r = R.case("N4", "N4_burst_%02d" % (i + 1), narm.legit_body(), path="/upload.php")
        statuses.append(r["http_status"])
    print("N4 burst statuses:", statuses)
    R.case("N4", "N4_arm_after_burst", arm(), cookie=COOKIE)
    # concurrency limb (separate exact-match location, limit_conn only)
    results = []

    def hit(i):
        r = narm.http_get(29004, "/sleep.php")
        results.append((i, r["http_status"]))

    ths = [threading.Thread(target=hit, args=(i,)) for i in range(10)]
    t0 = time.time()
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    print("N4 limit_conn results:", sorted(results), "wall=%.1fs" % (time.time() - t0))
    with open(os.path.join(BASE, "results", "n4_limit_conn.json"), "w") as f:
        json.dump({"results": sorted(results), "wall_s": round(time.time() - t0, 2)}, f, indent=2)


def p5_shapes():
    R.case("SHAPE", "shape_quoted_control",
           narm.shape_body(b"sessshapequoted001", b"PHP_SESSION_UPLOAD_PROGRESS"),
           cookie="PHPSESSID=sessshapequoted001")
    R.case("SHAPE", "shape_unquoted",
           narm.shape_body(b"sessshapeunquoted1", b"PHP_SESSION_UPLOAD_PROGRESS",
                           quote=False),
           cookie="PHPSESSID=sessshapeunquoted1")
    R.case("SHAPE", "shape_lowercase",
           narm.shape_body(b"sessshapelower0001", b"PHP_SESSION_UPLOAD_PROGRESS",
                           case="lower"),
           cookie="PHPSESSID=sessshapelower0001")
    R.case("SHAPE", "shape_percent_encoded",
           narm.shape_body(b"sessshapeperc00001", b"PHP_SESSION_UPLOAD_PROGRESS",
                           encoded=True),
           cookie="PHPSESSID=sessshapeperc00001")
    R.case("SHAPE", "shape_no_token",
           narm.shape_body(b"sessshapenone00001", None),
           cookie="PHPSESSID=sessshapenone00001")
    R.case("SHAPE", "shape_single_quoted_name",
           (b"--" + narm.BOUNDARY + b"\r\n"
            b"Content-Disposition: form-data; name='PHP_SESSION_UPLOAD_PROGRESS'\r\n\r\n"
            b"MMM\r\n--" + narm.BOUNDARY + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\nY\r\n"
            b"--" + narm.BOUNDARY + b"--\r\n"),
           cookie="PHPSESSID=sessshapesingle001")
    R.get_case("SHAPE", "shape_probe_tokrename_ini", path="/tokrename/probe.php")


def p6_n3():
    R.case("N3", "N3_arm_stock_4983500", arm(), cookie=COOKIE)
    R.case("N3", "N3_small_token_shape",
           narm.shape_body(b"sessshimsmall00001", b"PHP_SESSION_UPLOAD_PROGRESS"),
           cookie="PHPSESSID=sessshimsmall00001")
    R.case("N3", "N3_legit_upload", narm.legit_body(), path="/upload.php")
    R.case("N3", "N3_legit_upload_token_in_filename",
           narm.legit_body(b"PHP_SESSION_UPLOAD_PROGRESS_notes.bin"), path="/upload.php")
    R.case("N3", "N3_arm_notoken_4983404", arm(token=False), cookie=COOKIE)
    R.case("N3", "N3_arm_userini_dir_default_field", arm(), cookie=COOKIE,
           path="/tokrename/index.php",
           extra_headers={"X-Note": "field renamed to UPGX"})
    # the renamed arm needs the *renamed* field to be the one PHP would use
    R.case("N3", "N3_arm_userini_UPGX_field",
           narm.arm_body(SID, 262144, 20, token_field=b"UPGX"),
           cookie=COOKIE, path="/tokrename/index.php")
    late = late_token_arm()
    R.case("N3", "N3_arm_token_after_parts_%d" % len(late), late, cookie=COOKIE)
    R.case("N3-8k", "N3_8k_arm_token_after_parts_%d" % len(late), late, cookie=COOKIE)
    R.case("N3-8k", "N3_8k_arm_stock_4983500", arm(), cookie=COOKIE)
    R.case("N3", "N3_arm_percent_field",
           narm.arm_body(SID, 262144, 20, token_field=b"%50HP_SESSION_UPLOAD_PROGRESS"),
           cookie=COOKIE)


def p7_n3core():
    # core-only `if ($request_body ~ ...)` attempt: expect it never fires
    p = {"err": R.size(f"{BASE}/logs/fpm_n3.error.log"),
         "acc": R.size(f"{BASE}/logs/fpm_n3.access.log"),
         "ngx": R.size(f"{BASE}/logs/n3core.access.log"),
         "sess": R.sess_state(f"{BASE}/sessions/n3")}
    r = narm.raw_post(29007, "/index.php",
                      narm.shape_body(b"sesscoreapprox001", b"PHP_SESSION_UPLOAD_PROGRESS"),
                      30, cookie="PHPSESSID=sesscoreapprox001")
    r["extra"] = {"note": "if($request_body~TOKEN) small body"}
    R.post("N3-core", "N3core_small_token_if_request_body", r, p)


def p8_sweep():
    out = {"baseline": {}, "sizes": []}
    # baseline: GET, no body
    lo, hi = 1 << 20, 256 << 20
    if not sweep_ok(None, hi):
        raise SystemExit("sweep lane broken at high limit")
    base = sweep_min(None)
    out["baseline"] = {"kind": "GET /probe.php", "min_ok_limit": base}
    print("baseline min_ok:", base)
    for parts in (4, 6, 8, 12, 16, 20):
        body = arm(parts=parts)
        m = sweep_min(body)
        rec = {"parts": parts, "body_len": len(body), "min_ok_limit": m,
               "min_ok_limit_MiB": round(m / 1048576, 3),
               "k_vs_body": round(m / len(body), 3),
               "k_minus_base": round((m - base) / len(body), 3)}
        out["sizes"].append(rec)
        print(rec)
        # log-backed boundary pair
        R.case("SWEEP", "SWEEP_%dparts_fail_%d" % (parts, m - 65536), body,
               cookie=COOKIE, extra_headers={"X-PHP-Mem": str(m - 65536)})
        R.case("SWEEP", "SWEEP_%dparts_ok_%d" % (parts, m), body,
               cookie=COOKIE, extra_headers={"X-PHP-Mem": str(m)})
    with open(os.path.join(BASE, "results", "sweep.json"), "w") as f:
        json.dump(out, f, indent=2)


def sweep_ok(body, limit):
    if body is None:
        r = narm.http_get(29005, "/probe.php",
                          extra_headers={"X-PHP-Mem": str(limit)})
        return r["http_status"] == 200 and "memory_limit" in r["resp_body_head"]
    r = narm.raw_post(29005, "/index.php", body, 60, cookie=COOKIE,
                      extra_headers={"X-PHP-Mem": str(limit)})
    return "S:count=" in (r["resp_body_head"] or "")


def sweep_min(body):
    lo, hi = 1 << 20, 256 << 20
    assert sweep_ok(body, hi)
    while hi - lo > 65536:
        mid = (lo + hi) // 2
        if sweep_ok(body, mid):
            hi = mid
        else:
            lo = mid
    return hi


PHASES = {"p1": p1_control, "p2": p2_n1, "p3": p3_n2, "p4": p4_n4,
          "p5": p5_shapes, "p6": p6_n3, "p7": p7_n3core, "p8": p8_sweep}

if __name__ == "__main__":
    for name in sys.argv[1:] or list(PHASES):
        print("== phase", name, "==", flush=True)
        PHASES[name]()
