#!/usr/bin/env python3
"""Send a consumer-only wave (no priming) and correlate crashes with a known primed set."""
import argparse, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import matrix_run as m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=29511)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--type", choices=["decode", "encode"], default="decode")
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--primed", default="")
    ap.add_argument("--fpm-access", default=m.RUN + "/lab/logs/fpm-matrix-access.log")
    ap.add_argument("--fpm-error", default=m.RUN + "/lab/logs/fpm-matrix-error.log")
    ap.add_argument("--nginx-access", default=m.RUN + "/lab/logs/nginx-matrix-access.log")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(m.SESSION_DIR, exist_ok=True)
    offsets = {}
    for p in (args.fpm_access, args.fpm_error, args.nginx_access):
        try:
            offsets[p] = os.path.getsize(p)
        except FileNotFoundError:
            offsets[p] = 0
    session = m.DECODE_SESSION if args.type == "decode" else m.ENCODE_SESSION
    safe = re.sub(r"[^A-Za-z0-9,-]", "", args.tag)
    sids = []
    for i in range(args.count):
        sid = "m%s-%d" % (safe, i)
        sids.append(sid)
        with open(os.path.join(m.SESSION_DIR, "sess_" + sid), "wb") as f:
            f.write(session)
    primed = sorted(int(x) for x in args.primed.split(",") if x.strip().isdigit())

    t0 = time.time()
    with m.ThreadPoolExecutor(max_workers=args.count) as ex:
        futs = {}
        for i in range(args.count):
            body = m.build_consumer_body(sids[i], "wkey_%s_%d" % (args.tag, i))
            path = "/consumer.php?tag=%sc%d" % (args.tag, i)
            futs[ex.submit(m.http_post_multipart, args.host, args.port, path, body)] = i
        cons = []
        for f in m.as_completed(futs):
            i = futs[f]
            r = f.result()
            r["i"] = i
            r["sid"] = sids[i]
            cons.append(r)
    cons.sort(key=lambda x: x["i"])
    time.sleep(0.6)

    fpm_access = m.read_new(args.fpm_access, offsets[args.fpm_access])
    fpm_error = m.read_new(args.fpm_error, offsets[args.fpm_error])
    nginx = m.read_new(args.nginx_access, offsets[args.nginx_access])
    open(os.path.join(args.outdir, "fpm_access_new.txt"), "w").write(fpm_access)
    open(os.path.join(args.outdir, "fpm_error_new.txt"), "w").write(fpm_error)
    open(os.path.join(args.outdir, "nginx_access_new.txt"), "w").write(nginx)

    rows = m.parse_fpm_access(fpm_access)
    ctag = re.compile(r"tag=%sc(\d+)" % re.escape(args.tag))
    crows = []
    for ln in rows:
        mm = ctag.search(ln["query"])
        if mm and "consumer.php" in ln["script"]:
            ln["i"] = int(mm.group(1))
            crows.append(ln)
    crashed = sorted(set(m.parse_sig11(fpm_error)))
    nginx_rows = [x for x in m.parse_nginx_access(nginx) if ("tag=%sc" % args.tag) in x["path"]]

    result = {
        "tag": args.tag, "type": args.type, "count": args.count, "wall": round(time.time() - t0, 3),
        "primed_input": primed,
        "consumer_responses": cons,
        "consumer_rows": crows,
        "crashed_pids": crashed,
        "crashed_in_primed": sorted(set(crashed) & set(primed)),
        "crashed_not_in_primed": sorted(set(crashed) - set(primed)),
        "nginx_502": sum(1 for x in nginx_rows if x["status"] == 502),
        "nginx_200": sum(1 for x in nginx_rows if x["status"] == 200),
        "survivor_pids": sorted(set(int(x["pid"]) for x in crows if x["status"] == "200")),
    }
    with open(os.path.join(args.outdir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: result[k] for k in ("tag", "count", "crashed_pids", "crashed_in_primed",
                                              "crashed_not_in_primed", "nginx_502", "nginx_200",
                                              "survivor_pids")}, indent=2))


if __name__ == "__main__":
    main()
