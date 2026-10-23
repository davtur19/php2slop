#!/usr/bin/env python3
"""T1 negative control on static-2 raw FastCGI.

C1: t1_producer.php (keep=1) -> OOM inside BG(serialize) at request shutdown,
    leaving stale BG(unserialize)/BG(serialize) state on worker A.
C1/C2: t1_consumer.php (normal Moodle-shaped session write) -> expect 200,
    no SIGSEGV, even if it lands on the same worker.
"""
import argparse, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t3_raw_fcgi as t
import matrix_run as m


def dec_bytes(obj):
    if isinstance(obj, bytes):
        return obj.decode("latin1", "replace")
    if isinstance(obj, dict):
        return {k: dec_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [dec_bytes(v) for v in obj]
    return obj


def send(sock, req, seconds=3.0):
    try:
        sock.sendall(req)
    except Exception as e:
        return {"send_error": "%s: %s" % (type(e).__name__, e), "responses": {}}
    try:
        data = t.recv_all(sock, seconds=seconds)
    except Exception as e:
        return {"recv_error": "%s: %s" % (type(e).__name__, e), "responses": {}}
    try:
        res = t.parse_responses(data, ids=(1, 2))
    except Exception as e:
        res = {"parse_error": "%s: %s" % (type(e).__name__, e)}
    return {"responses": res}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=29510)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--access-log", default=m.RUN + "/lab/logs/fpm-s2-access.log")
    ap.add_argument("--error-log", default=m.RUN + "/lab/logs/fpm-s2-error.log")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(m.SESSION_DIR, exist_ok=True)
    off_a = os.path.getsize(args.access_log) if os.path.exists(args.access_log) else 0
    off_e = os.path.getsize(args.error_log) if os.path.exists(args.error_log) else 0

    safe = re.sub(r"[^A-Za-z0-9,-]", "", args.tag)
    sid = "mt1-%s" % safe
    with open(os.path.join(m.SESSION_DIR, "sess_" + sid), "wb") as f:
        f.write(m.DECODE_SESSION)

    result = {"tag": args.tag, "port": args.port, "sid": sid}
    c1 = t.connect(args.port)
    env = t.get_env("t1_producer.php", "/t1_producer.php")
    env["QUERY_STRING"] = "tag=%sprod" % args.tag
    r1 = send(c1, t.build_request(1, env, keep=True), seconds=2.5)
    result["producer"] = dec_bytes(r1["responses"])

    env2 = t.get_env("t1_consumer.php", "/t1_consumer.php")
    env2["QUERY_STRING"] = "sid=%s&tag=%scons" % (sid, args.tag)
    req2 = t.build_request(2, env2, keep=False)
    r2 = send(c1, req2, seconds=3.0)
    used = "same_connection"
    if r2.get("send_error") or r2.get("recv_error"):
        used = "same_connection_failed_retry_new"
        c1.close()
        c2 = t.connect(args.port)
        r2 = send(c2, t.build_request(1, env2, keep=False), seconds=3.0)
        c2.close()
    result["consumer_transport"] = used
    result["consumer"] = dec_bytes(r2["responses"])
    try:
        c1.close()
    except Exception:
        pass
    time.sleep(0.4)

    def read_new(path, off):
        try:
            with open(path, "rb") as f:
                f.seek(off)
                return f.read().decode("latin1", "replace")
        except FileNotFoundError:
            return ""
    access = read_new(args.access_log, off_a)
    error = read_new(args.error_log, off_e)
    open(os.path.join(args.outdir, "access_new.txt"), "w").write(access)
    open(os.path.join(args.outdir, "error_new.txt"), "w").write(error)
    rows = m.parse_fpm_access(access)
    result["access_rows"] = rows
    result["sig11_pids"] = m.parse_sig11(error)

    def find_pid(tag):
        for row in rows:
            if tag in row["query"]:
                return row["pid"]
        return None
    result["producer_pid"] = find_pid("tag=%sprod" % args.tag)
    result["consumer_pid"] = find_pid("tag=%scons" % args.tag)
    result["same_worker"] = (result["producer_pid"] is not None and
                             result["producer_pid"] == result["consumer_pid"])

    def body(resp, rid):
        out = resp.get(rid, {}).get("stdout", "")
        return out
    result["producer_body"] = body(result["producer"], 1)
    # consumer request id is 2 on same connection, 1 on retry
    cid = 2 if used == "same_connection" else 1
    result["consumer_body"] = body(result["consumer"], cid)
    with open(os.path.join(args.outdir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: result[k] for k in ("tag", "producer_pid", "consumer_pid", "same_worker",
                                             "sig11_pids", "producer_body", "consumer_body",
                                             "consumer_transport")}, indent=2))


if __name__ == "__main__":
    main()
