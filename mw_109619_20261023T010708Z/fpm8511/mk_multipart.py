#!/usr/bin/env python3
"""Build a multipart body for the upload-progress tests.

Usage: mk_multipart.py OUT --progress-key KEY --filename-len N
       [--file-bytes N] [--filename-char A] [--progress-count N]
"""
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--progress-key", default="probe1")
ap.add_argument("--progress-key-len", type=int, default=0)
ap.add_argument("--progress-key-char", default="k")
ap.add_argument("--filename-len", type=int, default=120)
ap.add_argument("--file-bytes", type=int, default=1024)
ap.add_argument("--filename-char", default="A")
ap.add_argument("--boundary", default="----mw109619boundary")
args = ap.parse_args()

b = args.boundary.encode()
key = args.progress_key
if args.progress_key_len:
    key = args.progress_key_char * args.progress_key_len
parts = []
parts.append(b"--" + b + b"\r\n")
parts.append(b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n')
parts.append(key.encode("latin1") + b"\r\n")
parts.append(b"--" + b + b"\r\n")
parts.append(
    b'Content-Disposition: form-data; name="file"; filename="'
    + (args.filename_char.encode("latin1") * args.filename_len)
    + b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
)
parts.append(b"x" * args.file_bytes + b"\r\n")
parts.append(b"--" + b + b"--\r\n")
data = b"".join(parts)
open(args.out, "wb").write(data)
print(len(data))
