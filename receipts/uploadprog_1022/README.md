# Stock `session.upload_progress` write limits and the 8.5.10 decode → `zif_passthru` chain

Receipt: `/tmp/opencode/research/uploadprog_20261022T014518Z/`
Date: 2026-10-22
Lab: private `realapps` PHP-FPM tree (`/tmp/opencode/research/realchain_20261022T015900Z`), nginx `127.0.0.1:28893`, PHP 8.5.10 non-PIE, ASLR on.

## Verdict

* **Write ceiling is the request-body cap, not the session engine.** Largest accepted progress key **8,388,349 B** (session file **8,388,711 B**, HTTP 200) under nginx `client_max_body_size 8m` and PHP `post_max_size=8M`. A key of 8,388,400 B returned HTTP 413 and wrote no session file.
* **Byte control is adequate for fake structures.** The key is copied raw and contiguous at file offset 16 (pure progress record) or 39 (combined two-record file). NULs survive; only `|` is special — a key containing `|` makes the encoder fail and leaves a **0-byte** session file. With `cleanup=On` the progress record is removed at request end (0-byte file, not unlinked); with `cleanup=0` it persists.
* **Stock-only blocker:** the primitive alone cannot write the first record's integer value `referrer_id|i:10731636;`, because its own record is always a progress array and its key cannot contain `|`. In this lab the HexCoupon `handle_referral()` write (`GET /?ref=10731636`) supplied that record; everything else in the primitive was sufficient.
* **Chain executed without gdb, ASLR on.** The upload-progress writer supplied the large fake-structure record, the referrer writer supplied `referrer_id|i:10731636;` (decimal `zif_passthru`), and the plant left `BG(unserialize)={data=P,level=1}`. The final trigger returned HTTP 500 with an empty body, created `MARK_UP`, left the session file at 0 bytes, and worker `1685915` survived. Post-state: `basic_globals.unserialize={data=0x0,level=0}`, `ps_serializers[1].decode=0xa3c074` (static poison).

## Layout

| path | content |
|---|---|
| `REPORT.md` | full write-up: primitive format, size ladder, controllability, cleanup/locking, HexCoupon first record, chain geometry and limits |
| `cycles/` | create/probe JSON cycles, large-key bodies, referrer records and trigger artefacts |
| `conf/` | nginx/FPM/`.user.ini` configs used for the pools |
| `log/` | access/error logs, plant and trigger output |
| `req/` | HTTP request captures for plant, large-key probe and final trigger |
| `www/` | minimal lab endpoints (`uptrigger.php`, `diag_params.php`, `hexplant.php`) |
| `probe_up.py`, `poll_during.py`, `upmp.py`, `mkup_trigger.py` | probe, poll, multipart and trigger drivers |
| `MARK_UP` | final exploit marker (empty file) |

## Scope

The target is a private WordPress 7 + HexCoupon lab; the receipt exercises the **stock PHP primitive** and the native decode slot, and uses one plugin write for the prerequisite integer record. It does not claim a stock end-to-end application exploit. No shared service was restarted; only lab workers were recycled for lab hygiene. Multi-megabyte upload bodies are retained in `cycles/` because the size boundary is the result.
