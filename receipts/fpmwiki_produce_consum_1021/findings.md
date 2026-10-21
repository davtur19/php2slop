# findings — fpmwiki_produce_consum_1021 (harvest of worker G run `run_fpmwiki_20261021_173406`)

Curated 2026-10-21 ~20:0x UTC from `/tmp/opencode/realapps/side/php2shell/runs/run_fpmwiki_20261021_173406/`
(volatile tmpfs — full integrity list in `inventory.sha256.txt`). What was run is documented
verbatim in `run_README.md` (copy of the run's own README) and in `scripts/`;
this findings.md is written **from the artifacts**, not from worker G's own report.

**Context.** Worker G (previous session) ran a producer→consumer chain experiment against the
real-app target — MediaWiki 1.46.2 at `127.0.0.1:28840` (nginx 1.30.1 in front, PHP-FPM pool
`wiki`, master pid 3920992, single static worker pid 3920993 `pm=static max_children=1`,
`memory_limit` 8388608, `post_max_size` 8388608). The worker COMPLETED but its session returned
no text report; all evidence lives in these artifacts.

## What was run (chronology reconstructed from mtimes + script contents)

1. **Producer calibration** — `scripts/producer_edit.py <N> <label> prod/`, anon MW edit POST
   (bootstrap `mwdb_session` cookie → `api.php` csrf scrape → multipart
   `/index.php?title=Sandbox&action=submit`, `wpTextbox1=b"A"*N`, `wpSave`), 17:34–17:36:
   | N | response | classification |
   |---|---|---|
   | 1M, 2M (`2M`/`2Mcons`/`2Mclean` byte-identical requests, sha `9ace4ee5…`) | 222 B fatal `Allowed memory … (tried to allocate 8000032 bytes) in …/includes/EditPage/EditPage.php on line 1232` | OOM **after** request parse, in app code; worker survives |
   | 3M, 2.3M, 2.6M, 6M | 150 B fatal `Allowed memory … (tried to allocate 2098791 bytes) in Unknown on line 0` | OOM **inside the rfc1867/multipart machinery** ("Unknown on line 0") — the CVE-2026-109618 surface |
   | 9M (`L9000000`) | 41071 B: `Warning: PHP Request Startup: POST Content-Length of 9000593 bytes exceeds the limit of 8388608 …` + MW warnings | pre-parser ceiling, no app fatal |
   `prod/getout.bin` (2295 B) is an MW XML export dump (siteinfo "C4b1nLabWiki") — auxiliary target data.

2. **Producer ARM ×5** — `scripts/consumer_arm.py 5 1.0 cons/` (17:44), single native STOCK arm
   request per iteration (`arm_body = STOCK.arm_body(b"abcdefgh", L)`, sid travels as
   `PHPSESSID=abcdefgh` **form field**, no Cookie header, Basic auth user ×23, `Connection: close`),
   body 4983497 B containing `PHP_SESSION_UPLOAD_PROGRESS`. Results (`results/producer_arm_x5_summary.json`):
   deterministic across 5 runs — status 200, body 149 B
   `Allowed memory size of 8388608 bytes exhausted (tried to allocate 266240 bytes) in Unknown on line 0`
   (body sha12 `561043a1e978` ×5, identical to the archived 17:44 `arm-*-body.bin`), elapsed 6–7 ms,
   worker **survived** (matches `receipts/` diag4/diag3 arm-receipt lineage).

3. **Coupled producer→ARM→probe** — `scripts/flow_immediate.py cons/` (17:46): 2M producer POST
   (EditPage OOM fatal, `results/producer_2M_edit_fatal_body.bin`) → ARM immediately <1 s
   (266240/Unknown-0 fatal, `results/producer_arm_fatal_body.bin` + headers in
   `producer_arm_response_headers.bin`) → consumer probe request
   (`results/consumer_probe_request_flow.bin`). The driver prints its step records to stdout —
   **stdout was not archived in the run dir** (worker session captured it; gap).

4. **Consumer probes ×2** — `cons/probe_1/`, `probe_2/` (17:47), the structured end-state
   (`results/consumer_probe_{1,2}_result.json`, responses archived for probe_1):
   multipart `PHP_SESSION_UPLOAD_PROGRESS=probe` + `upload0/upload1` parts with
   `filename="F"*33`, `Authorization: Basic dXNlcn...=` (64×'U' user), `Cookie: PHPSESSID=`
   **(empty)**, `Content-Length: 453`. Two-step driver, kept request-2 (sha `547e9f13…`,
   byte-identical between probe_1 and probe_2); host header differs from the flow probe
   (`Host: 127.0.0.1` vs `127.0.0.1:28840` — different driver invocation, both to :28840).
   Response 36991 B → dechunked body 36377 B, prefix `<!DOCTYPE html` = fresh canonical
   MediaWiki render; analysis fields: `pointer_bytes_in_requests: false`, `candidate: false`,
   `canonical: false`, machinery pointer `0x505954434f44213c` never appeared in any request or
   response bytes. probe_1/probe_2 bodies differ only in static-file-hash noise (dynamic content) —
   the negative result is deterministic.

## Verdict — stale-state chain classification

**NOT REPRODUCED / NEGATIVE** for this real-app setting (MW 1.46.2 + FPM wiki pool, unproxied
nginx front). Every consumer upload-progress probe issued after a producer-created OOM state
(both the post-startup EditPage OOM at 2M and the machinery OOM at the 266240-byte arm)
received a fresh canonical MediaWiki page; no attacker-gadget pointer leak, no non-canonical
response, `candidate=false` twice. The producer stages themselves are fully reproducible and
deterministic (see tables above), so the negative comes from the consumer side, not producer
instability. Post-advisory note: with PHP 8.5.12+ the OOM→bailout corruption this chain
depends on is fixed (CVE-2026-109618 — see `receipts/advisory_1400/attribution_8510_8512.md`);
the php build of this wiki FPM pool is not recorded in the run artifacts (gap, see below).

## Anomalies & gaps (pointers)

- **Empty sid in the consumer probe** (`Cookie: PHPSESSID=` with no PHPSESSID form field) while
  the producer arm carries `PHPSESSID=abcdefgh` — archived requests show no sid linkage between
  producer and consumer. If the intended chain required *same-sid* consumption of
  PHP_SESSION_UPLOAD_PROGRESS state, the probes could not have done that; a rerun with a
  matching sid is needed before calling the same-sid variant dead. (Process-global stale
  machinery state — the shape this run actually tested — was not produced.)
- Driver invocations for the `probe_1/probe_2` result.json files are not archived (shape per
  `php2shell.py::attempt()`, whose snapshot is in the run dir, sha `f8923c41…`).
- Worker-pid receipts between coupled steps (promised by `flow_immediate.py`'s docstring):
  absent from the dir.
- `run_README.md` "## Receipts" section is empty — the experiments were never appended there;
  the 17:31:02 access-log line with a blank pid field and the note that another worker deleted
  `side/php2shell/diag*.py` between 17:33–17:34 (snapshots of the core modules were copied
  into the run dir) are preserved verbatim in `run_README.md`.
- **lemmalog cross-reference: NOT FOUND.** No `memory.snapshot` or lemmalog artifact anywhere
  under `/tmp/opencode/realapps/side/` (exhaustive find), and no lemmalog MCP tools in the
  curation session — the package ships without the claimed memory snapshot.
- TMPFS volatility: originals (incl. 2–9 MB request binaries) live only under
  `/tmp/opencode/realapps/side/php2shell/runs/run_fpmwiki_20261021_173406/`; every file's
  sha256 + size is pinned in `inventory.sha256.txt` so nothing is silently dropped:
  big-path highlights — `cons/arm-request.bin` 4983710 B sha `6745b3dc…`,
  `cons/producer-request.bin` / `prod/{2M,2Mcons,2Mclean}-request.bin` 2000593 B sha
  `9ace4ee5…`, `prod/L9000000-request.bin` 9000593 B sha `7a017bb1…`,
  `body_mw.bin` 300294 B sha `05399d9e…`.
- `UNIVERSAL_PLAN.md` at `side/php2shell/runs/UNIVERSAL_PLAN.md` documents the broader chain
  plan referencing this run (supplier step table names producer N≈6000000 and the 9M ceiling);
  deliberately NOT curated here per instruction (handled by another agent).

## Inline subset in this receipt

`run_README.md`, `scripts/{producer_edit,consumer_arm,flow_immediate}.py`,
`results/{producer_arm_x5_summary.json, consumer_probe_1_result.json, consumer_probe_2_result.json,
producer_arm_fatal_body.bin, producer_arm_response_headers.bin, producer_2M_edit_fatal_body.bin,
consumer_probe_request_flow.bin, consumer_probe_1_request_2.bin, consumer_probe_1_response_2.bin,
consumer_probe_1_body_2.bin}`, `inventory.sha256.txt`. Everything else of the run: path+sha only.
