# 9bie `php2shell-bypass-aslr-exp` — receipt index

**Receipt:** `/tmp/opencode/research/9bie_aslr_20261022T095015Z` (copy: `phpshell/receipts/9bie_aslr_20261022/`)
**Date:** 2026-10-22 (UTC)
**PoC:** <https://github.com/9bie/php2shell-bypass-aslr-exp> @ `4586f5cc120c82fd468b17469202bac629810ad9`
**Prior receipt (same HEAD, 8.4.26 only):** `phpshell/receipts/9bie_1022`

## Verdict

The public repo is **real and reproducible**: on the official `php:8.4.26-apache`
and `php:8.5.11-apache` images, unmodified request shapes, ASLR on, single Apache
prefork worker, the full chain gives **one-shot RCE 3/3 on each version at 8M**
(and 2/2 each at 16M). It is a distinct mod_php/session-upload-progress path, not
a repackaging of our FPM G2/G6 chain.

It does **not** unblock any of our open blockers:

| Blocker | Result |
|---|---|
| `display_errors=Off` | **Not unblocked.** The chain needs output before `php_session_send_cookie()` so `SG(headers_sent)=1`; then `send_cookie` stays 1 and the stale id leaks. With Off, the classic chain fails at stage 1 (0/2 at 8M and 16M, both versions). The repo's Off branch only reaches a chunk-base heap leak; stage 2/3 are left unresolved by the author, and the published Off shape did not hit its intended OOM allocation on the official images. |
| FPM | **No evidence.** Repo is mod_php + Apache prefork only (SIGABRT refork rotation, Apache request heap). No FPM transport, calibration or test ships. Our `g2_chain.py` G2/G6 route remains the FPM path. |
| PHP 8.2.34 | **Affected, not unblocked as shipped.** 8.2.34 < 8.2.35 is in the CVE range, but all offsets/stage counts are 8.4.26-specific. Not tested. |
| PHP 7.x | **No.** Outside the CVE ranges and no 7.x profile. |

## Measured matrix (one-shot, ASLR on)

| PHP | `display_errors` | limit | field | n | stage1 | stage2 | stage3 | RCE |
|---|---|---|---|---:|---|---|---|---|
| 8.4.26 | On | 8M | 12 MB | 3 | 3/3 | 3/3 | 3/3 | **3/3** |
| 8.5.11 | On | 8M | 12 MB | 3 | 3/3 | 3/3 | 3/3 | **3/3** |
| 8.4.26 | On | 16M | 12 MB | 2 | 2/2 | 2/2 | 2/2 | **2/2** |
| 8.5.11 | On | 16M | 12 MB | 2 | 2/2 | 2/2 | 2/2 | **2/2** |
| 8.4.26 | On | 128M | 12 MB | 2 | 0/2 | — | — | 0/2 |
| 8.5.11 | On | 128M | 12 MB | 2 | 0/2 | — | — | 0/2 |
| 8.4.26 | On | 128M | 63 MB | 2 | 2/2 | 2/2 | 0/2 | 0/2 |
| 8.5.11 | On | 128M | 63 MB | 2 | 2/2 | 2/2 | 0/2 | 0/2 |
| both | Off | 8M / 16M | 12 MB | 2 each | 0/2 | — | — | 0/2 |

Every success wrote `uid=33(www-data) gid=33(www-data)` to `/tmp/p1` inside the
container. Leaked libphp bases matched `/proc/1/maps` in **6/6** On containers.
`n` is 2–3 per row: these are existence/one-shot measurements, not reliability
rates.

## Mechanism in brief

1. **A**: 1001 fields trigger the `max_input_vars` warning; with
   `display_errors=On` it is output and sets `SG(headers_sent)=1`. A
   `PHPSESSID=\x00` creates a new id + `PS(send_cookie)=1`; `send_cookie` then
   fails on the headers check without clearing the flag. A 12 MB field OOMs,
   leaving `PS(id)` dangling.
2. **B**: attacker fields reclaim the freed id block with a forged `zend_string`
   length; the pre-RINIT upload-progress session init calls
   `php_session_send_cookie()`, and `php_url_encode()` returns up to 4096 bytes of
   heap in `Set-Cookie`. Decoded pointers give the Zend MM chunk base (stage 1)
   and, via `HashTable::pDestructor = zval_ptr_dtor`, the libphp base (stage 2).
3. **Stage 3**: a fake `HashTable` with `pDestructor = libphp+zif_system` and a
   fake `execute_data` is placed in a live string; the next request's
   `php_session_track_init()` destroys the stale `http_session_vars` reference
   and calls `system("id>/tmp/p1")`. No libc base is needed.

The leak is the **OOB `Set-Cookie` read**, not the error text. `display_errors`
matters only because it turns the warning into output.

## Key files

| Path | Contents |
|---|---|
| `report.md` | full analysis: mechanism, source anchors, gate, matrix, ASLR ground truth, G2/G6 comparison, verdicts |
| `metadata.txt` | commit, image digests, container IDs/ports, offsets, CVE facts |
| `SHA256SUMS` | checksums of report/README/metadata/configs/scripts/logs |
| `lab/driver_one.py` | repo-`Exploit` wrapper with in-container proof check |
| `lab/capture_stage1.py` | raw On/Off stage-1 A/B capture |
| `lab/off/` | repo Off A/B senders, loopback-port patched, plus probe harness |
| `lab/configs/` | php.ini variants, single-worker prefork config, index/probe pages |
| `lab/logs/results.json` | machine-readable matrix |
| `lab/logs/aslr-groundtruth.txt` | end-of-run `/proc/1/maps` bases and child counts |
| `lab/logs/display_errors_gate.txt` | Apache warning signature On vs Off |
| `lab/logs/source-anchors-8.5.11.txt` | 8.4.26 ↔ 8.5.11 source line map |
| `lab/logs/<container>/` | driver/classic/capture logs and full `docker.log` |

## Reproduce

```bash
# containers (ten, loopback only)
lab/mkcontainer.sh 9bieaslr-8426-on-8M 18230 php:8.4.26-apache on-8M

# full chain, 8.4.26
python3 lab/driver_one.py --container 9bieaslr-8426-on-8M \
  --url http://127.0.0.1:18230/index.php \
  --zif 0x465370 --dtor 0x65eb60 --huge-mb 12 --retries 1

# full chain, 8.5.11
python3 lab/driver_one.py --container 9bieaslr-8511-on-8M \
  --url http://127.0.0.1:18235/index.php \
  --zif 0x5996e0 --dtor 0x7b47a0 --huge-mb 12 --retries 1

# On/Off gate, raw stage-1 response
python3 lab/capture_stage1.py http://127.0.0.1:18230/index.php 0x465370 0x65eb60
python3 lab/capture_stage1.py http://127.0.0.1:18231/index.php 0x465370 0x65eb60
```

Verify integrity: `sha256sum -c SHA256SUMS`.

## Limits

- Small n; no reliability claim.
- Only official Apache images; custom builds need re-calibration.
- 128M stage-3 failure is uncalibrated geometry, not impossibility.
- Off tested with the classic chain and one published shape here; the full Off
  sweep is in `9bie_1022`.
- Multi-worker and `MaxConnectionsPerChild=1` were not re-run (see `9bie_1022`).
- FPM, 8.2.34 and 7.x were not executed.
- All requests went to `127.0.0.1` in disposable containers; no host process was
  used for exploitation.
