# `php:8.2.34-apache` — Apache prefork mod_php full chain

**Status: target-written proof.** 2/2 chain runs (`8234b_r1`, `8234b_r2`) ended
with a `uid` file written by the exploited worker. The bodies are the recovered
Oct-24 pair, rebuilt byte-identically from session-recorded generators.

## Target (measured)

| item | value |
|---|---|
| image | `php:8.2.34-apache` |
| image id | `sha256:f380b054d6364b80f0952a9198e5dc1e1ab4d809aad24d3f3174f059e863f48a` |
| repo digest | `php@sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` |
| PHP | `PHP 8.2.34 (cli) (built: Oct 21 2026 00:35:21) (NTS)` |
| SAPI | `Apache/2.4.69 (Debian)`, prefork mod_php |
| MPM | `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0` |
| php.ini | `php.ini-production`, 73,870 B, `b40aed987458694f7d81b0e469e05d125fff3175d9901fe70a6321ed833af9e1`; `memory_limit=128M`, `display_errors=Off` |
| docroot | `/var/www/html`, 22-byte `/index.php` stub, `1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23` |
| ASLR | on at the host (`randomize_va_space=2`) |
| traffic | loopback only; access logs contain only `127.0.0.1` and `172.17.0.1` |

## Build constants

`zval_ptr_dtor = libphp + 0x487650` · `zif_system = libphp + 0x39b8a0` ·
`S = main + 0xF9398` · A2 fillers `115`

## Bodies

| body | bytes | sha256 |
|---|---|---|
| A1 `a1_8234.bin` | 1,060,869 | `673cc3175551a35934d9ac11dbe26d06d9b83c6b3e32db35272eed515ab0201c` |
| B1 `b1_8234.bin` | 29,218,150 | `d4ef67293645f5beeafac1798f6fb92abed35fa90936b8a6fbfbcc522323e2d3` |

Both bodies were reconstructed byte-identically from session-recorded
generators and match the recorded Oct-24 hashes. They are not shipped in this
repository. The proof uses the 29,218,150 B B1 body and the 149-holder pin.
`c1.bin` is not an input to this chain and is not shipped.

## Runs

| run | tag | A1 | B1 | A2 | B2 | decoded / hits | proof capture |
|---|---|---|---|---|---|---|---|
| 1 | `8234b_r1` | 500 / 211 B | 200 / 1,383,427 B | 500 / 211 B | 0 B / SIGSEGV | 1,169,032 / 584 | `proof/proof_8234b_r1.txt` |
| 2 | `8234b_r2` | 500 / 211 B | 200 / 1,383,427 B | 500 / 211 B | 0 B / SIGSEGV | 1,169,032 / 584 | `proof/proof_8234b_r2.txt` |

Both runs used the same container after the pool recovered from the first
SIGSEGV. The leak bases were identical: `main=0x7f9f44000000`,
`libphp=0x7f9f45be7000`, `S=0x7f9f440f9398`, `zif_system=0x7f9f45f828a0`.

The error log proves the same child served all four stages: pid 195 for
`8234b_r1` and pid 315 for `8234b_r2` carry the A1 4096-byte OOM, the B1
session warnings, the A2 20480-byte OOM and the B2 SIGSEGV.

## Proof provenance

The B2 request body carries `id>/tmp/p1; echo PWNED_<tag> >>/tmp/p1`. The
host-side harness never executes `id` and never writes `/tmp/p1`; the driver
deletes the path inside the container immediately before the run and only cats
it after the run. The file is owned by `www-data:www-data` (uid/gid 33) and
contains the `id` output plus the tag. B2 returns 0 bytes and the child dies
with SIGSEGV after the marker is written.

The in-container marker is 69 B. The published captures are 124 B
(`proof_8234b_r2.txt`: stat, uid and tag) and 1,995 B
(`proof_8234b_r1.txt`: the same plus an appended error-log excerpt). The
1,995 B figure is the capture size, not the marker size.

## Evidence files

- `report.md` — full redacted report.
- `commands.txt` — exact commands with `<RUNDIR>`, `<container>` and `<PORT>`
  placeholders.
- `proof/` — the two target-written `uid` captures, verbatim.
- `decoded/` — the two decoded leak JSON files.
- `evidence/` — the earlier negative public rerun, preserved and marked
  superseded.
- `sha256sums.txt` — hashes for this directory.

## Reproduction

See `commands.txt` for the body regeneration, the stock container and the R1
driver invocation. The driver and body files are retained privately; the
commands record the measured sequence and constants. Verify this directory with:

```sh
cd receipts/php-8.2.34
sha256sum -c sha256sums.txt
```
