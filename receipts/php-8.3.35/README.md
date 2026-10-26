# `php:8.3.35-apache` — Apache prefork mod_php full chain

**Status: target-written proof.** 2/2 chain runs (`8335b_r1`, `8335b_r2`) ended
with a `uid` file written by the exploited worker. The bodies are the recovered
Oct-24 pair, rebuilt byte-identically from session-recorded generators.

## Target (measured)

| item | value |
|---|---|
| image | `php:8.3.35-apache` |
| image id | `sha256:90620e863c15e608cfebd058554d82d2c7fd816bdd690adc69027409cbb7a369` |
| repo digest | `php@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` |
| PHP | `PHP 8.3.35 (cli) (built: Oct 21 2026 00:33:53) (NTS)` |
| SAPI | `Apache/2.4.69 (Debian)`, prefork mod_php |
| MPM | stock prefork; `StartServers 5` and `MaxRequestWorkers 150` measured in the container config |
| php.ini | `php.ini-production`, 73,397 B, `2533da00f66b1cf18430b08871262afa12f58cf2ee43b2077740c9c3972bb980`; `memory_limit=128M`, `display_errors=Off` |
| docroot | `/var/www/html`, 22-byte `/index.php` stub, `1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23` |
| ASLR | on at the host (`randomize_va_space=2`) |
| traffic | loopback only; access logs contain only `127.0.0.1` and `172.17.0.1` |

## Build constants

`zval_ptr_dtor = libphp + 0x49EC50` · `zif_system = libphp + 0x3AC080` ·
`S = main + 0xF9398` · A2 fillers `115`

## Bodies

| body | bytes | sha256 |
|---|---|---|
| A1 `a1_8234.bin` | 1,060,869 | `673cc3175551a35934d9ac11dbe26d06d9b83c6b3e32db35272eed515ab0201c` |
| B1 `b1_8234.bin` | 29,218,150 | `d4ef67293645f5beeafac1798f6fb92abed35fa90936b8a6fbfbcc522323e2d3` |

Both bodies were reconstructed byte-identically from session-recorded
generators and match the recorded Oct-24 hashes. The 8.3.35 run reused this
same pair; the filenames retain their 8.2.34 origin. They are not shipped in
this repository. The proof uses the 29,218,150 B B1 body and the 149-holder
pin. `c1.bin` is not an input to this chain and is not shipped.

## Runs

| run | tag | A1 | B1 | A2 | B2 | decoded / hits | proof capture |
|---|---|---|---|---|---|---|---|
| 1 | `8335b_r1` | 500 / 211 B | 200 / 1,380,063 B | 500 / 211 B | 0 B / SIGSEGV | 1,169,032 / 584 | `proof/proof_8335b_r1.txt` |
| 2 | `8335b_r2` | 500 / 211 B | 200 / 1,380,063 B | 500 / 211 B | 0 B / SIGSEGV | 1,169,032 / 584 | `proof/proof_8335b_r2.txt` |

Both runs used the same container after the pool recovered from the first
SIGSEGV. The leak bases were identical: `main=0x7fd639000000`,
`libphp=0x7fd63ad56000`, `S=0x7fd6390f9398`, `zif_system=0x7fd63b102080`.

The error log proves the same child served all four stages: pid 186 for
`8335b_r1` and pid 253 for `8335b_r2` carry the A1 4096-byte OOM, the B1
session warnings, the A2 20480-byte OOM and the B2 SIGSEGV.

## Proof provenance

The B2 request body carries `id>/tmp/p1; echo PWNED_<tag> >>/tmp/p1`. The
host-side harness never executes `id` and never writes `/tmp/p1`; the driver
deletes the path inside the container immediately before the run and only cats
it after the run. The file is owned by `www-data:www-data` (uid/gid 33) and
contains the `id` output plus the tag. B2 returns 0 bytes and the child dies
with SIGSEGV after the marker is written.

The in-container marker is 69 B. The published captures are 124 B
(`proof_8335b_r2.txt`: stat, uid and tag) and 1,995 B
(`proof_8335b_r1.txt`: the same plus an appended error-log excerpt). The
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
cd receipts/php-8.3.35
sha256sum -c sha256sums.txt
```
