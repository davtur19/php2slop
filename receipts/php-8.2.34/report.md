# PHP 8.2.34 mod_php chain — target-written proof

- Date: 2026-10-26 (UTC).
- Lab: loopback-only; no external target traffic.
- Status: **2/2 target-written `uid=33(www-data)` proofs** on a fresh stock
  `php:8.2.34-apache` container.
- Receipt scope: two proof captures, two decoded leak JSON files and the exact
  commands. Raw responses, full Apache logs and the body files are retained
  privately and are not part of this receipt.

## Verdict

| item | result |
|---|---|
| target | `php:8.2.34-apache`, image `sha256:f380b054d6364b80f0952a9198e5dc1e1ab4d809aad24d3f3174f059e863f48a` |
| chain | A1 500 / B1 200 with leak / A2 500 / B2 0 bytes + SIGSEGV |
| proofs | 2/2, markers `PWNED_8234b_r1` and `PWNED_8234b_r2` |
| marker | 69 B in-container, owner `www-data:www-data` (uid/gid 33) |
| leak | 1,383,427 B encoded; 1,169,032 B decoded; `n=584`; 44 main-chunk hits |
| constants | `zval_ptr_dtor=libphp+0x487650`, `zif_system=libphp+0x39b8a0`, `S=main+0xF9398` |
| config | Apache 2.4.69 (Debian) prefork, `MaxRequestWorkers 150`, `memory_limit=128M`, `display_errors=Off`, ASLR on |
| traffic | loopback only; access logs contain only `127.0.0.1` and `172.17.0.1` |
| `c1.bin` | not used, not shipped, not claimed as the priming body |

## What was run

The recipe is the R1 pool-pinning sequence:

```
warmup:20,holders:149:640,ramp:15,a1,b1,a2,b2,marker
```

- 20 warmup GETs move the prefork pool past `StartServers`.
- 149 holders each declare a 1 MiB body, send one body byte and trickle 640 B/s.
  Apache's `RequestReadTimeout body=10,minrate=500` keeps them alive.
- With `MaxRequestWorkers=150`, the last child has no holder and has never
  completed a request. The error log records `AH00161: server reached
  MaxRequestWorkers setting`.
- A1, B1, A2 and B2 are sent in order to that single idle child. No container
  restart and no gdb are used.

Stage signatures, both runs:

| stage | status | bytes | signature |
|---|---|---|---|
| A1 | `HTTP/1.0 500 Internal Server Error` | 211 | OOM `tried to allocate 4096 bytes` |
| B1 | `HTTP/1.1 200 OK` | 1,383,427 | `Set-Cookie` leak, `n=584` |
| A2 | `HTTP/1.0 500 Internal Server Error` | 211 | OOM `tried to allocate 20480 bytes` |
| B2 | empty | 0 | `AH00052: child pid ... exit signal Segmentation fault (11)` |

## Results

| run | tag | A1 | B1 | A2 | B2 | decoded / hits | proof capture |
|---|---|---|---|---|---|---|---|
| 1 | `8234b_r1` | 500 / 211 B | 200 / 1,383,427 B | 500 / 211 B | 0 B / SIGSEGV | 1,169,032 / 584 | `proof/proof_8234b_r1.txt` |
| 2 | `8234b_r2` | 500 / 211 B | 200 / 1,383,427 B | 500 / 211 B | 0 B / SIGSEGV | 1,169,032 / 584 | `proof/proof_8234b_r2.txt` |

The two runs used the same container after the pool recovered from the first
SIGSEGV. The leak bases were identical in the two runs:
`main=0x7f9f44000000`, `libphp=0x7f9f45be7000`, `S=0x7f9f440f9398`,
`zif_system=0x7f9f45f828a0`.

## Same-child evidence

The Apache error log is the decisive same-child record; the stock access-log
format does not carry a pid.

| run | A1 OOM pid | B1 session warnings pid | A2 OOM pid | B2 SIGSEGV pid |
|---|---|---|---|---|
| `8234b_r1` | 195 | 195 | 195 | 195 |
| `8234b_r2` | 315 | 315 | 315 | 315 |

For `8234b_r1` the sequence in the error log is: `tried to allocate 4096 bytes`
on pid 195, the session-id read/write warnings on pid 195, `tried to allocate
20480 bytes` on pid 195, then `child pid 195 exit signal Segmentation fault
(11)`. The second run repeats the same sequence on pid 315.

## Decoded leak

`decoded/b1_8234b_r1.json` and `decoded/b1_8234b_r2.json` are the decoded
`Set-Cookie` summaries. The decoded payload is 1,169,032 B in both runs, with
`n=584` `zval_ptr_dtor` hits and 44 hits in the main-chunk bucket.

| field | `8234b_r1` | `8234b_r2` |
|---|---|---|
| `resp_bytes` | 1,383,427 | 1,383,427 |
| `decoded` | 1,169,032 | 1,169,032 |
| `n` | 584 | 584 |
| `main_hits` | 44 | 44 |
| `main` | `0x7f9f44000000` | `0x7f9f44000000` |
| `lib` | `0x7f9f45be7000` | `0x7f9f45be7000` |
| `zdtor` | `0x7f9f4606e650` | `0x7f9f4606e650` |
| `decoded_sha256` | `eb084cc60d9ce3fbf96a836023912fdeefc2c82990f204b226531587e92500c2` | `4a81d77acf17213a00478270a5389d7f099418bb09dfa9411224d55dc9b46e21` |

## Why this is target-written

The command string is carried in the B2 request body:
`id>/tmp/p1; echo PWNED_<tag> >>/tmp/p1`. The host-side harness only turns it
into fake-HashTable bytes; it never executes `id` and never writes `/tmp/p1`.
The driver's only marker operations are `docker exec ... rm -f /tmp/p1` before
the run and `docker exec ... cat /tmp/p1` after it.

The resulting file exists only inside the container, is owned by
`www-data:www-data` (uid/gid 33), and contains the `id` output
`uid=33(www-data) gid=33(www-data) groups=33(www-data)` followed by the tag.
B2 returns zero bytes and the same child dies with SIGSEGV, consistent with the
fake-reference destructor path; the marker is written before the crash.

### Marker size and capture size

The in-container marker is **69 B**. The files under `proof/` are capture
files, not the raw marker:

- `proof_8234b_r2.txt` is 124 B: the `stat` line, the uid line and the tag.
- `proof_8234b_r1.txt` is 1,995 B: the same content plus an appended Apache
  error-log excerpt. The `stat` line inside it records the 69 B marker.

The 1,995 B figure is the capture size, not the marker size.

## Bodies and calibration

| body | bytes | sha256 |
|---|---|---|
| A1 `a1_8234.bin` | 1,060,869 | `673cc3175551a35934d9ac11dbe26d06d9b83c6b3e32db35272eed515ab0201c` |
| B1 `b1_8234.bin` | 29,218,150 | `d4ef67293645f5beeafac1798f6fb92abed35fa90936b8a6fbfbcc522323e2d3` |

Both bodies were reconstructed byte-identically from session-recorded
generators and match the recorded Oct-24 hashes. They are not shipped in this
repository. The proof uses the 29,218,150 B B1 body and the 149-holder pin.
The driver (`cold_chain.py`, 13,391 B, sha256
`d7d95f689aa869823f112a6676fe412a367b612ebd47df63758d722ca98ce4ac`) is also
retained privately.

`c1.bin` belongs to a later B1c lane, is not an input to this chain and is not
shipped. No claim is made here about its priming geometry.

## Configuration and integrity

| item | measured value |
|---|---|
| image | `php:8.2.34-apache` |
| image id | `sha256:f380b054d6364b80f0952a9198e5dc1e1ab4d809aad24d3f3174f059e863f48a` |
| PHP | `PHP 8.2.34 (cli) (built: Oct 21 2026 00:35:21) (NTS)` |
| Apache | `Apache/2.4.69 (Debian)`, prefork mod_php |
| MPM | `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0` |
| php.ini | `php.ini-production`, 73,870 B, `b40aed987458694f7d81b0e469e05d125fff3175d9901fe70a6321ed833af9e1`; `memory_limit=128M`, `display_errors=Off` |
| docroot | `/var/www/html`, 22-byte `/index.php` stub, `1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23` |
| ASLR | on at the host (`randomize_va_space=2`) |
| traffic | loopback only; access logs contain only `127.0.0.1` and `172.17.0.1` |

The source manifest and the source per-file hashes were verified before
publication. The published subset is re-hashed in `sha256sums.txt`.

## Superseded negative evidence

`evidence/` is the earlier public rerun with the stock early A1. It reached only
a parse-time OOM (`tried to allocate 8192 bytes`) and B1 returned no pointers
(`decoded=34`); it produced no target-written proof. It is preserved as
historical evidence and is superseded by the recovered-body rerun recorded
here. See `evidence/SUPERSEDED.md`.

## Limitations

- Loopback lab only; the attacker model assumes the ability to hold about 150
  simultaneous HTTP connections against the stock 150-worker prefork pool.
- The image's own `php.ini-production` is mounted, the same baseline as the
  Oct-24 lane; this is not a pristine no-INI default.
- The proof is a lab marker file, not an out-of-band channel or a published PoC.
- The 149-holder pin is a pool-exhaustion primitive, not a configuration change.
- The chain is build-specific: do not reuse these offsets or bodies on another
  build.
