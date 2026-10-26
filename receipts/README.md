# mod_php `session.upload_progress` UAF — reproduction receipts

Run date: 2026-10-26 (rerun) · historical proofs: 2026-10-23 · tree generated from a private scratch root; host paths, container names and host ports are redacted.

Four provenance classes appear in this tree:

- **rerun** — 8.4.1–8.4.7, executed 2026-10-26 in this session on official `php:<v>-apache` images. Raw responses, Apache logs and per-stage JSON are included.
- **recovered-body rerun** — 8.2.34 and 8.3.35, executed 2026-10-26 on fresh stock images with the Oct-24 bodies rebuilt byte-identically from session-recorded generators. Proof captures and decoded leak JSON are included; raw responses, logs and bodies are retained privately.
- **copied** — 8.4.10–8.4.26, produced 2026-10-23 in the earlier matrix run, copied byte-for-byte and hash-verified, **not** re-executed in this session.
- **superseded negative** — the earlier public rerun of 8.2.34/8.3.35 with the stock early A1, preserved under each build's `evidence/`; it produced no target-written proof and is not the basis for the ✅ rows.

## Status

### Rerun this session (target-written proofs for 8.4.1–8.4.7)

| build | chain runs | A1 / B1 / A2 / B2 | proofs | proof files |
|---|---|---|---|---|
| 8.4.1 | A, B, C, +1 failed, WP | 500 / 200 / 500 / 0 | 3 + WP | PR841A 61B, PR841B 61B, PR841C 61B, PR841WP 62B |
| 8.4.2 | A, B, C | 500 / 200 / 500 / 0 | 3 | PR842A 61B, PR842B 61B, PR842C 61B |
| 8.4.3 | A, B, C | 500 / 200 / 500 / 0 | 3 | PR843A 61B, PR843B 61B, PR843C 61B |
| 8.4.4 | A, B, C | 500 / 200 / 500 / 0 | 3 | PR844A 61B, PR844B 61B, PR844C 61B |
| 8.4.5 | A, B, C | 500 / 200 / 500 / 0 | 3 | PR845A 61B, PR845B 61B, PR845C 61B |
| 8.4.6 | A, B, C | 500 / 200 / 500 / 0 | 3 | PR846A 61B, PR846B 61B, PR846C 61B |
| 8.4.7 | A, B, C | 500 / 200 / 500 / 0 | 3 | PR847A 61B, PR847B 61B, PR847C 61B |

`A1 / B1 / A2 / B2` are HTTP statuses; B2 is always `0` response bytes on success.

### Recovered-body rerun (target-written proofs for 8.2.34 and 8.3.35)

| build | chain runs | A1 / B1 / A2 / B2 | proofs | proof files |
|---|---|---|---|---|
| 8.2.34 | `8234b_r1`, `8234b_r2` | 500 / 200 / 500 / 0 | 2 | `php-8.2.34/proof/proof_8234b_r1.txt` 1,995 B capture, `php-8.2.34/proof/proof_8234b_r2.txt` 124 B capture |
| 8.3.35 | `8335b_r1`, `8335b_r2` | 500 / 200 / 500 / 0 | 2 | `php-8.3.35/proof/proof_8335b_r1.txt` 1,995 B capture, `php-8.3.35/proof/proof_8335b_r2.txt` 124 B capture |

The in-container marker is 69 B in all four runs. The 1,995 B `r1` capture
includes an appended Apache error-log excerpt; the 124 B `r2` capture is the
`stat` line, uid line and tag only.

In this tree, 8.4.1–8.4.7 are target-written (rerun: 3 proofs per build, plus
the 8.4.1 WordPress control); 8.4.10–8.4.26 are copied target-written proofs
(17 plus the WordPress 7.1.3 control); 8.2.34 and 8.3.35 are target-written
from the recovered-body rerun (2 proofs each).

### Copied proofs from the 2026-10-23 matrix run (target-written, not re-executed)

| build | proof file | size | sha256 |
|---|---|---|---|
| 8.4.10 | p1_conc_M84_8410_a | 65 B | bbbb206d0b5a07a7… |
| 8.4.11 | p1_conc_M84_8411_a | 65 B | a44086204e82d9af… |
| 8.4.12 | p1_conc_M84_8412_a | 65 B | 81f832a9ee5995a1… |
| 8.4.13 | p1_conc_M84_8413_b | 65 B | e89329d80d5cc9ff… |
| 8.4.14 | p1_conc_M84_8414_a | 65 B | 751bd28acf12df47… |
| 8.4.15 | p1_conc_M84_8415_a | 65 B | 09b418d369954978… |
| 8.4.16 | p1_conc_M84_8416_a | 65 B | 6d3df9c57791583d… |
| 8.4.17 | p1_conc_M84_8417_a | 65 B | 936db1025b444724… |
| 8.4.18 | p1_conc_M84_8418_a | 65 B | 7822f196fff39dad… |
| 8.4.19 | p1_conc_M84_8419_a | 65 B | 66e6176d52804708… |
| 8.4.20 | p1_conc_M84_8420_a | 65 B | 21285c793060900d… |
| 8.4.21 | p1_conc_M84_8421_a | 65 B | d482f1a9854699fc… |
| 8.4.22 | p1_conc_M84_8422_a | 65 B | 8fdb0411c141955e… |
| 8.4.23 | p1_conc_M84_8423_a | 65 B | c23439ab82f4d81e… |
| 8.4.24 | p1_conc_M84_8424_a | 65 B | cd41b42743685010… |
| 8.4.25 | p1_conc_M84_8425_a | 65 B | 0cd5318ee3e9bfc1… |
| 8.4.26 | p1_conc_M84_8426_a | 65 B | 879c05d545aa675e… |

WordPress 7.1.3 on 8.4.26: `wordpress-7.1.3-php-8.4.26/proofs/p1_conc_WP713` (60 B, marker `WP713`).

## What `target-written` means in this tree

A file counts as a proof only if all of the following hold:

1. It contains `uid=33(www-data) gid=33(www-data) groups=33(www-data)` **and** the per-run marker that appears in the B2 command string.
2. It appeared after the B2 request. The driver deletes the path inside the container (`rm -f /var/log/apache2/pwn<tag>`) immediately before B2.
3. For the 8.4 rerun builds, the container-side owner is `www-data www-data 33 33` and the host-side owner is uid 100032 (the rootless mapping of container uid 33). The harness runs as uid 1000, so a harness-created file would carry uid 1000.
4. The proof mtime falls within one second of that run's A2 log line (0 s or +1 s), and the child that served A1/B1/A2 dies with `AH00052: child pid N exit signal Segmentation fault (11)` right after B2.
5. No harness code path creates files in the bind-mounted log directory: `tools/chain_early.py` deletes the proof path before B2, otherwise only reads it (`last_log_line`, `cat`, `stat`), and writes its outputs only to `--outdir`.

For the recovered 8.2.34/8.3.35 runs, the proof path is `/tmp/p1`, the driver
deletes it before the run and only cats it after the run, and the captures
record the 69 B marker with owner `www-data:www-data`. The same-child check is
the Apache error-log pid sequence (A1 OOM, B1 session warnings, A2 OOM, B2
SIGSEGV); the stock access-log format does not carry a pid. See each build's
`report.md` for the per-run pids.

For the copied proofs, 1–2 are checkable from `final.json` (`chain.proof`, `chain.b2.cmd`, `b2_hit`); 3–5 are documented in `report.md` §3 but cannot be re-derived from the stored records.

## Verify this tree

From this directory:

```bash
sha256sum -c sha256sums.txt
python3 tools/verify_receipts.py
```

Per-build sums are relative to the build directory:

```bash
cd php-8.2.34 && sha256sum -c sha256sums.txt
cd ../php-8.3.35 && sha256sum -c sha256sums.txt
```

`verify_receipts.py` re-checks every hash, re-parses every `Set-Cookie` leak from the raw response (decoded length and `zval_ptr_dtor` hit count against `result-*.json`), and checks every proof's uid line and marker.

## Claim support against `README_published.md`

| published claim | verdict from this tree |
|---|---|
| 8.4.1–8.4.7 ✅ — direct mod_php chain, target-written `uid`, `S=main+0xED398` | **supported** — 21/21 rerun chain runs plus a WordPress silence-file control on 8.4.1. Caveats: the published row says “WordPress core silence file”, while the main runs used the 22-byte `/index.php` stub (as the D3 report itself specifies); and the 8.4.7 note “no `%P`” does not describe this rerun, which added `%P` to the access-log format for PID attribution (logging only, no functional change). |
| 8.2.34 ✅ — full chain, target-written `uid` | **supported** — 2/2 target-written proofs on a fresh stock image with the recovered Oct-24 bodies; B1 1,383,427 B encoded / 1,169,032 B decoded, `n=584`, 44 main hits; same-child pid; 69 B marker. Caveats: bodies rebuilt from session records and not shipped; 149-holder pin; production INI mount; lab marker. |
| 8.3.35 ✅ — full chain, target-written `uid` | **supported** — same shape with the recorded 8.3.35 calibration (`zval_ptr_dtor=0x49EC50`, `zif_system=0x3AC080`); B1 1,380,063 B encoded / 1,169,032 B decoded, `n=584`, 44 main hits; same caveats. |
| 8.4.10–8.4.26 ✅ — distinct target-written `uid` proofs, `S=main+0xF8398` | **supported as copied evidence** — 17/17 proofs present and hash-verified; not re-executed in this session. |
| 8.4.26 on pristine WordPress 7.1.3 — target-written `uid` | **supported as copied evidence** — `p1_conc_WP713`, 60 B, marker `WP713`. |
| 8.4.27 🚫 fixed | not tested in this session; no artifact here. |

## Discrepancies and errata

- The D3 report lists Apache `2.4.69` for 8.4.1–8.4.7. The official images measure **Apache 2.4.62 (Debian)** at run time (`apache2 -v` inside each container). 2.4.69 is what 8.2.34/8.3.35 ship.
- The published 8.4.1–8.4.7 row says “WordPress core silence file”; the D3 report and this rerun use the 22-byte lab endpoint. The 8.4.1 WP control shows the chain works identically on the real silence file, so the difference is cosmetic — but the row's wording does not match the recorded early-build runs.
- The published 8.4.7 note says “no `%P`”; this rerun added the `%P` log format. The attack traffic is unchanged.
- 8.4.1–8.4.7 were previously reported as needing “a different early-cleanup groom” (matrix report); the D3 report later solved it with the stage-1 A1 shipped here, and this rerun confirms 21/21.
- The 8.2.34/8.3.35 in-container marker is 69 B. The published capture files are 124 B (`r2`: stat, uid and tag) and 1,995 B (`r1`: the same plus an appended error-log excerpt). The 1,995 B figure is a capture size, not the marker size.

## Superseded negative evidence (8.2.34 / 8.3.35)

The earlier public rerun with the stock early A1 is preserved under
`php-8.2.34/evidence/` and `php-8.3.35/evidence/`. It reached only the
parse-time OOM and B1 returned no pointers; it produced no target-written
proof. It is labeled superseded and is not the basis for the ✅ rows. The
recovered-body rerun is recorded in each build's `report.md`, `proof/` and
`decoded/`.

## Layout

```
README.md              this file
sha256sums.txt         every file in the tree
commands.txt           exact commands (placeholders for paths/ports/containers)
bodies/                a1_early.bin.xz, b1_early.bin.xz (+ uncompressed sha256)
tools/                 chain driver, body generator, pure helpers, setup + verify scripts
php-8.4.1/ … php-8.4.7/
  README.md            measured target, constants, runs, proof provenance
  proofs/              target-written uid files, verbatim
  evidence/            result JSON, raw responses/logs, mounted config, env manifest
php-8.2.34/, php-8.3.35/
  README.md            measured target, recovered bodies, runs, proof provenance
  report.md            redacted report
  commands.txt         exact recovered-body commands
  proof/               target-written uid captures, verbatim
  decoded/             decoded leak JSON
  evidence/            earlier negative rerun, marked superseded
  sha256sums.txt       hashes for this directory
php-8.4.10/ … php-8.4.26/, wordpress-7.1.3-php-8.4.26/
  README.md            copied-proof record
  proofs/              copied target-written uid files, verbatim
  evidence/final.json  original per-build record (port redacted)
  report.md            verbatim copy of the matrix report
```

## Redaction

Scratch paths, the home directory, container names and host ports were replaced with `<RUNDIR>`, `<HOME>`, `<container>` and `<redacted>` in JSON and text evidence. Image names, image IDs, repo digests, PHP/Apache versions and package strings are kept. The 8.2.34/8.3.35 proof captures contain only the in-container marker path `/tmp/p1`; no host path is published. Other proof files contain no paths and are byte-identical to the originals.
