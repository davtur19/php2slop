# php8pie_20261022_0325

PHP 8.5.10 PIE FPM lab receipt: ASLR-on session-file PIE base leak and
G2/G6 `php_binary` decode-slot overwrite to `zif_passthru`.

Open `REPORT.md` for the full result. Quick facts:

* Binary: `src/php-8.5.10/sapi/fpm/php-fpm`, ELF `DYN`, not stripped,
  BuildID `69ef9c150adebfd8c7409304eef1dc9ddabc2810`.
* ASLR on (`randomize_va_space=2`); leaked base `0x556e4a800000`.
* Leak: encoder overread of the S zend_string; the served session file
  (`req/leak3_served.bin`, 135369 bytes) contains exactly one PIE pointer at
  payload `+0x88`: `0x556e4ae644e5 = base + zval_ptr_dtor(0x6644e5)`.
  Reproduce with `python3 phase/analyze_leak.py`.
* Chain: `phase/rec_zif_final.bin` writes `zif_passthru`
  (`base+0x464c15`) into `ps_serializers[2].decode`
  (`base+0x10c1980`), using `K=-2883979953001`.
* Result: `run/M_ZIF` contains `PIE_ZIF`; trigger HTTP 200; worker 1701090
  (gdb-instrumented run) and worker 1709897 (clean no-gdb rerun) both
  survived and served a later `info.php` with the same PID.

Layout:

```
conf/    nginx + fpm configs
www/     test scripts and the live session directory
phase/   builders, records, gdb scripts, profiles
req/     plant/trigger responses and the served leak artifact
log/     gdb logs, leak analysis, binary/offset evidence, fpm/nginx logs
run/     pids and the PIE_ZIF marker
src/     PHP 8.5.10 build tree (only the binary/config are checksummed)
```

No git commit. Lab ports 28931/28933 only; WP lab and shared PIDs untouched.

## Repository curation note (this copy)

The source receipt's `src/` was a **445 MB** PHP 8.5.10 build tree. The public copy keeps only
`src/php-8.5.10/config.nice` (the configure provenance quoted in `REPORT.md`); the object
files, generated makefiles and the **42 MB** `sapi/fpm/php-fpm` binary are not included. The
binary identity used by the report is BuildID `69ef9c150adebfd8c7409304eef1dc9ddabc2810`;
its offsets are reproducible from that build.

`www/` keeps the test scripts and the live session captures (`www/sess/sess_*`) that the
analysis reads; nginx temp directories and sockets are omitted. `SHA256SUMS` was regenerated
for the curated set (every file except itself), so `sha256sum -c SHA256SUMS` passes here; the
source manifest covered 118 of these files, skipped only the 42 MB binary, and differs from
this copy only in this README.
