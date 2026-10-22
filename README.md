# php2slop

**Status: WIP.** Work in progress, not a universal or stock-default exploit;
every success needs a specific build and lab configuration (PHP `session.upload_progress` UAF, CVE-2026-109618/109619).

**Works (lab-verified):**
- mod_php, PIE + ASLR, `display_errors=On`, single worker: PHP 8.3.35/8.4.26/8.5.11 — two-stage `Set-Cookie` leak → `zif_system`, one-shot.
- FPM serializer-decode route: reported on PHP 8.5.10 (profiles 8.4.25/8.1.34/7.4.33); **end-to-end verification running** — not yet confirmed in the README.
- OpenMage 20.10.0 PIE POP with a second `php_serialize` writer + slow-upload race.

**Does not work / blocked:**
- 9bie-style in-band FPM chain (8.3.35/8.5.10/8.5.11).
- `display_errors=Off` (stage 2); PHP 8.2.34 (`session_reset_id`/`mod_data` SIGSEGV); PHP 7.4 PIE; PHP 5.x stock.
- Multi-worker (~20% E2E); WordPress default (no `session_start()`); MediaWiki FPM.

**Lab-only:** non-PIE 7.0–8.0 serializer/decode; PHP 5.4/5.6 served-file/GOT.

**Pending:** FPM serializer-decode E2E verification; PHP 8.1/8.0/7.2/7.3; FPM 8.4.26; `display_errors=Off` alternative trigger.

## Requirements

- python3 ≥ 3.10, stdlib only; a target you own supplied by the operator (`--target wiki|wp|modphp` → 127.0.0.1, or a URL); `gdb`/`nm`/`readelf` optional for new builds.

## Build and usage

No build step; run in place with `./tool/php2shell.py` or `python3 -m tool`.

```sh
./tool/php2shell.py --target wiki --step recon
./tool/php2shell.py --target modphp --step chain \
  --unser-url http://127.0.0.1:8080/unser.php --arm-url http://127.0.0.1:8080/
./tool/php2shell.py --target modphp --step producer --producer unser \
  --unser-url http://127.0.0.1:8080/unser.php --memory-limit 2M
```

`recon`, `producer` and `chain` send to the operator-supplied target; `chain`
is the public end-to-end path. Output: `files/io/<target>-<step>-<timestamp>/`.
Internal calibration stages (`write_stage`, `leak`) are documented in `USAGE.md`.

## Scope and license

Authorized testing on operator-owned targets only. AGPL-3.0; see `LICENSE`; details in `USAGE.md` and `docs/`.
