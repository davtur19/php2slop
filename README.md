# php2slop

**Status: WIP.** Research exploit for the PHP `session.upload_progress` UAF
(CVE-2026-109618/109619). Not universal and not a stock-default exploit: every
positive needs a specific build and lab configuration, and most need
`display_errors=On`, a single worker and a small `memory_limit`.

## Works (lab-verified, conditional)

- mod_php, PIE + ASLR, `display_errors=On`, single Apache prefork worker:
  PHP 8.3.35/8.4.26/8.5.11 — two-stage `Set-Cookie` leak → `zif_system`,
  one-shot. Existence evidence, not a reliability rate.
- 9bie ASLR reproduction (official `php:8.4.26-apache`/`8.5.11-apache`,
  unmodified repo PoC, ASLR on, single worker, `display_errors=On`, 12 MB
  field): 3/3 on 8.4.26 and 3/3 on 8.5.11 at 8M; 2/2 each at 16M. Leaked
  libphp base matched `/proc/1/maps` 6/6.
- 128M header flood (stock official images, no php.ini, single prefork
  worker): 500,000 `X: v` headers / 3,072,588 B OOMs PHP
  8.3.35/8.4.26/8.5.11; 425,000 does not, so the threshold is between 425k
  and 430k. Full upstream chain 2/2 on fresh containers. Availability/OOM
  arm only; stock images default to `display_errors=On`.

## Does not work / blocked

- 9bie `display_errors=Off`: 0/2 at 8M and 0/2 at 16M (both versions). The
  `max_input_vars` warning must set `SG(headers_sent)=1`, otherwise
  `php_session_send_cookie()` clears `PS(send_cookie)`. The leak is an OOB
  `Set-Cookie: PHPSESSID` read, not error text. The Off branch reaches only a
  4000 B / 47-pointer chunk-base leak; stages 2–3 are unresolved.
- 9bie at 128M: 12 MB field does not OOM; 63 MB gets stage 1/2 2/2 but
  stage 3 0/2 (uncalibrated geometry, not impossibility). No FPM evidence
  (mod_php only); no PHP 7.x. PHP 8.2.34 is in range but the shipped offsets
  are 8.4.26-specific, so it is not usable as shipped.
- Header flood full chain on a dirty 8.3.35 container: 0/3 (stale sessions),
  against 2/2 on fresh containers. No claim for a hardened
  `display_errors=Off` target.
- Stock PHP 8.0/7.2/7.3 negative; PHP 7.4 PIE blocked; PHP 5.x stock blocked.
- Stock Drupal/Joomla use database sessions, so no served session file.
- CVE-2026-109618 on FPM: pre-RINIT OOM makes the child exit 70 with zero
  PHP-origin bytes — availability only, no code execution. Public mod_php
  chains require `display_errors=On`; at `Off` they fail at the leak, and the
  128M `Off` artifact is not demonstrated.

## Lab-only (config delta, not stock)

- FPM serializer-decode lane on plain non-PIE PHP 8.5.10/8.4.25. Official
  PIE builds fail at `ps_serializers[2].decode`, and no in-band leak exists.
- Karasawa phar: `display_errors=Off`, PHP 8.5.4, 14/15 RCE, but it needs a
  pre-staged `.phar` whose stub calls `Phar::webPhar()`; there is no remote
  planting.
- WordPress: needs the `cf7msm_force_session` mu-plugin, ~2M
  `memory_limit` and a served writable session directory.
- OpenMage 20.10.0: PIE POP with a second `php_serialize` writer plus a
  slow-upload race. Known OpenMage CVEs are admin/post-auth; phar
  deserialization is PR:N but conditional. This is a config delta, not stock.

## Pending

- 8.4.26 FPM strict-bar retest.
- CVE-2026-109619: conditional, unverified (clarification running; not claimed).
- Stock OpenMage 20.17.0 chain test.
- PHP 5.x and 7.0–7.1; WordPress/MediaWiki FPM 109618.

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
