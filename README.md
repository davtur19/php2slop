# php2slop

**Status: WIP.** Research exploit for the PHP `session.upload_progress` UAF
(CVE-2026-109618/109619). No stock-default RCE chain is demonstrated. Results
are split by whether they satisfy the chain validity rules below.

## Chain validity rules

- **Allowed:** a file written by the exploit chain itself (e.g. the session
  file PHP creates from `session.upload_progress`).
- **Not allowed / cheating:** pre-staged PHP files, `.user.ini`, custom
  `php.ini`, nginx/FPM config deltas, synthetic sessions, pre-staged `.phar`,
  admin/post-auth, app-specific vulnerabilities, LFI, gdb/operator addresses,
  single-worker/sticky routing.
- The target app must be stock. If it must already call `session_start()` or
  contain a custom `unser.php`/`index.php`, it is a pre-staged app and not a
  stock chain.

## Works (DoS / availability only)

- 128M header flood on stock official images (no `php.ini`, one prefork
  worker, `display_errors=On`, fresh state): 500,000 `X: v` headers /
  3,072,588 B OOMs PHP 8.3.35/8.4.26/8.5.11; 425,000 does not, so the
  threshold is between 425k and 430k. Availability only, not RCE; it needs
  `display_errors=On`, a single worker and fresh state. Dirty 8.3.35: 0/3,
  against 2/2 on fresh containers.
- CVE-2026-109618 on FPM: pre-RINIT OOM makes the child exit 70 with a 502;
  the parser OOM is contained. Availability only: no PHP-origin bytes and no
  code execution.
- No RCE chain currently satisfies the validity rules.

## Does not work / blocked

- 9bie `display_errors=Off`: no remote leak. The `max_input_vars` warning
  must set `SG(headers_sent)=1`, otherwise `php_session_send_cookie()` clears
  `PS(send_cookie)`. Off stage 2/3 works only in the lab (see below).
- 9bie at 128M: 12 MB field does not OOM; 63 MB gets stage 1/2 2/2 but stage
  3 0/2 (uncalibrated geometry, not impossibility). No FPM evidence (mod_php
  only), no PHP 7.x; PHP 8.2.34 is in range but the shipped offsets are
  8.4.26-specific.
- Stock PHP 8.0/7.2/7.3 negative; PHP 7.4 PIE blocked; PHP 5.x stock blocked.
- Stock Drupal/Joomla use database sessions, so there is no served session
  file.
- CVE-2026-109619: conditional, unverified; not claimed.

## Lab-only / pre-staged (not chains)

- **8.4.26 FPM (`fpm8426`):** the remote leak and
  `echo finalproof>/tmp/fpm8426_pwn` are real given the pre-staged
  `fpm8426_pre.php`, `fpm8426_state_b.php`, `.user.ini`, custom `php.ini` and
  nginx buffers. The exploit does not plant them; 5-worker end-to-end is
  unproven.
- **FPM synthetic-session lane:** synthetic session, `php_binary`, `/sessions`
  path and non-PIE binary; no stock target.
- **Karasawa phar:** 14/15 RCE on PHP 8.5.4 with `display_errors=Off`, but the
  `.phar` is pre-staged and its stub calls `Phar::webPhar()`; there is no
  remote planting.
- **9bie / Datadog mod_php:** custom `unser.php`/`index.php` and/or
  gdb-oracle addresses. Off: stages 2/3 work but there is no remote leak. On:
  the leak works only with `display_errors=On`.
- **mod_php two-stage `Set-Cookie` leak → `zif_system`:** one-shot on
  8.3.35/8.4.26/8.5.11 with `display_errors=On` and a single prefork worker;
  not valid under the rules.
- **Real-app WordPress/Drupal/Joomla:** rely on an mu-plugin, a files-handler,
  a 2M `memory_limit` and/or a served session directory. App/config specific,
  not a stock chain.
- **OpenMage 20.10.0:** PIE POP with a second `php_serialize` writer plus a
  slow-upload race; lab-only. The stock 20.17.0 test is pending.

## Pending

- 9bie session OOM: 16 KB OOB cookie for a heap pointer (mod_php PHP 8.4/8.5);
  no pointer yet.
- Stock OpenMage 20.17.0 chain test.
- CVE-2026-109618 source primitive.

## Requirements

- python3 ≥ 3.10, stdlib only; a target you own supplied by the operator (`--target wiki|wp|modphp` → 127.0.0.1, or a URL); `gdb`/`nm`/`readelf` optional for new builds.

## Build and usage

No build step; run in place with `./tool/php2shell.py` or `python3 -m tool`.

```sh
./tool/php2shell.py --target wiki --step recon
# --unser-url is a pre-staged lab endpoint, not a valid stock chain
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
