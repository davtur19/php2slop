# php2slop

**Status: WIP.** Work in progress, not a universal or stock-default exploit:
every success below needs a specific build and lab configuration.

Offline record builder and lab driver for the PHP `session.upload_progress`
use-after-free family (CVE-2026-109618 / CVE-2026-109619).

## Works (verified)

| setup | result |
|---|---|
| mod_php (Apache prefork), PIE + ASLR on, `display_errors=On`, single worker: PHP 8.3.35, 8.4.26, 8.5.11 | two-stage `Set-Cookie` leak → `zif_system`, one-shot |
| OpenMage 20.10.0 PIE POP | needs a second `php_serialize` writer on the same `save_path` + slow-upload race |
| lab-only non-PIE: PHP 7.0–8.0 | serializer/decode chain |
| lab-only non-PIE: PHP 5.4 / 5.6 | served-session-file / GOT chain |

## Does not work (verified)

- FPM 8.3.35, 8.5.10, 8.5.11: child exit/RSHUTDOWN, no in-band leak; FPM 8.4.26 pending.
- `display_errors=Off`: stage 2 fails.
- PHP 8.2.34: `session_reset_id` clears `send_cookie`, dangling `mod_data` → SIGSEGV.
- PHP 7.4 PIE: no write primitive or natural chain.
- PHP 5.x stock: no `system` import / heap mismatch; 5.0–5.3 lack stale state.
- Multi-worker prefork: ~20% end-to-end, not one-shot.
- WordPress default: no `session_start()`; MediaWiki on FPM: blocked.

## Pending

PHP 8.1, 8.0, 7.2/7.3 chain hunts; FPM 8.4.26; a `display_errors=Off` alternative trigger.

## Requirements

- python3 ≥ 3.10, standard library only.
- A target you own, passed by the operator: `--target wiki|wp|modphp` (mapped to 127.0.0.1) or `--target http://127.0.0.1:8080`.
- Optional: `gdb`, `nm`, `readelf` to derive offsets for new builds.

## Build and usage

No build step; run in place with `./tool/php2shell.py` or `python3 -m tool`.

```sh
./tool/php2shell.py --target wiki --step recon
./tool/php2shell.py --target modphp --step chain \
  --unser-url http://127.0.0.1:8080/unser.php --arm-url http://127.0.0.1:8080/
./tool/php2shell.py --target modphp --step producer --producer unser \
  --unser-url http://127.0.0.1:8080/unser.php --memory-limit 2M
```

`recon`, `producer` and `chain` send to the operator-supplied target; the
public end-to-end path is `--step chain`. Output goes to
`files/io/<target>-<step>-<timestamp>/`. Internal transport-less planning
stages (`leak`, `g2`) live in `USAGE.md` and are not needed for normal use.

## Scope and license

Authorized testing on operator-owned targets only. AGPL-3.0; see `LICENSE`.
Details: `USAGE.md` and `docs/`.
