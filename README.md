# php2slop

Offline record builder and lab driver for the PHP 8.5
`session.upload_progress` use-after-free family
(CVE-2026-109618 / CVE-2026-109619).

## Requirements

- python3 ≥ 3.10, standard library only.
- A loopback target you own (`wiki`, `wp` and `modphp` default to 127.0.0.1).
- Optional: `gdb`, `nm` and `readelf` to derive offsets for new builds.

## Build

No build step; run in place with `./tool/php2shell.py` or `python3 -m tool`.

## Usage

```sh
./tool/php2shell.py --target wiki --step recon
./tool/php2shell.py --target modphp --step chain
./tool/php2shell.py --target modphp --step producer --producer unser --memory-limit 2M
./tool/php2shell.py --target wiki --step write_stage --main-chunk 0x7f8875a00000
./tool/php2shell.py --step g2 --g2-x 0x7ffff7a6a000 --g2-p 0x7ffff7a81000 \
  --g2-b0 0x7ffff7a84000 --g2-total 131014 --command 'id;exit;#' \
  --libc-base 0x7ffff7c9c000
```

`producer`, `write_stage`, `leak` and `g2` are dry by default and write
`result.json` plus artifacts under `files/io/<target>-<step>-<timestamp>/`.
`--step g2` never opens a socket and refuses `--live`; profiles are md5 locked
and selected with `--g2-profile 8.5.10|8.4.25|8.1.34|7.4.33|<md5>`.

## Scope and limits

Authorized testing on operator-owned loopback targets only. The tool builds
records, profiles and request bytes; `--step g2` has no transport and refuses
`--live`.

## License

AGPL-3.0; see `LICENSE`. Details: `USAGE.md` and `docs/`.
