# apppop run journal (UTC)

Receipt: /tmp/opencode/research/apppop_20261022T015427Z
Lab: MediaWiki 1.46.2, nginx 127.0.0.1:28866, PHP-FPM 8.5.10 (private master 1666498)

## Baseline (03:57 UTC)
- health 200; session dir /tmp/opencode/research/wikitype_20261021T212610Z/sessions
- pool: save_handler=files, save_path=sessions, serialize_handler=php,
  upload_progress enabled=1 cleanup=0 prefix="" freq=1 min_freq=0
- TestClass registered via $wgAutoloadClasses (lab-only, marker files under phase/markers)
- normal request: no marker (class not loaded unless unserialized)

## CLI encoder probe (03:57 UTC)
- php 8.5.10 CLI: $_SESSION["x|O:9:\"TestClass\":0:{}"]=1; session_write_close()
  -> Warning: Failed to write session data. Data contains invalid key ...
  -> sess file 0 bytes
- control key upload_progress_x -> file upload_progress_x|a:1:{s:1:"a";i:1;}

## HTTP upload (03:59 UTC)
- first attempt with only wikidb_session cookie: no progress write (session.name
  at request parse time is PHPSESSID, not wikidb_session) -> file unchanged
- with Cookie: PHPSESSID=<sid>; wikidb_session=<sid>: progress write lands
  (cleanup=0): existing fr-unsub + x|a:5:{...} in file
- payload x|O:9:"TestClass":0:{}: PHP Request Startup warnings
  "Failed to write session data. Data contains invalid key ..." x9,
  session file truncated to 0 bytes, no markers

## Out-of-band decode proof (03:59:54 UTC)
- valid SID from optin; file overwritten with
  x|O:9:"TestClass":0:{}|a:5:{...}
- GET optin with same cookie -> 200
- markers: class_file_loaded (autoloader), testclass_wakeup, testclass_destruct
- file after: x|O:9:"TestClass":1:{s:1:"p";s:1:"x";}|a:5:{...}fr-unsub|...
  => php serializer decode at session_start, autoload OK, trailing data tolerated

## Later runs (dates UTC; local = UTC+2)

- 02:00 cleanup matrix: cleanup=1 removed the benign progress key at request shutdown
  (`sess_5ptn`, 223 B, only fr-unsub); cleanup=0 retained it after abort
  (`sess_ccue`, 560 B, `done:1`). In-flight cleanup=1 snapshot: 535 B with `x|a:5:{...done:0...}`
  (`log/slowabort_cleanup_on.txt`).
- 02:00-02:06 injection runs: `x|O:...` and `upload_progress_x|O:...` produced 0-byte session
  files plus `Failed to write session data. Data contains invalid key` warnings; counts and
  exact messages in `phase/php_error_excerpts.txt`.
- 02:01 CLI 5.6.40 / 7.0.33: 0-byte files for the pipe key, 22-byte controls
  (`phase/ver_sess/`). Repeated cleanly at 02:10 for 5.6.40/7.0.33/7.4.33/8.5.10
  (`phase/ver_cli_20261022/`, `phase/cli_matrix_20261022.txt`).
- 02:03-02:05 POP proofs over HTTP with MediaWiki-issued session ids and out-of-band session
  files: Guzzle FW1 marker JSON, MediaWiki FD1 victim delete, Monolog RCE8/RCE9 `touch`,
  Monolog FW1 file write. Monolog RCE2 failed with a typed-property TypeError (Monolog 3).
- 02:05 class resolution probe: Guzzle core, Monolog 3.12.1 extension vendor, TempFSFile core;
  `JakubOnderka\PhpParallelLint\FileWriter` not loadable (`phase/class_resolution.txt`).
- 02:07 negative controls: no autoloader -> no TestClass markers; only PHPSESSID -> no decode,
  new wikidb_session cookie.
- 02:14-02:18 clean re-proofs after the run: FD1 victim existed (38 B, sha256 271dad...)
  then absent, HTTP 200 (`phase/fd1_reproof_clean_20261022.txt`); Guzzle marker and RCE9
  touch marker re-created, HTTP 200 (`phase/pop_clean_reproof_20261022.txt`).
- 02:19-02:20 config restored: fpm.conf 201e55f9..., nginx.conf 065dbfde...,
  LocalSettings.php e259dacc... (byte-identical to pre-run); TestClass count 0;
  health 200; FPM master 1696968.
- 02:22 receipt README, source/CLI/error/config evidence files, SHA256SUMS (508 files).
- 02:25 13 representative lab `sessions/sess_*` files copied into `phase/`; original → copy map with
  bytes/sha256 in `phase/lab_session_snapshots.txt`; README evidence index updated.
- 02:26 SHA256SUMS regenerated over all 522 receipt files (`phpggc/.git/` excluded), verified clean.
