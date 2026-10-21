# M4 measured summary (php_admin_value[unserialize_callback_func]="")

PHP 8.5.10 FPM (ASAN build), loopback FastCGI, one worker per pool (`pm.max_requests=0`). `marker` = `D2::__destruct` wrote a file.

| lane | pool pin | probe callback (access) | ini_set result | script `unserialize()` marker | predefined-class marker | pre-script marker | class at script entry |
|---|---|---|---|---|---|---|---|
| l0 | none (no .user.ini; PHP defaults) | '' (access=7) | '' | no | **yes** | upload-progress: no | false |
| l1 | none (docroot .user.ini sets callback) | 'spl_autoload' (access=7) | 'spl_autoload' | **yes** | **yes** | upload-progress: **yes** | true |
| l2 | php_admin_value[unserialize_callback_func]="" | '' (access=4) | false | no | **yes** | upload-progress: no | false |
| l3 | callback="" + include_path="." | '' (access=4) | false | no | **yes** | upload-progress: no | false |
| l4 | none (docroot .user.ini, auto_start=1) | 'spl_autoload' (access=7) | 'spl_autoload' | **yes** | n/a | auto_start: **yes** | true |
| l5 | callback="" (auto_start=1) | '' (access=4) | false | no | n/a | auto_start: no | false |

Raw probe transcripts: `results/effective_ini.txt`, `results/transcripts/<lane>_*.http`; one JSON row per request in `results/m4_results.jsonl`.

## Orthogonality check: stock OOM arm on the pinned pool (l6, 8M)

- body sent: 4983495 B; response 139 B, sha `b5e7074e0e774ad4a713ee2b3413151059b40c8ac874bed0752d2c0637d7ea2b`
- body: `Fatal error: Allowed memory size of 8388608 bytes exhausted (tried to allocate 1052672 bytes) in Unknown on line 0 / Stack trace: / #0 {main}`
- result: pre-RINIT OOM **still fires** with the callback pinned empty; the FPM worker exits 70 (see `logs/fpm-master.log`). M4 does not touch the multipart allocation.
