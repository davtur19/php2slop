# Run A — tag `PR841A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `806 1792978296 POST /index.php 500 - 84061` |
| POST | `806 1792978296 POST /index.php 200 3 51056` |
| POST | `806 1792978296 POST /index.php 500 - 55491` |

Error-log lines for pid 806:

```
[Mon Oct 26 01:31:36.167288 2026] [php:error] [pid 806:tid 806] [client 172.17.0.1:47308] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:31:36.290614 2026] [php:warn] [pid 806:tid 806] [client 172.17.0.1:47322] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:31:36.290641 2026] [php:warn] [pid 806:tid 806] [client 172.17.0.1:47322] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:31:36.290645 2026] [php:warn] [pid 806:tid 806] [client 172.17.0.1:47322] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:31:36.434373 2026] [php:error] [pid 806:tid 806] [client 172.17.0.1:47328] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:31:36.840130 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 806 exit signal Segmentation fault (11)
```

Proof: `PR841A` (61 bytes, sha256 `5a0de9d3b6956b995b98c1a7e2b4730585c8197f1045210929383d1461f93aab`), mtime 1792978296 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
