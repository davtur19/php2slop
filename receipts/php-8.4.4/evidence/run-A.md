# Run A — tag `PR844A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `780 1792978413 POST /index.php 500 - 89985` |
| POST | `780 1792978413 POST /index.php 200 3 49772` |
| POST | `780 1792978413 POST /index.php 500 - 59726` |

Error-log lines for pid 780:

```
[Mon Oct 26 01:33:33.232859 2026] [php:error] [pid 780:tid 780] [client 172.17.0.1:32994] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:33:33.345893 2026] [php:warn] [pid 780:tid 780] [client 172.17.0.1:32996] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:33:33.345926 2026] [php:warn] [pid 780:tid 780] [client 172.17.0.1:32996] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:33:33.345932 2026] [php:warn] [pid 780:tid 780] [client 172.17.0.1:32996] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:33:33.498064 2026] [php:error] [pid 780:tid 780] [client 172.17.0.1:33012] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:33:33.927679 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 780 exit signal Segmentation fault (11)
```

Proof: `PR844A` (61 bytes, sha256 `fdef16d3de6f81193a204e1baad8bbdb28c180a26690d3e5c9ff1a008d4b4525`), mtime 1792978413 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
