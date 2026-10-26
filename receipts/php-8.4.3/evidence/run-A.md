# Run A — tag `PR843A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `776 1792978381 POST /index.php 500 - 102273` |
| POST | `776 1792978381 POST /index.php 200 3 50545` |
| POST | `776 1792978381 POST /index.php 500 - 59097` |

Error-log lines for pid 776:

```
[Mon Oct 26 01:33:01.488474 2026] [php:error] [pid 776:tid 776] [client 172.17.0.1:48504] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:33:01.609205 2026] [php:warn] [pid 776:tid 776] [client 172.17.0.1:48512] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:33:01.609223 2026] [php:warn] [pid 776:tid 776] [client 172.17.0.1:48512] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:33:01.609228 2026] [php:warn] [pid 776:tid 776] [client 172.17.0.1:48512] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:33:01.763308 2026] [php:error] [pid 776:tid 776] [client 172.17.0.1:48518] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:33:01.971676 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 776 exit signal Segmentation fault (11)
```

Proof: `PR843A` (61 bytes, sha256 `5c539b9061c5fe394138065f2d0e40466bb86fc3e2820638b65d08636974fd94`), mtime 1792978381 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
