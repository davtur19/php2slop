# Run A — tag `PR846A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `776 1792978467 POST /index.php 500 - 84486` |
| POST | `776 1792978467 POST /index.php 200 3 46498` |
| POST | `776 1792978468 POST /index.php 500 - 55402` |

Error-log lines for pid 776:

```
[Mon Oct 26 01:34:27.868117 2026] [php:error] [pid 776:tid 776] [client 172.17.0.1:51594] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:34:27.974040 2026] [php:warn] [pid 776:tid 776] [client 172.17.0.1:51596] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:34:27.974063 2026] [php:warn] [pid 776:tid 776] [client 172.17.0.1:51596] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:34:27.974068 2026] [php:warn] [pid 776:tid 776] [client 172.17.0.1:51596] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:34:28.118883 2026] [php:error] [pid 776:tid 776] [client 172.17.0.1:51606] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:34:28.359695 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 776 exit signal Segmentation fault (11)
```

Proof: `PR846A` (61 bytes, sha256 `89d8bfcfe70beb96de0e0adb0464c507a2fe9c9ff12e7fd4dd402911370fed10`), mtime 1792978468 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
