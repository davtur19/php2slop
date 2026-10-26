# Run A — tag `PR847A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `774 1792978492 POST /index.php 500 - 80563` |
| POST | `774 1792978492 POST /index.php 200 3 51024` |
| POST | `774 1792978492 POST /index.php 500 - 55116` |

Error-log lines for pid 774:

```
[Mon Oct 26 01:34:52.412544 2026] [php:error] [pid 774:tid 774] [client 172.17.0.1:47034] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:34:52.523453 2026] [php:warn] [pid 774:tid 774] [client 172.17.0.1:47046] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:34:52.523476 2026] [php:warn] [pid 774:tid 774] [client 172.17.0.1:47046] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:34:52.523482 2026] [php:warn] [pid 774:tid 774] [client 172.17.0.1:47046] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:34:52.668212 2026] [php:error] [pid 774:tid 774] [client 172.17.0.1:47058] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:34:53.089957 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 774 exit signal Segmentation fault (11)
```

Proof: `PR847A` (61 bytes, sha256 `8a4449f7e439ed5b14a0152f769353b501a25175786968473b2d283b023d1544`), mtime 1792978492 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
