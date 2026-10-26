# Run A — tag `PR845A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `764 1792978437 POST /index.php 500 - 83674` |
| POST | `764 1792978438 POST /index.php 200 3 51850` |
| POST | `764 1792978438 POST /index.php 500 - 55563` |

Error-log lines for pid 764:

```
[Mon Oct 26 01:33:57.991354 2026] [php:error] [pid 764:tid 764] [client 172.17.0.1:34920] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:33:58.106457 2026] [php:warn] [pid 764:tid 764] [client 172.17.0.1:34926] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:33:58.106480 2026] [php:warn] [pid 764:tid 764] [client 172.17.0.1:34926] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:33:58.106485 2026] [php:warn] [pid 764:tid 764] [client 172.17.0.1:34926] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:33:58.254216 2026] [php:error] [pid 764:tid 764] [client 172.17.0.1:34942] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:33:58.953941 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 764 exit signal Segmentation fault (11)
[Mon Oct 26 01:34:11.868981 2026] [php:error] [pid 764:tid 764] [client 172.17.0.1:44654] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:34:11.980172 2026] [php:warn] [pid 764:tid 764] [client 172.17.0.1:44668] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:34:11.980196 2026] [php:warn] [pid 764:tid 764] [client 172.17.0.1:44668] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:34:11.980201 2026] [php:warn] [pid 764:tid 764] [client 172.17.0.1:44668] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:34:12.124599 2026] [php:error] [pid 764:tid 764] [client 172.17.0.1:44676] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:34:12.510008 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 764 exit signal Segmentation fault (11)
```

Proof: `PR845A` (61 bytes, sha256 `3d0dc74c098b991c7f56bd968df705f421f31dddf3fdc8f4dc7f09a846d699ec`), mtime 1792978438 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
