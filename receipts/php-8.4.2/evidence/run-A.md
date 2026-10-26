# Run A — tag `PR842A` (log-level record)

The per-stage JSON of this run was overwritten by the later B run. This is the
unmodified `%P` access-log record and error-log record for the worker that served
all four stages, plus the proof file itself.

| stage | line (`pid epoch method path status bytes duration_us`) |
|---|---|
| POST | `771 1792978356 POST /index.php 500 - 99301` |
| POST | `771 1792978356 POST /index.php 200 3 51735` |
| POST | `771 1792978357 POST /index.php 500 - 58421` |

Error-log lines for pid 771:

```
[Mon Oct 26 01:32:36.814464 2026] [php:error] [pid 771:tid 771] [client 172.17.0.1:54018] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:32:36.928870 2026] [php:warn] [pid 771:tid 771] [client 172.17.0.1:54030] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:32:36.928891 2026] [php:warn] [pid 771:tid 771] [client 172.17.0.1:54030] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:32:36.928896 2026] [php:warn] [pid 771:tid 771] [client 172.17.0.1:54030] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:32:37.078826 2026] [php:error] [pid 771:tid 771] [client 172.17.0.1:54044] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:32:37.236276 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 771 exit signal Segmentation fault (11)
```

Proof: `PR842A` (61 bytes, sha256 `e7b73fc6a2b63922c6402f21aeacaee4b3162b1f851a090f90c97b6a2983fb8d`), mtime 1792978357 (same second as the A2 log line),

The B2 request itself is not access-logged: the worker dies in the destructor
before the log line is written. The proof file appears in the same second as A2.
