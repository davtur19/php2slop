# Extra chain attempt — pid 1186 (no proof)

This attempt reached B2 and the worker died with `SIGSEGV` without executing the
command, so no proof file exists for it. The chain was repeated; the `PR841B` proof
in `proofs/` is from the successful repeat.

| stage | line |
|---|---|
| POST | `1186 1792978314 POST /index.php 500 - 84426` |
| POST | `1186 1792978314 POST /index.php 200 3 40401` |
| POST | `1186 1792978314 POST /index.php 500 - 57869` |

Error log:

```
[Mon Oct 26 01:31:54.359728 2026] [php:error] [pid 1186:tid 1186] [client 172.17.0.1:36534] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Mon Oct 26 01:31:54.473841 2026] [php:warn] [pid 1186:tid 1186] [client 172.17.0.1:36546] PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in Unknown on line 0
[Mon Oct 26 01:31:54.473862 2026] [php:warn] [pid 1186:tid 1186] [client 172.17.0.1:36546] PHP Warning:  PHP Request Startup: Failed to read session data: files (path: ) in Unknown on line 0
[Mon Oct 26 01:31:54.473867 2026] [php:warn] [pid 1186:tid 1186] [client 172.17.0.1:36546] PHP Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in Unknown on line 0
[Mon Oct 26 01:31:54.623306 2026] [php:error] [pid 1186:tid 1186] [client 172.17.0.1:36552] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[Mon Oct 26 01:31:54.870004 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 1186 exit signal Segmentation fault (11)
```
