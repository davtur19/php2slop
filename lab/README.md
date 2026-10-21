# lab/ — one-off experiment jigs (not the tool)

Historical lab scripts kept as evidence of the run receipts. These replicate
the trigger experiments against local, operator-owned SAPIs and do not form
the take-and-run tool (that is `tool/`).

| file | what it does |
|---|---|
| `gen_shape.py` | S1/S2/S3/S5 multipart shape generator for the machinery hunt. |
| `slowfeed.py` | stdin feeder pacing body bytes (~40 KB/s default). |
| `sender_fpm.py` | staged HTTP sender for the 618 producer shape against the lab nginx->fpm stack (references an external BASE; read-only usage). |
| `feeder_f618.py` | phase1 / stall / tail stdin feeder for the 618 shape. |
| `probe_abort.sh` | client-abort mid-upload probe (checks worker health + leftover machinery state). |
| `probe_ov25.sh` | 25-file body through the CGI jig (max_file_uploads boundary behavior). |
| `run_trigger.sh` | 258-byte writeup trigger shape, stock min_freq vs min_freq=0. |
| `run_g618.sh` | gdb run of the staged 618 shape (inert forge) on the plain php-cgi build. |
| `run_p619.sh` | 619 shape run jig. |
| `run_asan_battery.sh` | ASAN battery over the attack shapes. |
| `build_asan.sh` | ASAN php-src build helper. |
| `g618.gdb`, `gdb_p4_*.gdb`, `gdb_p4_3.console` | gdb breakpoint scripts / captured console for the machinery OOM + free-window experiments. |
| `empty.php` | minimal CGI script file used by the jigs. |

Most scripts point at an external lab BASE directory and a lab php build via
absolute paths from the original run session; they are kept verbatim. See
`lab/` script headers before running anything.
