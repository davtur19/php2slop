# 109618 worker crashes observed per build (captured at run time)

`docker logs` lines (format: `[date] WARNING: [pool www] child <PID> exited on signal 11 (SIGSEGV) ...`).
8.1.34 / 8.2.34 containers were removed after their runs; the lines below are the ones captured
from `docker logs` during those runs (PIDs appear in the per-build evidence response files too).

## 8.0.30 (f80x-8030, logs/fpm-8.0.30/access.log + docker logs)
decode simple : 86 (09:18:44), 130 (09:20:02), 143 (09:20:02), 156 (09:20:03)
encode ref    : 107 (09:19:24), 114 (09:19:25), 121 (09:19:25)
decode ref    : 178 (09:29:38), 191 (09:29:38)

## 8.1.34 (f80x-8134)
decode ref    : 26, 39, 52, 65 (09:26:07-09:26:08)  [4/4]
encode ref    : none [0/4]
decode simple : none [0/4]

## 8.2.34 (f80x-8234)
decode ref    : 23, 30, 43 (09:27:37)  [3/3]
encode ref    : 56, 63, 70 (09:27:38)  [3/3]
decode simple : none [0/3]

## 8.3.35 (f80x-8335)
decode ref    : 23, 31, 44 (09:28:41)  [3/3]
encode ref    : 57, 64, 71 (09:28:42)  [3/3]
decode simple : none [0/3]

## 8.3.36 control (f80x-8336)
decode ref    : none [0/3]
encode ref    : none [0/3]; encode producer children 23, 30, 43 exited code 137 (hard OOM)
decode simple : none [0/3]
