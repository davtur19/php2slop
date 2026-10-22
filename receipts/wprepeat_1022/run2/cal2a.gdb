[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f791d29b3a7 in ?? () from /lib/x86_64-linux-gnu/libc.so.6
warning: File "/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm" auto-loading has been declined by your `auto-load safe-path' set to "$debugdir:$datadir/auto-load".
To enable execution of this file add
	add-auto-load-safe-path /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
line to your configuration file "/home/davide/.config/gdb/gdbinit".
To completely disable this security protection add
	set auto-load safe-path /
line to your configuration file "/home/davide/.config/gdb/gdbinit".
For more information about this security protection see the
"Auto-loading safe path" section in the GDB manual.  E.g., run from the shell:
	info "(gdb)Auto-loading safe path"
Catchpoint 1 (signal SIGSEGV)
Catchpoint 2 (signal SIGABRT)
Breakpoint 3 at 0x9e68b5: file /home/davide/ailocal/php/zerodays_1020/build_plain/ext/session/session.c, line 290.
Breakpoint 4 at 0x9e6a66: file /home/davide/ailocal/php/zerodays_1020/build_plain/Zend/zend_types.h, line 670.
Breakpoint 5 at 0xa3c074: file /home/davide/ailocal/php/zerodays_1020/build_plain/ext/standard/exec.c, line 257.
Breakpoint 6 at 0x7f791d28bf90
Breakpoint 7 at 0xaeac62: file /home/davide/ailocal/php/zerodays_1020/build_plain/main/main.c, line 1957.
ARMED
DECODE n=1 data=0x7f791b06a000 val=0x7f791b06a018 len=524288 bg=1 bgd=0x7f791b0e6000 decodefield=0x9e6fae
SETVAR name=0x7f791b0eb000 nlen=96 namebytes= val=0x7ffc9bc9d720 type=0xd
SETVAR name=0x7f791b0ec000 nlen=396 namebytes=B val=0x7ffc9bc9d720 type=0xd
SETVAR name=0x7f791b057200 nlen=1 namebytes=K val=0x7ffc9bc9d720 type=0xd
DECODE n=2 data=0x7f791b0f2000 val=0x7f791b0f2018 len=524600 bg=1 bgd=0x7f791b0e6000 decodefield=0xa3c074
ZIF_PASSTHRU rdi=0x7f791b0f2018 rsi=524600
0x7f791b0f2018:	0x0000000000000000	0x0000000000000000
0x7f791b0f2028:	0x0000000000000000	0x00007f791b0f2218
0x7f791b0f2038:	0x0000000000000000	0x0000000100000000
0x7f791b0f2048:	0x0000000000000000	0x0000000000000000
POPEN cmd=touch /tmp/opencode/research/wprepeat_20261022T004227Z/run2/MARK_TEST;
[Detaching after vfork from child process 959023]
DECODE n=3 data=0x7f791a9dfd80 val=0x7f791a9dfd98 len=343 bg=0 bgd=(nil) decodefield=0xa3c074
ZIF_PASSTHRU rdi=0x7f791a9dfd98 rsi=343
0x7f791a9dfd98:	0x705f64616f6c7075	0x5f73736572676f72
0x7f791a9dfda8:	0x737b3a353a617c78	0x617473223a30313a
0x7f791a9dfdb8:	0x22656d69745f7472	0x36323937313a693b
0x7f791a9dfdc8:	0x3a733b3534383033	0x746e6f63223a3431
REQUEST_SHUTDOWN static=0xa3c074
[Inferior 1 (process 958654) detached]
