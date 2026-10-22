[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007fa8ab89b3a7 in ?? () from /lib/x86_64-linux-gnu/libc.so.6
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
Breakpoint 6 at 0x7fa8ab88bf90
Breakpoint 7 at 0xaeac62: file /home/davide/ailocal/php/zerodays_1020/build_plain/main/main.c, line 1957.
ARMED
DECODE n=1 data=0x7fa8a966a000 val=0x7fa8a966a018 len=524288 bg=1 bgd=0x7fa8a96e6000 decodefield=0x9e6fae
SETVAR name=0x7fa8a96eb000 nlen=96 namebytes= val=0x7fffd7e0ca90 type=0xd
SETVAR name=0x7fa8a96ec000 nlen=396 namebytes=B val=0x7fffd7e0ca90 type=0xd
SETVAR name=0x7fa8a9657200 nlen=1 namebytes=K val=0x7fffd7e0ca90 type=0xd
DECODE n=2 data=0x7fa8a96f2000 val=0x7fa8a96f2018 len=524600 bg=1 bgd=0x7fa8a96e6000 decodefield=0xa3c074
ZIF_PASSTHRU rdi=0x7fa8a96f2018 rsi=524600
0x7fa8a96f2018:	0x0000000000000000	0x0000000000000000
0x7fa8a96f2028:	0x0000000000000000	0x00007fa8a96eb218
0x7fa8a96f2038:	0x0000000000000000	0x0000000100000000
0x7fa8a96f2048:	0x0000000000000000	0x0000000000000000
SIGSEGV rip=0xb9d576
[Inferior 1 (process 953919) detached]
