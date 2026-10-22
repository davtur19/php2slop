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
ARMED
DECODE n=1 data=0x7fa8a966a000 val=0x7fa8a966a018 len=1048576 bg_level=1 bg_data=0x7fa8a96e6000
SETVAR name=0x7fa8a9657200 nlen=1 namebytes=S val=0x7fffd7e0ca90 type=0xd
SREAL z=0x7fa8a9656080 type=0x106 str=0x7fa8a9656080 sdata=0x7fa8a9656098 slen=32
SETVAR name=0x7fa8a9657220 nlen=1 namebytes=J val=0x7fffd7e0ca90 type=0xd
SETVAR name=0x7fa8a9657240 nlen=1 namebytes=K val=0x7fffd7e0ca90 type=0xd
DECODE n=2 data=0x7fa8a9001000 val=0x7fa8a9001018 len=1052954 bg_level=1 bg_data=0x7fa8a96e6000
LEAK_TWO_DECODES
[Inferior 1 (process 886227) detached]
