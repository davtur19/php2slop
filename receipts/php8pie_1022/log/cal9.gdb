[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f65f555b3a7 in ?? () from /lib/x86_64-linux-gnu/libc.so.6
warning: File "/tmp/opencode/research/php8pie_20261022_0325/src/php-8.5.10/sapi/fpm/php-fpm" auto-loading has been declined by your `auto-load safe-path' set to "$debugdir:$datadir/auto-load".
To enable execution of this file add
	add-auto-load-safe-path /tmp/opencode/research/php8pie_20261022_0325/src/php-8.5.10/sapi/fpm/php-fpm
line to your configuration file "/home/davide/.config/gdb/gdbinit".
To completely disable this security protection add
	set auto-load safe-path /
line to your configuration file "/home/davide/.config/gdb/gdbinit".
For more information about this security protection see the
"Auto-loading safe path" section in the GDB manual.  E.g., run from the shell:
	info "(gdb)Auto-loading safe path"
Breakpoint 1 at 0x556e4ac119de: file /tmp/opencode/research/php8pie_20261022_0325/src/php-8.5.10/ext/session/session.c, line 290.
Breakpoint 2 at 0x556e4ac11bc8: file /tmp/opencode/research/php8pie_20261022_0325/src/php-8.5.10/Zend/zend_types.h, line 670.
DECODE hit=1 str=0x7f65f526a000 val=0x7f65f526a018 len=131014 free56=0x7f65f5259268
SETVAR#1 namelen=25 slot=0x7f65f5285010 type=0x106 free56=0x7f65f52592d8
  STR zend=0x7f65f52592a0 len=24 val=0x7f65f52592b8 al=0
SETVAR#2 namelen=1 slot=0x7f65f5285020 type=0x4 free56=0x7f65f52592d8
SETVAR#3 namelen=1 slot=0x7f65f5285030 type=0x106 free56=0x7f65f5259310
  STR zend=0x7f65f52592d8 len=24 val=0x7f65f52592f0 al=8
SETVAR#4 namelen=1 slot=0x7f65f5285040 type=0x106 free56=0x7f65f5259310
  STR zend=0x7f65f528c000 len=130882 val=0x7f65f528c018 al=0
SETVAR#5 namelen=2 slot=0x7f65f5285050 type=0x307 free56=0x7f65f5259348
  ARR ht=0x7f65f5259310 al=0
FINAL S=0x7f65f52592a0
0x7f65f52592a0:	0x0000001600000001	0x0000000000000000
0x7f65f52592b0:	0x0000000000000018	0x5151515151515151
0x7f65f52592c0:	0x5151515151515151	0x5151515151515151
0x7f65f52592d0:	0x7bbc421e9b056500	0x0000001600000001
0x7f65f52592e0:	0x0000000000000000	0x0000000000000018
0x7f65f52592f0:	0x5858585858585858	0x5858585858585858
0x7f65f5259300:	0x5858585858585858	0xb3bd421e9b056500
0x7f65f5259310:	0x0000000700000001	0xfffffff000000010
0x7f65f5259320:	0x00007f65f5264680	0x0000000100000001
0x7f65f5259330:	0x0000000000000008	0x0000000000000001
0x7f65f5259340:	0x0000556e4ae644e5	0x00007f65f5259380
0x7f65f5259350:	0x0000000000000000	0x638f1abedba694a9
DECODE hit=2 str=0x7f65f528c000 val=0x7f65f528c018 len=131320 free56=0x7f65f5259150
[Inferior 1 (process 1685215) detached]
