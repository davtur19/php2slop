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
DECODE hit=1 str=0x7f65f526a000 val=0x7f65f526a018 len=131014 level=1 data=0x7f65f5282000 ser2decode=0x556e4ac11f36
SETVAR#1 name=[S] slot=0x7f65f5285010 type=0x106
  STR zend=0x7f65f5202080 len=32 val=0x7f65f5202098
SETVAR#2 name=[J] slot=0x7f65f5285020 type=0x4
SETVAR#3 name=[K] slot=0x7f65f5285030 type=0x106
  STR zend=0x7f65f528c000 len=130927 val=0x7f65f528c018
SETVAR#4 name=[o] slot=0x7f65f5285040 type=0x308
  OBJ ptr=0x7f65f52582a8
0x7f65f52582a8:	0x0000000800000001	0x0000000000000001
0x7f65f52582b8:	0x0000556e85ba3c60	0x0000556e4b7ff600
0x7f65f52582c8:	0x00007f65f5259268	0x00007f65f52582f8
0x7f65f52582d8:	0x0000000000000000	0x0000000000000000
0x7f65f52582e8:	0x0000000000000000	0xd720a30ea3860e64
0x7f65f52582f8:	0x00007f65f5258320	0x0000000000000000
  FINAL DUMP at S (0x7f65f5202080):
0x7f65f5202080:	0x0000001600000001	0x0000000000000000
0x7f65f5202090:	0x0000000000000020	0x5151515151515151
0x7f65f52020a0:	0x5151515151515151	0x5151515151515151
0x7f65f52020b0:	0x5151515151515151	0xef82a60ea3860e00
0x7f65f52020c0:	0x00007f65f5202100	0x65722f65646f636e
0x7f65f52020d0:	0x702f686372616573	0x325f656970387068
DECODE hit=2 str=0x7f65f528c000 val=0x7f65f528c018 len=131320 level=1 data=0x7f65f5282000 ser2decode=0x556e4ac11f36
[Inferior 1 (process 1665286) detached]
