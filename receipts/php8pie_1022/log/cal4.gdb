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
DECODE hit=1 str=0x7f65f526a000 val=0x7f65f526a018 len=131014
  heap=0x7f65f5200040 free64=0x7f65f5202080 free80=0x7f65f52560f0
SETVAR#1 name=[S] slot=0x7f65f5285010 type=0x106 heap=0x7f65f5200040 free64=0x7f65f52020c0
  STR zend=0x7f65f5202080 len=32 val=0x7f65f5202098
SETVAR#2 name=[J] slot=0x7f65f5285020 type=0x4 heap=0x7f65f5200040 free64=0x7f65f52020c0
SETVAR#3 name=[K] slot=0x7f65f5285030 type=0x106 heap=0x7f65f5200040 free64=0x7f65f52020c0
  STR zend=0x7f65f528c000 len=130932 val=0x7f65f528c018
SETVAR#4 name=[a] slot=0x7f65f5285040 type=0x307 heap=0x7f65f5200040 free64=0x7f65f52020c0
  ARR ht=0x7f65f5259268
DECODE hit=2 str=0x7f65f528c000 val=0x7f65f528c018 len=131320
  heap=0x7f65f5200040 free64=0x7f65f5202080 free80=0x7f65f52560f0
[Inferior 1 (process 1678204) detached]
