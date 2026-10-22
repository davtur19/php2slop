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
DECODE hit=1 str=0x7f65f526a000 val=0x7f65f526a018 len=131014
  num_args=1 arg1=0x7f65f528d196 type=6
DECODE hit=2 str=0x7f65f528d000 val=0x7f65f528d018 len=131320
  num_args=1 arg1=0x7f65f528d196 type=6
  F=0x7f65f528d196 F+0x10(len)=71 F+0x18=0x454950206f686365
0x7f65f528d1ae:	101 'e'	99 'c'	104 'h'	111 'o'	32 ' '	80 'P'	73 'I'	69 'E'
0x7f65f528d1b6:	95 '_'	90 'Z'	73 'I'	70 'F'
  serializer decode slot=0x556e4ac64c15
[Inferior 1 (process 1701090) detached]
