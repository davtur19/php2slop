#!/usr/bin/env python3
"""Catch the writer that clobbers the stale P->last_dtor before the decode.

usage: watcher.py <version> [field-offset]
"""
import json, os, re, sys, time
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, 'scripts'))
import lab

TPL = '''set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
watch *(long*)@ADDR@
commands
silent
printf "WATCH addr=@ADDR@ rip=%p\\n", $rip
bt
info registers rip rdi rsi rdx rcx rax rbx rbp rsp
x/6i $rip-12
detach
quit
end
continue
printf "STOPPED rip=%p\\n", $rip
bt
detach
quit
'''


def main():
    v = sys.argv[1]
    off = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x18
    s = lab.info(v)
    labd = lab.labdir(v)
    master = lab.rd(os.path.join(labd, 'run', 'master.pid'))
    child = lab.rd(os.path.join(labd, 'run', 'child.pid'))
    if not master or not lab.alive(master):
        lab.stop(v)
        time.sleep(0.3)
        master, child = lab.start(v)
    elif child and lab.alive(child):
        lab.kill_wait(master, child)
    newchild = lab.wait_child(master, exclude=child)
    assert newchild
    lab.note_child(v, newchild)
    time.sleep(0.2)
    st = lab.drv(v, 'probe')
    assert int(re.search(r'PID=(\d+)', st).group(1)) == newchild
    out = lab.drv(v, 'plant', '0', env={'PLANT_PAYLOAD': s['plant_payload']})
    print('plant:', out.replace('\n', ' ')[:120])
    txt, _ = lab.gdb(v, 'state.gdb', phase='watch_state.txt')
    P = int(lab.kv(txt, 'BG_DATA'), 16)
    print('P=%#x last_dtor=%s' % (P, lab.kv(txt, 'P_LAST_DTOR')))
    addr = P + off
    open(os.path.join(labd, 'gdb', 'watch_field.gdb'), 'w').write(
        TPL.replace('@ADDR@', hex(addr)))
    sid = 'w' + v.replace('.', '')
    sys.path.insert(0, os.path.join(labd, 'scripts'))
    import fcgi
    fcgi.init(os.path.join(labd, 'www'), port=s['port'])
    act = lambda: fcgi.request('trig.php', b'', None, cookie='PHPSESSID=' + sid,
                               timeout=20, extra_params={'REQUEST_METHOD': 'GET',
                                                         'CONTENT_LENGTH': '0'})
    txt, _ = lab.gdb(v, 'watch_field.gdb', act, phase='watch_gdb.txt', timeout=60)
    print('\n'.join(l for l in txt.splitlines() if re.match(
        r'^(WATCH|STOPPED|Program|#[0-9]| )', l)))


if __name__ == '__main__':
    main()
