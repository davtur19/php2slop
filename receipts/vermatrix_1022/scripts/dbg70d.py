#!/usr/bin/env python3
"""Diagnostic 3 for 7.0.33: watch A during the FINAL (zif_passthru) trigger."""
import json, os, re, sys, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab

v = '7.0.33'
labdir = lab.labdir(v)
s = lab.info(v)


def refresh_child():
    master = int(open(os.path.join(labdir, 'run', 'master.pid')).read().strip())
    for _ in range(50):
        kids = subprocess.run(['pgrep', '-P', str(master)], capture_output=True, text=True).stdout.split()
        if kids:
            open(os.path.join(labdir, 'run', 'child.pid'), 'w').write(kids[0])
            return int(kids[0])
        time.sleep(0.1)
    raise SystemExit('no child')


def show(name, txt):
    print('=' * 20, name)
    print(txt)
    open(os.path.join(labdir, 'phase', 'dbg70_' + name + '.txt'), 'w').write(txt)


print('child', refresh_child())
out = lab.drv(v, 'plant', env={'PLANT_PAYLOAD': s['plant_payload']})
print('PLANT:', out.replace('\n', ' ')[:160])
txt, _ = lab.gdb(v, 'state.gdb', phase='dbg70_state1.txt')
show('state1', txt)
P = int(lab.kv(txt, 'BG_DATA'), 16)
B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
plast = int(lab.kv(txt, 'P_LAST') or 0, 16)
X1 = B0
X2 = 0x7ffff7aaa000
print('P=%x B0=%x plast=%x' % (P, B0, plast))

sid = 'f7033'
cmd = 'touch ' + s['marker']
m = lab.build(v, sid, dict(mode='final', zero=False, x1=X1, x2=X2, p=P, b0=B0,
                           target=int(s['zif_passthru'], 16),
                           a_target=int(s['A'], 16), cmd=cmd,
                           real_p=True, p_last=plast))
print('REC:', json.dumps({k: m[k] for k in ('K', 'F', 'F_off', 'cmd_off')}))
txt, _ = lab.gdb(v, 'diag3.gdb', lambda: lab.drv(v, 'trigger', sid),
                 phase='dbg70_diag3.txt', timeout=90)
show('diag3', txt)
print('marker', os.path.exists(s['marker']))
