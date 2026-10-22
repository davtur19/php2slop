#!/usr/bin/env python3
"""One-off diagnostic for 7.0.33 G2 write at A (real_p layout)."""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab

v = '7.0.33'
labdir = lab.labdir(v)
s = lab.info(v)

def show(name, txt):
    print('=' * 20, name)
    print(txt)
    open(os.path.join(labdir, 'phase', 'dbg70_' + name + '.txt'), 'w').write(txt)

txt, _ = lab.gdb(v, 'state.gdb', phase='dbg70_state0.txt')
show('state0', txt)

out = lab.drv(v, 'plant', env={'PLANT_PAYLOAD': s['plant_payload']})
print('PLANT:', out.replace('\n', ' ')[:200])
txt, _ = lab.gdb(v, 'state.gdb', phase='dbg70_state1.txt')
show('state1', txt)
P = int(lab.kv(txt, 'BG_DATA'), 16)
B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
plast = int(lab.kv(txt, 'P_LAST') or 0, 16)
print('P=%x B0=%x plast=%x' % (P, B0, plast))

sid = 'k' + v.replace('.', '')
target = int(s['decode2'], 16)
m = lab.build(v, sid, dict(mode='calib', zero=False, x1=B0, p=P, b0=B0,
                           target=target, real_p=True, p_last=plast,
                           a_target=int(s['A'], 16)))
print('REC:', json.dumps({k: m[k] for k in ('K', 'used_slots_file_off', 'F_off')}))
txt, _ = lab.gdb(v, 'diag.gdb', lambda: lab.drv(v, 'trigger', sid),
                 phase='dbg70_diag1.txt', timeout=60)
show('diag1', txt)
