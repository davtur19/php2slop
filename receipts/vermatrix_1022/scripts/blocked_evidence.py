#!/usr/bin/env python3
"""Capture the 8.2.35 / 8.3.36 mitigation evidence in one artifact each.

fresh worker -> probe -> plant (cross-request stale BG(unserialize)) -> state
             -> same worker handles the trigger GET (auto_start decode)
             -> decode breakpoint prints level/bgdata for that request.

Expected: BG_LEVEL=1 right after the plant, but the trigger request decodes
with level=0 bgdata=(nil) because php_basic_early_rinit() memsets
BG(unserialize) at request startup.
"""
import json, os, re, sys

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, 'scripts'))
import lab
import run2


def one(v):
    s = lab.info(v)
    out = {'version': v, 'port': s['port'], 'marker': s['marker'],
           'plant_payload': s['plant_payload']}
    lab.stop(v)
    master, child = lab.start(v)
    out['master'] = master
    out['worker'] = child
    st = lab.drv(v, 'probe')
    pid = int(re.search(r'PID=(\d+)', st).group(1))
    assert pid == child, (pid, child)
    p = lab.drv(v, 'plant', '0', '0', '0',
                env={'PLANT_PAYLOAD': s['plant_payload']})
    out['plant_bailed'] = 'stop' in p
    txt, _ = lab.gdb(v, 'state.gdb', phase='blocked_state.txt')
    out['state_after_plant'] = {k: lab.kv(txt, k) for k in (
        'BG_LEVEL', 'BG_DATA', 'P_LAST_DTOR', 'P_FIRST_DTOR', 'DTOR_USED')}
    assert out['state_after_plant']['BG_LEVEL'] == '1'
    sid = 'b' + v.replace('.', '')
    d = run2.dummy(131014)
    open(os.path.join(lab.labdir(v), 'sessions', 'sess_' + sid), 'wb').write(d)
    txt, res = lab.gdb(v, 'calib.gdb', lambda: run2.fcgi_get(v, sid),
                       phase='blocked_decode.txt', timeout=90)
    hits = re.findall(r'DECODE hit=(\d+) data=(\S+) val=(\S+) len=(\d+) level=(-?\d+)'
                      r'(?: bgdata=(\S+))?', txt)
    out['trigger_decodes'] = [
        {'hit': int(a), 'data': b, 'val': c, 'len': int(d2),
         'level': int(e), 'bgdata': f} for a, b, c, d2, e, f in hits]
    out['ser2decode'] = re.search(r'ser2decode=(\S+)', txt).group(1) \
        if 'ser2decode=' in txt else None
    out['worker_alive'] = lab.alive(child)
    out['master_alive'] = lab.alive(master)
    out['marker_exists'] = os.path.exists(s['marker'])
    p = os.path.join(lab.labdir(v), 'phase', 'blocked_evidence.json')
    json.dump(out, open(p, 'w'), indent=1)
    print(json.dumps(out, indent=1))
    return out


if __name__ == '__main__':
    for v in sys.argv[1:] or ['8.2.35', '8.3.36']:
        one(v)
