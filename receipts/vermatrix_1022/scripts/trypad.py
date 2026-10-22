#!/usr/bin/env python3
"""Sweep plant-time pad to keep the stale P out of the RFC1867 early allocations."""
import os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab

v = '7.1.33'
s = lab.info(v)
pads = [int(x) for x in (sys.argv[1:] or ['8192', '32768', '65536'])]
cmd = 'touch ' + s['marker'] + ';#'
key_len = ord(cmd[0])
key_text = cmd[1:]
for pad in pads:
    lab.stop(v)
    time.sleep(0.2)
    master, child = lab.start(v)
    st = lab.drv(v, 'probe')
    pid = int(re.search(r'PID=(\d+)', st).group(1))
    out = lab.drv(v, 'plant', str(pad), env={'PLANT_PAYLOAD': s['plant_payload']})
    txt, _ = lab.gdb(v, 'state.gdb', phase='pad_%d_state.txt' % pad)
    P = int(lab.kv(txt, 'BG_DATA'), 16)
    B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
    plast = int(lab.kv(txt, 'P_LAST') or 0, 16)
    lvl = int(lab.kv(txt, 'BG_LEVEL'))
    print('PAD=%d pid=%d level=%d P=%#x B0=%#x last=%#x used=%s' % (
        pad, pid, lvl, P, B0, plast, lab.kv(txt, 'DTOR_USED')))
    opts = dict(mode='calib', zero=False, x1=B0, p=P, b0=B0,
                target=int(s['decode2'], 16), real_p=True, p_last=plast,
                a_target=int(s['A'], 16), key_len=key_len, key_text=key_text,
                no_frame=True)
    m = lab.build(v, 'k7133', opts)
    print('    rec=%s' % {k: m[k] for k in ('rec1_len', 'L', 'payload_start', 'b_off', 've_off', 'K')})
    txt, _ = lab.gdb(v, 'watch2.gdb', lambda: lab.drv(v, 'calib', 'k7133'),
                     phase='pad_%d_calib.txt' % pad, timeout=60)
    hits = re.findall(r'DECODE hit=(\d+) .*?val=(\S+) len=(\d+)', txt)
    vt = re.findall(r'VT n=(\d+) .*?ld=(\S+)', txt)
    print('    hits=%s' % hits)
    print('    vt=%s' % vt[:6])
    print('    watch=%s' % [l for l in txt.splitlines() if l.startswith('WATCH')][:3])
    print('    stop=%s' % [l for l in txt.splitlines() if l.startswith('STOPPED')][:1])
