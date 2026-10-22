#!/usr/bin/env python3
"""Watchpoint diagnostic for the 7.1.33 last_dtor clobber."""
import os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab

v = '7.1.33'
s = lab.info(v)
lab.stop(v)
time.sleep(0.3)
master, child = lab.start(v)
print('master=%d child=%d' % (master, child))
st = lab.drv(v, 'probe')
print(re.search(r'PID=(\d+)', st).group(0))
out = lab.drv(v, 'plant', env={'PLANT_PAYLOAD': s['plant_payload']})
print(out[:200].replace('\n', ' '))
time.sleep(0.2)
txt, _ = lab.gdb(v, 'watch_dtor.gdb', lambda: lab.drv(v, 'calib', 'k7133'),
                 phase='watch_calib.txt', timeout=90)
print(txt)
print('worker alive:', lab.alive(child), 'master alive:', lab.alive(master))
