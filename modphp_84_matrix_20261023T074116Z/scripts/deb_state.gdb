set pagination off
set confirm off
python
import gdb
def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
def u32(inf,a): return int.from_bytes(inf.read_memory(a,4).tobytes(),'little')
inf=gdb.selected_inferior()
ps=int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
ag=int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
h=u64(inf,ag)
main=h & ~0x1fffff
sid=u64(inf,ps+0x10)
hsv=u64(inf,ps+0x168)
hsvt=u32(inf,ps+0x170)
sc=int.from_bytes(inf.read_memory(ps+0x15e,1).tobytes(),'little')
st=u32(inf,ps+0x68)
z=int(gdb.parse_and_eval('(unsigned long)&zval_ptr_dtor'))
line="DEBSTATE heap=%#x main=%#x lib=%#x sid=%#x sidoff=%s hsv=%#x hsvoff=%s hsvtype=%#x send_cookie=%d status=%d" % (
  h, main, z-0x424ff0, sid, ("%#x"%(sid-main)) if sid else "NULL",
  hsv, ("%#x"%(hsv-main)) if hsv else "NULL", hsvt, sc, st)
try:
    rc=u32(inf,hsv); rtype=u32(inf,hsv+4); ptr=u64(inf,hsv+8); vtype=u32(inf,hsv+16)
    line += " refrc=%d reftype=%#x refptr=%#x valtype=%#x" % (rc, rtype, ptr, vtype)
    try:
        vrc=u32(inf,ptr); vgc=u32(inf,ptr+4)
        line += " valrc=%d valgc=%#x" % (vrc, vgc)
    except Exception:
        line += " valrc=ERR"
except Exception as e:
    line += " referr=%s" % e
print(line, flush=True)
end
quit
