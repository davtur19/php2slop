set pagination off
set confirm off
python
import gdb
PS_ID=0x10; PS_MD=0x60; PS_HSV=0x168; PS_SEND_COOKIE=0x15e; PS_STATUS=0x68
PS_MOD=0x8; PS_RFC=0x150
def u64(inf,a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
def u32(inf,a): return int.from_bytes(inf.read_memory(a,4).tobytes(),'little')
def u8(inf,a): return int.from_bytes(inf.read_memory(a,1).tobytes(),'little')
def hexmem(inf,a,n):
    try: return inf.read_memory(a,n).tobytes().hex()
    except Exception as e: return 'ERR %r'%e
try:
    inf=gdb.selected_inferior()
    ps=int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
    ag=int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
    h=u64(inf,ag); main=h & ~0x1fffff
    pid=u64(inf,ps+PS_ID); md=u64(inf,ps+PS_MD); hsv=u64(inf,ps+PS_HSV)
    mod=u64(inf,ps+PS_MOD); rfc=u64(inf,ps+PS_RFC)
    sc=u8(inf,ps+PS_SEND_COOKIE); st=u32(inf,ps+PS_STATUS)
    print("STATE ps=%#x heap=%#x main=%#x id=%#x idoff=%s md=%#x mod=%#x rfc=%#x hsv=%#x hsvoff=%s status=%d send_cookie=%d" % (
     ps,h,main,pid,("0x%x"%(pid-main)) if pid else "NULL",md,mod,rfc,hsv,("0x%x"%(hsv-main)) if hsv else "NULL",st,sc),flush=True)
    if pid:
        print("IDLEN %#x"%u64(inf,pid+0x10),flush=True)
        print("IDMEM "+hexmem(inf,pid,0x30),flush=True)
    if rfc:
        print("RFCMEM "+hexmem(inf,rfc,0x40),flush=True)
    if hsv:
        print("HSVMEM "+hexmem(inf,hsv,0x40),flush=True)
except Exception as e:
    print("DUMP_ERR %r" % (e,), flush=True)
end
detach
quit
