set pagination off
set confirm off
set breakpoint pending on
python
import gdb
def u64(a): return int.from_bytes(gdb.selected_inferior().read_memory(a,8).tobytes(),'little')
def u32(a): return int.from_bytes(gdb.selected_inferior().read_memory(a,4).tobytes(),'little')
def u8(a): return int.from_bytes(gdb.selected_inferior().read_memory(a,1).tobytes(),'little')
def psaddr():
    try: return int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
    except Exception: return 0
def state():
    p=psaddr()
    if not p: return "ps=?"
    try: return "status=%d send=%d id=%#x md=%#x hsv=%#x"%(u32(p+0x68),u8(p+0x15e),u64(p+0x10),u64(p+0x60),u64(p+0x168))
    except Exception as e: return "state_err %r"%e
class Trace(gdb.Breakpoint):
    def __init__(self, spec, tag, bt=False):
        super().__init__(spec, internal=True)
        self.tag=tag; self.silent=True; self.bt=bt
    def stop(self):
        print("%s %s"%(self.tag, state()), flush=True)
        if self.bt:
            gdb.execute("bt 10")
        return False
Trace("php_session_initialize","INIT")
Trace("php_session_send_cookie","SEND_COOKIE")
Trace("php_session_rfc1867_update","UPDATE")
Trace("zend_mm_safe_error","OOM", bt=True)
end
continue
