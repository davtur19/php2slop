set pagination off
set confirm off
set width 0
set height 0
set breakpoint pending on
python
import gdb, struct
BG = int(gdb.parse_and_eval("&basic_globals"))
def rd(addr, n):
    try:
        return gdb.selected_inferior().read_memory(addr, n).tobytes()
    except Exception as e:
        return None
def u32(addr):
    b = rd(addr, 4)
    return "ERR" if b is None else str(struct.unpack("<I", b)[0])
def u64(addr):
    b = rd(addr, 8)
    return "ERR" if b is None else hex(struct.unpack("<Q", b)[0])
def state():
    lock = u32(BG + 848)
    data = u64(BG + 856)
    level = u32(BG + 864)
    extra = ""
    if data not in ("ERR", "0x0"):
        d = int(data, 16)
        extra = " ht.nNumUsed=%s ht.nTableSize=%s ht.arData=%s" % (
            u32(d + 24), u32(d + 32), u64(d + 16))
    return "lock=%s level=%s data=%s%s" % (lock, level, data, extra)
def log(label, bt=0):
    gdb.write("TRACE %s %s\n" % (label, state()))
    if bt:
        try:
            gdb.write(gdb.execute("bt %d" % bt, to_string=True))
        except Exception as e:
            gdb.write("BT-ERR %s\n" % e)
class B(gdb.Breakpoint):
    def __init__(self, spec, label, bt=0):
        super(B, self).__init__(spec, internal=False)
        self.label = label
        self.bt = bt
        self.n = 0
    def stop(self):
        self.n += 1
        log("%s#%d" % (self.label, self.n), self.bt)
        return False
class Detach(gdb.Breakpoint):
    def stop(self):
        log("accept-detach", 0)
        gdb.execute("detach")
        gdb.execute("quit")
        return True
B("php_request_startup", "reqstart", 2)
B("php_session_flush", "session_flush", 6)
B("php_var_serialize_init", "ser_init", 6)
B("php_var_serialize_destroy", "ser_destroy", 4)
B("php_add_var_hash", "addvar", 5)
B("php_request_shutdown", "reqshutdown", 2)
Detach("fcgi_accept_request")
end
continue
