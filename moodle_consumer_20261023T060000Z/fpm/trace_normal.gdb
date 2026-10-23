set pagination off
set confirm off
set width 0
set height 0
set breakpoint pending on
python
import gdb
def v(e):
    try:
        return str(gdb.parse_and_eval(e))
    except Exception as ex:
        return "ERR:" + str(ex)
def st():
    return ("slock=%s slevel=%s sdata=%s ulevel=%s udata=%s status=%s id=%s" % (
        v("basic_globals.serialize_lock"),
        v("basic_globals.serialize.level"),
        v("basic_globals.serialize.data"),
        v("basic_globals.unserialize.level"),
        v("basic_globals.unserialize.data"),
        v("ps_globals.session_status"),
        v("ps_globals.id")))
class B(gdb.Breakpoint):
    def __init__(self, spec, label, bt=0):
        super(B, self).__init__(spec, internal=False)
        self.label = label
        self.bt = bt
        self.n = 0
    def stop(self):
        self.n += 1
        gdb.write("TRACE %s hit=%d %s\n" % (self.label, self.n, st()))
        if self.bt:
            try:
                gdb.write(gdb.execute("bt %d" % self.bt, to_string=True))
            except Exception as e:
                gdb.write("BT-ERR %s\n" % e)
        return False
class Detach(gdb.Breakpoint):
    def stop(self):
        gdb.write("TRACE accept-detach %s\n" % st())
        gdb.execute("detach")
        gdb.execute("quit")
        return True
B("php_session_flush", "session_flush", 8)
B("php_var_serialize_init", "ser_init", 6)
B("php_add_var_hash", "addvar", 5)
B("php_request_startup", "reqstart", 3)
B("php_request_shutdown", "reqshutdown", 3)
Detach("fcgi_accept_request")
end
continue
