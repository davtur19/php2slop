set pagination off
set confirm off
set breakpoint pending on
set print elements 0
set height 0
set width 0
set disable-randomization off
handle SIGPIPE nostop noprint pass
handle SIGUSR1 nostop noprint pass
python
import gdb, time

LOGPATH = "/tmp/opencode/research/drupal_fpm_20261022T013000Z/gdb/gdb.log"
logf = open(LOGPATH, "a", buffering=1)

def log(s):
    logf.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), s))
    logf.flush()

def rdu64(a):
    if not a:
        return 0
    try:
        return int(gdb.parse_and_eval("*(unsigned long*)%d" % a))
    except Exception:
        return 0

def rds64(a):
    v = rdu64(a)
    return v - (1 << 64) if v >= (1 << 63) else v

def rdu32(a):
    if not a:
        return 0
    try:
        return int(gdb.parse_and_eval("*(unsigned int*)%d" % a))
    except Exception:
        return 0

def rdb(a, n):
    try:
        return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception:
        return b""

def sym(name):
    try:
        return int(gdb.parse_and_eval("(unsigned long)&%s" % name))
    except Exception as e:
        log("SYMERR %s: %s" % (name, e))
        return 0

def zstr(a, tag):
    if not a:
        log("%s ZSTR none" % tag)
        return 0
    rc = rdu32(a); ti = rdu32(a + 4); h = rdu64(a + 8); ln = rdu64(a + 16)
    take = ln if ln < 200 else 96
    val = rdb(a + 24, take)
    log("%s ZSTR ptr=%#x rc=%u ti=%#x h=%#x len=%d val=%r" % (tag, a, rc, ti, h, ln, val))
    return ln

def bg():
    b = sym("basic_globals")
    return (rdu64(b + 872), rdu32(b + 880)) if b else (0, 0)

def ps():
    return sym("ps_globals")

def heapbase():
    return rdu64(sym("alloc_globals"))

def dump_dat(tag):
    P, l = bg()
    if not P:
        log("%s DAT none" % tag)
        return
    log("%s DAT P=%#x last_dtor=%#x first_dtor=%#x used_slots=%d next=%#x level=%u" % (
        tag, P, rdu64(P + 16), rdu64(P + 8), rds64(rdu64(P + 16)), rdu64(rdu64(P + 16) + 8), l))

def dump_buckets(tag):
    p = ps()
    if not p:
        return
    hv = p + 0x168
    t = rdu32(hv + 8)
    ap = rdu64(hv)
    log("%s PSVARS slot=%#x type=%#x value=%#x" % (tag, hv, t, ap))
    if (t & 0xff) != 7 or not ap:
        return
    ar = rdu64(ap + 16); nu = rdu32(ap + 24)
    log("%s SESSION HT=%#x arData=%#x nNumUsed=%d nTableSize=%d" % (tag, ap, ar, nu, rdu32(ap + 32)))
    for i in range(min(nu, 10)):
        b = ar + 32 * i
        kp = rdu64(b + 24)
        vt = rdu32(b + 8); vv = rdu64(b)
        if not kp:
            continue
        kl = rdu64(kp + 16)
        kd = rdb(kp + 24, min(kl, 16))
        log("%s bucket[%d] key=%r kptr=%#x type=%#x value=%#x" % (tag, i, kd, kp, vt, vv))
        if (vt & 0xff) == 6:
            zstr(vv, "%s  strval" % tag)

S = {"req": 0, "X": 0, "len": 0}

class FnBP(gdb.Breakpoint):
    def __init__(self, spec, fn):
        super(FnBP, self).__init__(spec, internal=False)
        self.fn = fn
    def stop(self):
        try:
            self.fn()
        except Exception as e:
            log("ERR %s: %s" % (self.location, e))
        return False

class FinBP(gdb.FinishBreakpoint):
    def __init__(self, fn):
        super(FinBP, self).__init__(internal=True)
        self.fn = fn
    def stop(self):
        try:
            self.fn(self.return_value)
        except Exception as e:
            log("ERR finish: %s" % e)
        return False

def h_start():
    S["req"] += 1
    p = ps()
    log("REQ%d PHPRQ_START heap=%#x ps=%#x" % (S["req"], heapbase(), p))
    if p:
        log("REQ%d START save_path=%s status=%d id=%s" % (
            S["req"],
            zstr(rdu64(p + 0x00), "REQ%d START save_path" % S["req"]),
            rdu32(p + 0x68),
            zstr(rdu64(p + 0x10), "REQ%d START id" % S["req"])))

def h_sessinit():
    p = ps()
    log("REQ%d SESSION_INITIALIZE entry" % S["req"])
    if p:
        log("REQ%d SI status=%d save_path=%s" % (
            S["req"], rdu32(p + 0x68), zstr(rdu64(p + 0x00), "REQ%d SI save_path" % S["req"])))
        post_sid()

def post_sid():
    try:
        cg = sym("core_globals")
        zv = cg + 0x160
        if (rdu32(zv + 8) & 0xff) != 7:
            return
        ht = rdu64(zv)
        if not ht:
            return
        ar = rdu64(ht + 16); nu = rdu32(ht + 24)
        for i in range(min(nu, 20)):
            b = ar + 32 * i
            kp = rdu64(b + 24)
            if not kp:
                continue
            kl = rdu64(kp + 16)
            if kl == 9 and rdb(kp + 24, 9) == b"PHPSESSID":
                vv = rdu64(b); vt = rdu32(b + 8)
                log("REQ%d POST PHPSESSID bucket=%#x val=%#x ti=%#x" % (S["req"], b, vv, vt))
                if (vt & 0xff) == 6:
                    zstr(vv, "REQ%d POST PHPSESSID" % S["req"])
                return
    except Exception as e:
        log("ERR post_sid: %s" % e)

def h_open():
    try:
        data = int(gdb.parse_and_eval("$rdi"))
        key = int(gdb.parse_and_eval("$rsi"))
        bd = rdu64(data + 8)
        log("REQ%d PSFILES_OPEN data=%#x basedir=%s" % (S["req"], data, zstr(bd, "REQ%d PSFILES_OPEN basedir" % S["req"])))
        zstr(key, "REQ%d PSFILES_OPEN key" % S["req"])
    except Exception as e:
        log("ERR h_open: %s" % e)

def h_decode():
    s = int(gdb.parse_and_eval("$rdi"))
    ln = rdu64(s + 16)
    S["X"] = s; S["len"] = ln
    log("REQ%d SESSION_DECODE str=%#x len=%d hdr=%s" % (S["req"], s, ln, rdb(s, 32).hex()))

def h_tmpvar():
    P = rdu64(int(gdb.parse_and_eval("$rdi")))
    last = rdu64(P + 16) if P else 0
    log("REQ%d TMPVAR entry P=%#x last_dtor=%#x used_slots=%d next=%#x" % (
        S["req"], P, last, rds64(last) if last else 0, rdu64(last + 8) if last else 0))
    FinBP(lambda rv: h_tmpret(P, int(rv)))

def h_tmpret(P, rv):
    last = rdu64(P + 16) if P else 0
    log("REQ%d TMPVAR ret slot=%#x dtor=%#x off=%d used_now=%d pre_val=%#x pre_type=%#x" % (
        S["req"], rv, last, (rv - last) if last else 0, rds64(last) if last else 0,
        rdu64(rv), rdu32(rv + 8)))

def h_flush():
    p = ps()
    log("REQ%d SESSION_FLUSH status=%d" % (S["req"], rdu32(p + 0x68) if p else -1))
    dump_buckets("REQ%d FLUSH" % S["req"])

def h_write():
    val = int(gdb.parse_and_eval("$rdx"))
    log("REQ%d PS_WRITE val=%#x len=%d head=%s" % (
        S["req"], val, rdu64(val + 16) if val else 0, rdb(val + 24, 64).hex() if val else b""))

def h_encode():
    FinBP(lambda rv: (lambda q: log("REQ%d ENCODE ret=%#x len=%s head=%s" % (
        S["req"], q, rdu64(q + 16) if q else None,
        rdb(q + 24, 48).hex() if q else b"")))(int(rv)))

def h_bailout():
    log("REQ%d ZEND_BAILOUT bg=%#x/%u" % (S["req"], *bg()))

def h_shutdown():
    log("REQ%d REQUEST_SHUTDOWN bg=%#x/%u" % (S["req"], *bg()))
    dump_dat("REQ%d SHUTDOWN" % S["req"])
    dump_buckets("REQ%d SHUTDOWN" % S["req"])

FnBP("php_request_startup", h_start)
FnBP("php_session_initialize", h_sessinit)
FnBP("ps_files_open", h_open)
def h_uvar():
    cur = int(gdb.parse_and_eval("$rdi"))
    log("REQ%d UVAR entry cur=%#x" % (S["req"], cur))
    FinBP(lambda rv: h_uvar_ret(cur, int(rv)))

def h_uvar_ret(cur, rv):
    v = rdu64(cur); ti = rdu32(cur + 8)
    log("REQ%d UVAR ret=%d cur=%#x val=%#x ti=%#x" % (S["req"], rv, cur, v, ti))
    if (ti & 0xff) == 6:
        zstr(v, "REQ%d UVAR STR" % S["req"])

FnBP("php_var_unserialize", h_uvar)
FnBP("php_session_decode", h_decode)
FnBP("var_tmp_var", h_tmpvar)
FnBP("php_session_flush", h_flush)
FnBP("ps_write_files", h_write)
FnBP("php_session_encode", h_encode)
FnBP("_zend_bailout", h_bailout)
FnBP("php_request_shutdown", h_shutdown)
log("=== staticleak gdb harness armed ===")
end
break zif_zend_version
commands
silent
detach
quit
end
continue
