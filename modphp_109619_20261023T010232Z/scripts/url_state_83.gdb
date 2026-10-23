set pagination off
set confirm off
python
import gdb

PS_ID = 0x10
PS_SEND_COOKIE = 0x178
PS_STATUS = 0x68

def u64(inf, a):
    return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')

def u32(inf, a):
    return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')

def u8(inf, a):
    return int.from_bytes(inf.read_memory(a, 1).tobytes(), 'little')

def heap_addr(inf):
    ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
    return u64(inf, ag)

def chainlen(inf, p):
    n = 0
    seen = set()
    while p and n < 200 and p not in seen:
        seen.add(p)
        n += 1
        try:
            p = u64(inf, p)
        except Exception:
            break
    return n

class URLB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_url_encode", internal=True)

    def stop(self):
        inf = gdb.selected_inferior()
        try:
            rdi = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            rsi = int(gdb.parse_and_eval('$rsi')) & 0xffffffffffffffff
            h = heap_addr(inf)
            m = h & ~0x1fffff
            fp = u32(inf, m + 0x18)
            rsize = u64(inf, h + 0x110)
            limit = u64(inf, h + 0x120)
            fs128 = u64(inf, h + 0x20 + 11 * 8)
            fs64 = u64(inf, h + 0x20 + 7 * 8)
            fs320 = u64(inf, h + 0x20 + 16 * 8)
            fs96 = u64(inf, h + 0x20 + 9 * 8)
            fs112 = u64(inf, h + 0x20 + 10 * 8)
            allbins = []
            for bi in range(30):
                allbins.append(chainlen(inf, u64(inf, h + 0x20 + bi * 8)))
            ps = int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
            pid = u64(inf, ps + PS_ID)
            sc = u8(inf, ps + PS_SEND_COOKIE)
            st = u32(inf, ps + PS_STATUS)
            print("BINS83 " + " ".join(str(x) for x in allbins), flush=True)
            print("URL83 len=%d heap=%#x fp=%d rsize=%#x limit=%#x n128=%d n64=%d n320=%d n96=%d n112=%d idpage=%#x psid=%#x sc=%d st=%d" % (
                rsi, h, fp, rsize, limit, chainlen(inf, fs128), chainlen(inf, fs64),
                chainlen(inf, fs320), chainlen(inf, fs96), chainlen(inf, fs112), (rdi & 0x1fffff) >> 12 if rdi else 0, pid, sc, st), flush=True)
            if rdi:
                try:
                    print("  idbytes=%s" % inf.read_memory(rdi, min(rsi, 32)).tobytes().hex(), flush=True)
                except Exception:
                    pass
        except Exception as e:
            print("URLERR", repr(e), flush=True)
        return False

URLB()
end
continue
