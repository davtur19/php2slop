set pagination off
set confirm off
python
import gdb

def u64(inf, a):
    return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')

def u32(inf, a):
    return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')

class URLB(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_url_encode", internal=True)

    def stop(self):
        inf = gdb.selected_inferior()
        try:
            ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
            h = u64(inf, ag)
            print("HEAP h=%#x ag=%#x" % (h, ag), flush=True)
            for off in range(0, 0x140, 8):
                v = u64(inf, h + off)
                tag = ""
                if 0x7f0000000000 <= v <= 0x7fffffffffff:
                    tag = " PTR"
                print("  h+%#04x = %#018x%s" % (off, v, tag), flush=True)
            m = h & ~0x1fffff
            print("MAIN m=%#x" % m, flush=True)
            for off in range(0, 0x40, 4):
                print("  m+%#04x = %#010x" % (off, u32(inf, m + off)), flush=True)
            rdi = int(gdb.parse_and_eval('$rdi')) & 0xffffffffffffffff
            rsi = int(gdb.parse_and_eval('$rsi')) & 0xffffffffffffffff
            print("URL rdi=%#x len=%d" % (rdi, rsi), flush=True)
        except Exception as e:
            print("ERR", repr(e), flush=True)
        return False

URLB()
end
continue
