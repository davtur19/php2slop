set pagination off
set confirm off
python
import gdb

class HsvDtor(gdb.Breakpoint):
    def stop(self):
        try:
            z = int(gdb.parse_and_eval('(unsigned long)$rdi'))
            ps = int(gdb.parse_and_eval('(unsigned long)&ps_globals'))
        except Exception:
            return False
        if z != ps + 0x168:
            return False
        inf = gdb.selected_inferior()
        def u64(a): return int.from_bytes(inf.read_memory(a, 8).tobytes(), 'little')
        def u32(a): return int.from_bytes(inf.read_memory(a, 4).tobytes(), 'little')
        t = u32(z + 8)
        v = u64(z)
        print("HIT zval=%#x type=%#x value=%#x" % (z, t, v), flush=True)
        try:
            if (t & 0x1f) == 10:
                print("REF rc=%d type=%#x ptr=%#x valtype=%#x" % (
                    u32(v), u32(v + 4), u64(v + 8), u32(v + 16)), flush=True)
            print("MEM at value[:64]:", inf.read_memory(v, 64).tobytes().hex(), flush=True)
        except Exception as e:
            print("MEMERR", e, flush=True)
        try:
            gdb.execute("bt 6")
        except Exception:
            pass
        return True

HsvDtor('zval_ptr_dtor')
end
continue
detach
quit
