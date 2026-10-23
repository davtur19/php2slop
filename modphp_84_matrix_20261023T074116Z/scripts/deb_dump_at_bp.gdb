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
        ag = int(gdb.parse_and_eval('(unsigned long)&alloc_globals'))
        heap = u64(ag); main = heap & ~0x1fffff
        v = u64(z); t = u32(z+8)
        print("HIT zval=%#x type=%#x value=%#x main=%#x" % (z, t, v, main), flush=True)
        if (t & 0x1f) == 10:
            print("REF rc=%d type=%#x ptr=%#x valtype=%#x" % (u32(v), u32(v+4), u64(v+8), u32(v+16)), flush=True)
        try:
            gdb.execute("dump memory /tmp/chunk_bp.bin %#x %#x" % (main, main+0x200000))
            print("DUMPED %#x" % main, flush=True)
        except Exception as e:
            print("DUMPERR", e, flush=True)
        try:
            gdb.execute("bt 5")
        except Exception:
            pass
        return True
HsvDtor('zval_ptr_dtor')
end
continue
detach
quit
