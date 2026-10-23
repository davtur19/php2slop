set pagination off
set confirm off
python
import gdb
inf=gdb.selected_inferior()
ag=int(gdb.parse_and_eval('&alloc_globals'))&0xffffffffffffffff
def u64(a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
h=u64(ag); m=h&~0x1fffff
gdb.execute('dump memory /tmp/chunk_11.bin %#x %#x' % (m, m+0x200000))
print('HEAP %#x MAIN %#x' % (h, m), flush=True)
end
quit
