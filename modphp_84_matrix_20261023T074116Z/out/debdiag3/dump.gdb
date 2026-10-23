set pagination off
set confirm off
python
import gdb
inf=gdb.selected_inferior()
def u64(a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
ag=int(gdb.parse_and_eval('&alloc_globals'))&0xffffffffffffffff
ps=int(gdb.parse_and_eval('&ps_globals'))&0xffffffffffffffff
h=u64(ag); m=h&~0x1fffff
hsv=u64(ps+0x168)
gdb.execute('dump memory /tmp/chunk.bin %#x %#x' % (m, m+0x200000))
if hsv and (m <= hsv < m+0x200000):
    gdb.execute('dump memory /tmp/hsv.bin %#x %#x' % (hsv-0x40, hsv+0xC0))
    print('HSV %#x HSVVAL %#x' % (hsv, u64(hsv)), flush=True)
print('HEAP %#x MAIN %#x' % (h, m), flush=True)
end
quit
