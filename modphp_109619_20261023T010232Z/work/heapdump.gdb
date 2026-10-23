set pagination off
set confirm off
python
import gdb
inf=gdb.selected_inferior()
def u64(a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
def u32(a): return int.from_bytes(inf.read_memory(a,4).tobytes(),'little')
ag=int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
h=u64(ag)
print("heap=%#x"%h,flush=True)
for off in range(0,0x180,8):
    v=u64(h+off)
    mark=""
    if v==134217728: mark=" <-- LIMIT"
    if 0x200000<=v<=0x8000000 and v%0x200000==0: mark=" <-- 2M-multiple"
    print("+%#05x %#x%s"%(off,v,mark),flush=True)
end
detach
quit
