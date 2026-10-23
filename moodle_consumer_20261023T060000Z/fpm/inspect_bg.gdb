set pagination off
set confirm off
python
import gdb, struct
BG = int(gdb.parse_and_eval("&basic_globals"))
def rd(a,n):
    try: return gdb.selected_inferior().read_memory(a,n).tobytes()
    except Exception as e: return None
def u32(a):
    b=rd(a,4); return "ERR" if b is None else str(struct.unpack("<I",b)[0])
def u64(a):
    b=rd(a,8); return "ERR" if b is None else hex(struct.unpack("<Q",b)[0])
lock=u32(BG+848); data=u64(BG+856); level=u32(BG+864)
gdb.write("IDLE lock=%s level=%s data=%s\n" % (lock,level,data))
if data not in ("ERR","0x0"):
    d=int(data,16)
    gdb.write("IDLE-HT nNumUsed=%s nTableSize=%s arData=%s\n" % (u32(d+24),u32(d+32),u64(d+16)))
    try:
        gdb.write("IDLE-MEM " + gdb.execute("x/8gx %d" % d, to_string=True))
    except Exception as e:
        gdb.write("MEM-ERR %s\n" % e)
end
detach
quit
