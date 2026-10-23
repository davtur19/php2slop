set pagination off
set confirm off
python
import gdb, struct
inf = gdb.selected_inferior()
def u64(a): return int.from_bytes(inf.read_memory(a,8).tobytes(),'little')
def u32(a): return int.from_bytes(inf.read_memory(a,4).tobytes(),'little')
def u8(a):  return int.from_bytes(inf.read_memory(a,1).tobytes(),'little')

ag = int(gdb.parse_and_eval('&alloc_globals')) & 0xffffffffffffffff
ps = int(gdb.parse_and_eval('&ps_globals')) & 0xffffffffffffffff
heap = u64(ag)                      # alloc_globals.mm_heap
main = heap & ~0x1fffff
hsv = u64(ps + 0x168)
hsvt = u32(ps + 0x170)
sid = u64(ps + 0x10)
st = u32(ps + 0x68)

# heap fields: size@0x10, peak@0x18, real_size@0x?? (after free_slot[30] = 0x20+240)
# use gdb types for robustness
sz = int(gdb.parse_and_eval('((zend_mm_heap*)%d)->size' % heap))
peak = int(gdb.parse_and_eval('((zend_mm_heap*)%d)->peak' % heap))
rsz = int(gdb.parse_and_eval('((zend_mm_heap*)%d)->real_size' % heap))
ovf = int(gdb.parse_and_eval('((zend_mm_heap*)%d)->overflow' % heap))
limit = int(gdb.parse_and_eval('((zend_mm_heap*)%d)->limit' % heap))
mc = int(gdb.parse_and_eval('((zend_mm_heap*)%d)->main_chunk' % heap))

print("MMSTATE heap=%#x main=%#x size=%d peak=%d real=%d overflow=%d limit=%d main_chunk=%#x" % (
      heap, main, sz, peak, rsz, ovf, limit, mc), flush=True)
print("PSSTATE hsv=%#x hsvoff=%s hsvtype=%#x sid=%#x status=%d" % (
      hsv, ("%#x" % (hsv-main)) if hsv else "NULL", hsvt, sid, st), flush=True)

if hsv and (main <= hsv < main + 0x200000):
    rc = u32(hsv); rt = u32(hsv+4); rp = u64(hsv+8); vt = u32(hsv+16)
    print("REF rc=%d type=%#x valptr=%#x valtype=%#x" % (rc, rt, rp, vt), flush=True)
    chunk = hsv & ~0x1fffff
    page = (hsv - chunk) // 0x1000
    MAP = 0x260
    info = u32(chunk + MAP + page*4)
    print("PAGE chunk=%#x page=%d info=%#x" % (chunk, page, info), flush=True)
    # decode map entries around the page
    for p in range(page-2, page+3):
        if 0 <= p < 512:
            i2 = u32(chunk + MAP + p*4)
            kind = "FRUN"
            extra = ""
            if i2 & 0x80000000:
                if i2 & 0x40000000:
                    kind = "NRUN"; extra = "bin=%d off=%d" % (i2 & 0x1f, (i2>>16)&0x1ff)
                else:
                    kind = "SRUN"; extra = "bin=%d freecnt=%d" % (i2 & 0x1f, (i2>>16)&0x1ff)
            elif i2 & 0x40000000:
                kind = "LRUN"; extra = "pages=%d" % (i2 & 0x3ff)
            print("  map[%d]=%#x %s %s" % (p, i2, kind, extra), flush=True)
    # free_map bits
    fm = u64(chunk + 0x220 + (page//64)*8)
    print("FREEMAP word bit=%d" % ((fm >> (page % 64)) & 1), flush=True)
    # chunk free_pages / free_tail
    fp = u32(chunk + 0x18); ft = u32(chunk + 0x1c)
    print("CHUNK free_pages=%d free_tail=%d" % (fp, ft), flush=True)
    # decode bin for the run covering hsv
    run = page; i3 = info
    if i3 & 0x80000000 and (i3 & 0x40000000):
        run = page - ((i3>>16)&0x1ff); i3 = u32(chunk + MAP + run*4)
    if i3 & 0x80000000 and not (i3 & 0x40000000):
        b = i3 & 0x1f
        sizes = [8,16,24,32,40,48,56,64,80,96,112,128,160,192,224,256,320,384,448,512,640,768,896,1024,1280,1536,1792,2048,2560,3072]
        bs = sizes[b]
        page_addr = chunk + run*0x1000
        # element count per bin from alloc_sizes
        elems = [512,256,170,128,102,85,73,64,51,42,36,32,25,21,18,16,64,32,9,8,32,16,9,8,16,8,16,8,8,4]
        n = elems[b]
        off = hsv - page_addr
        print("BIN bin=%d size=%d elems=%d run_page=%d page_addr=%#x off_in_page=%#x slot=%d slot_off=%#x" % (
              b, bs, n, run, page_addr, off, off // bs, off % bs), flush=True)
        # free list walk for this bin: slot[0] = plain next pointer
        fs = heap + 0x28 + b*8  # free_slot[b] offset 0x28
        nxt = u64(fs)
        seen = 0
        found = False
        while nxt and seen < 400:
            ptr = nxt
            if ptr == hsv: found = True
            if not (chunk <= ptr < chunk + 0x200000): break
            try:
                nxt = u64(ptr)
            except Exception:
                break
            seen += 1
        print("FREELIST bin=%d found_hsv=%s walked=%d head=%#x" % (b, found, seen, u64(fs)), flush=True)
else:
    print("NO_HSV", flush=True)
end
detach
quit
