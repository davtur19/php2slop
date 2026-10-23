#!/usr/bin/env python3
"""Derive zif_system / zval_ptr_dtor / zend_function_entry cluster from a stripped php-fpm.

Method:
 - zval_ptr_dtor is an exported dynamic symbol (nm -D).
 - ZEND_FUNCTION(system) has a zend_function_entry in .data.rel.ro:
     { const char *name; void (*handler)(...); ... }
   In a PIE binary both are R_X86_64_RELATIVE relocations. The 'name' field's
   addend points at the "system\\0" string in .rodata; the handler field is the
   next 8 bytes and its addend is zif_system.
 - Same for exec / passthru / shell_exec, used as a cluster sanity check.
"""
import argparse, re, subprocess, sys


def sh(cmd):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True).stdout


def sections(path):
    out = sh(["readelf", "-SW", path])
    secs = {}
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", line)
        if m:
            secs[m.group(1)] = (int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16))
    return secs


def relocs(path):
    out = sh(["readelf", "-rW", path])
    r = {}
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-fA-F]{8,16})\s+[0-9a-fA-F]+\s+(R_X86_64_\w+)\s*([0-9a-fA-F]*)\s*$", line)
        if m:
            off = int(m.group(1), 16)
            typ = m.group(2)
            add = int(m.group(3), 16) if m.group(3) else 0
            r[off] = (typ, add)
    return r


def find_strings(path, needle):
    """Return file offsets of NUL-terminated exact needle occurrences."""
    data = open(path, "rb").read()
    res = []
    start = 0
    pat = needle + b"\x00"
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        res.append(i)
        start = i + 1
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    a = ap.parse_args()
    path = a.binary
    secs = sections(path)
    rel = relocs(path)
    ro_addr, ro_off, ro_size = secs[".rodata"]
    text_addr = secs.get(".text", (0, 0, 0))[0]

    dyn = sh(["nm", "-D", "--defined-only", path])
    zpd = None
    for line in dyn.splitlines():
        if re.search(r"\bzval_ptr_dtor$", line):
            zpd = int(line.split()[0], 16)
    print("zval_ptr_dtor = 0x%x" % zpd if zpd else "zval_ptr_dtor = NOT FOUND")

    res = {}
    for name in ("system", "exec", "passthru", "shell_exec", "proc_open", "popen"):
        hits = find_strings(path, name.encode())
        found = []
        for fo in hits:
            if not (ro_off <= fo < ro_off + ro_size):
                continue
            addr = ro_addr + (fo - ro_off)
            for off, (typ, add) in rel.items():
                if typ == "R_X86_64_RELATIVE" and add == addr:
                    h = rel.get(off + 8)
                    if h and h[0] == "R_X86_64_RELATIVE" and h[1]:
                        found.append((addr, off, h[1]))
        if found:
            res[name] = found
            for addr, noff, haddr in found:
                print("%-10s str=0x%x name_slot=0x%x handler=0x%x (text off 0x%x)"
                      % (name, addr, noff, haddr, haddr - text_addr))
        else:
            print("%-10s NOT FOUND (rodata hits=%d)" % (name, len(hits)))

    # cluster sanity: consecutive 16-byte zend_function_entry records
    sysaddrs = sorted(x[2] for x in res.get("system", []))
    others = {n: sorted(x[2] for x in v) for n, v in res.items() if n != "system"}
    print("cluster:", {n: [hex(x) for x in v] for n, v in others.items()}, "system", [hex(x) for x in sysaddrs])


if __name__ == "__main__":
    main()
