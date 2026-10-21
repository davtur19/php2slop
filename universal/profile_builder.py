#!/usr/bin/env python3
"""Universal per-binary PROFILE generator for the php 8.5.x machinery chain.
Given ANY php binary (cgi/fpm/cli, any flavor) it emits the runtime-capable
profile that both lanes consume:
  - non-PIE (EXEC): absolute vaddrs are deterministic -> noleak lane usable as-is.
  - PIE (DYN): offsets_from_base become the leak-lane constants; the live probe
    (native-output 14-byte P) anchors main_chunk and P-main == leak_offset must
    be measured per runtime at run time (recorded here as TBD-measure).
Read-only: nm + readelf on the given binary. No execution of the binary."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SYMBOLS = ["zif_passthru", "zif_system", "zend_call_function",
           "zend_llist_remove_tail", "zval_ptr_dtor"]


def readelf_header(binary: Path) -> dict:
    out = subprocess.check_output(
        ["readelf", "-h", str(binary)], text=True, stderr=subprocess.DEVNULL)
    info = {}
    m = re.search(r"Type:\s+(\w+)", out)
    info["elf_type"] = m.group(1) if m else "UNKNOWN"
    info["pie"] = info["elf_type"] == "DYN"
    return info


def first_load(binary: Path) -> tuple:
    out = subprocess.check_output(
        ["readelf", "-lW", str(binary)], text=True, stderr=subprocess.DEVNULL)
    for line in out.splitlines():
        if line.startswith("  LOAD"):
            parts = line.split()
            # LOAD offset vaddr paddr filesz memsz flags align
            return int(parts[2], 16), int(parts[-1], 16)
    return None, None


def nm_symbols(binary: Path) -> dict:
    out = subprocess.check_output(["nm", "-n", str(binary)], text=True,
                                  stderr=subprocess.DEVNULL)
    found = {}
    for line in out.splitlines():
        # "0000000000a3c074 t zif_passthru"
        parts = line.split()
        if len(parts) == 3 and parts[2] in SYMBOLS:
            found[parts[2]] = {"addr": "0x" + parts[0], "binding": parts[1]}
    return found


def dynsym_exported(binary: Path) -> int:
    out = subprocess.check_output(
        ["nm", "-D", str(binary)], text=True, stderr=subprocess.DEVNULL)
    return sum(1 for name in SYMBOLS if any(
        line.endswith(" " + name) for line in out.splitlines()))


def build_profile(binary: str) -> dict:
    p = Path(binary).resolve()
    if not p.is_file():
        return {"error": f"missing binary: {binary}"}
    hdr = readelf_header(p)
    base, palign = first_load(p)
    syms = nm_symbols(p)
    missing = [s for s in SYMBOLS if s not in syms]
    if int(palign or 0) <= 0 or base is None or not syms:
        return {"error": f"incomplete ELF/symbols for {p}", "missing": missing}
    ia = int(syms["zif_passthru"]["addr"], 16)
    ll = int(syms["zend_llist_remove_tail"]["addr"], 16)
    ca = int(syms["zend_call_function"]["addr"], 16)
    da = int(syms["zval_ptr_dtor"]["addr"], 16)
    offsets = {n: f"0x{int(s['addr'], 16) - base:x}" for n, s in syms.items()}
    profile = {
        "binary": str(p),
        "size_bytes": p.stat().st_size,
        "md5": hashlib.md5(p.read_bytes()).hexdigest(),
        "elf_type": hdr["elf_type"],
        "pie": hdr["pie"],
        "image_base": f"0x{base:x}",
        "p_align": f"0x{palign:x}",
        "symbols": {n: s["addr"] for n, s in syms.items()},
        "symbol_binding": {n: s["binding"] for n, s in syms.items()},
        "offsets_from_base": offsets,
        "delta_dtor_minus_call": f"0x{da - ca:x}",
        "delta_llist_minus_passthru": f"0x{ll - ia:x}",
        "dynsym_exported_count": dynsym_exported(p),
        "missing_symbols": missing,
        "lane": "noleak_abs_addr" if not hdr["pie"] else "leak_required_aslr",
        # leak-lane constants (PIE): measured from the live 14-byte discloser
        "leak_offset": "TBD_measure_live_probe",
        "target_offset": f"0x{ia - (base - (base % palign) if not hdr['pie'] else base):x}"
                         if not hdr["pie"] else "TBD_from_leak_chunk_anchor",
    }
    return profile


def main() -> int:
    outdir = Path("/tmp/opencode/realapps/side/addresses/generated")
    outdir.mkdir(parents=True, exist_ok=True)
    profiles = {}
    for binary in sys.argv[1:]:
        prof = build_profile(binary)
        name = Path(binary).stem + "_" + Path(binary).parent.name + ".json"
        (outdir / name).write_text(json.dumps(prof, indent=2, sort_keys=True) + "\n")
        profiles[binary] = {
            "artifact": str(outdir / name),
            "pie": prof.get("pie"),
            "image_base": prof.get("image_base"),
            "zif_passthru": prof.get("symbols", {}).get("zif_passthru"),
            "zif_passthru_from_base": prof.get("offsets_from_base", {}).get("zif_passthru"),
            "llist_from_base": prof.get("offsets_from_base", {}).get("zend_llist_remove_tail"),
            "delta_dtor_minus_call": prof.get("delta_dtor_minus_call"),
            "error": prof.get("error") or prof.get("missing_symbols"),
        }
        print(json.dumps({"binary": binary, **profiles[binary]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
