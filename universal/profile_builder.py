#!/usr/bin/env python3
"""Universal per-binary PROFILE generator for the php 8.5.x machinery chain.

Given ANY php binary (cgi/fpm/cli, any flavor) from the lab trees it emits the
runtime-capable profile that both lanes consume:
  - non-PIE (EXEC): absolute vaddrs are deterministic -> noleak lane usable as-is.
  - PIE (DYN): offsets_from_base become the leak-lane constants; the live probe
    (native-output 14-byte P) anchors main_chunk and P-main == leak_offset must
    be measured per runtime at run time.

Read-only: nm + readelf on the given binary. No execution of the binary.

Collision safety (fixed 2026-10-21): the old naming `stem + "_" + parent.name`
collapsed every same-SAPI binary across build flavors onto ONE output file
(e.g. all `sapi/*/php-cgi` -> `php-cgi_cgi.json`), so a 42-binary batch produced
only 6 surviving profiles, last writer wins. Output names are now derived from
the build-flavor directory as `<flavor>_<sapi>.json` -- exactly the naming used
by the curated `addresses/*.json` profiles (plainpie_cgi, asan_fpm, ...).

Duplicate handling: byte-identical copies of the same unique binary (in-tree
build copy vs installed copy, see docs/runtime_addresses.md section 1) carry the
same md5 and collapse into a single profile; the `binary` field prefers the
installed copy and `duplicate_of` records the in-tree copy (curated-schema
runs). If an output file already exists with a DIFFERENT md5, the run refuses
to write it (regression/stale build detection) unless --force is given.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SYMBOLS = ["zif_passthru", "zif_system", "zend_call_function",
           "zend_llist_remove_tail", "zval_ptr_dtor"]

# Lab roots that may be profiled (inventory: universal/all_binaries.txt).
LAB_ROOTS = [
    Path("/home/davide/ailocal/php/zerodays_1020"),
    Path("/tmp/opencode/realapps"),
]

# Directory name under a lab root -> curated flavor tag
# (file naming of addresses/*.json: <flavor>_<sapi>.json; flavor tags match
# the build-flavor names used in docs/runtime_addresses.md).
FLAVOR_TAGS = {
    "build": "default_debug",       # default+debug build tree (build/php-8.5.10)
    "build_asan": "asan",
    "build_O0": "O0",
    "build_plain": "plain",
    "build_plainpie": "plainpie",
    "install": "default_debug",     # default+debug installed tree
    "install_asan": "asan",
    "install_O0": "O0",
    "install_plain": "plain",
    "install_plainpie": "plainpie",
    "phpb": "realapps",             # realapps-class build tree
    "phpb_np": "realapps_np",
    "install_realapps": "realapps",
    "install_realapps_np": "realapps_np",
}

SAPI_TAGS = {"php-fpm": "fpm", "php-cgi": "cgi", "php": "cli"}


def lab_root_of(binary: Path) -> tuple:
    """Return (root, flavor_dir) for a binary inside a lab root, or (None, None)."""
    for root in LAB_ROOTS:
        try:
            rel = binary.relative_to(root)
        except ValueError:
            continue
        parts = rel.parts
        if len(parts) < 3:
            return root, None
        return root, parts[0]
    return None, None


def name_and_counterpart(binary: Path) -> tuple:
    """Derive (output_name, flavor, sapi_tag, counterpart_install/build_path).

    counterpart is the expected installed copy (for in-tree build binaries) or
    in-tree copy (for installed binaries) under the naming conventions of
    docs/runtime_addresses.md section 1. May not exist; verify before use.
    """
    root, flavor_dir = lab_root_of(binary)
    if root is None or flavor_dir not in FLAVOR_TAGS:
        raise ValueError(
            f"not a recognized lab binary (root/flavor): {binary} "
            f"-- only binaries from universal/all_binaries.txt can be profiled "
            f"(use --allow-unknown-root to override)")
    flavor = FLAVOR_TAGS[flavor_dir]
    sapi = SAPI_TAGS.get(binary.stem)
    if sapi is None:
        raise ValueError(f"unrecognized SAPI binary name: {binary}")
    name = f"{flavor}_{sapi}.json"

    sapi_install_layout = {"cgi": "bin", "cli": "bin", "fpm": "sbin"}
    sapi_build_layout = {"cgi": "sapi/cgi", "cli": "sapi/cli", "fpm": "sapi/fpm"}
    prefix_map = {
        "build": "install", "build_asan": "install_asan", "build_O0": "install_O0",
        "build_plain": "install_plain", "build_plainpie": "install_plainpie",
        "install": "build", "install_asan": "build_asan", "install_O0": "build_O0",
        "install_plain": "build_plain", "install_plainpie": "build_plainpie",
        "phpb": "install_realapps", "phpb_np": "install_realapps_np",
        "install_realapps": "phpb", "install_realapps_np": "phpb_np",
    }
    dest = prefix_map[flavor_dir]
    # default+debug in-tree copies live deeper: build/php-8.5.10/sapi/...
    if dest == "build":
        dest = "build/php-8.5.10"
    # installed copy <-> in-tree build copy layouts differ per direction
    if flavor_dir.startswith(("build", "phpb")):
        sub = sapi_install_layout[sapi]
    else:
        sub = sapi_build_layout[sapi]
    counterpart = root / dest / sub / binary.parts[-1]
    return name, flavor, sapi, counterpart


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


def dynsym_exported(binary: Path) -> list:
    out = subprocess.check_output(
        ["nm", "-D", str(binary)], text=True, stderr=subprocess.DEVNULL)
    lines = [ln.split()[-1] for ln in out.splitlines() if ln.split()]
    return [n for n in SYMBOLS if n in lines]


def fmt(addr: str) -> str:
    """Curated JSON style: compact hex, no zero padding (0x496cd5)."""
    return f"0x{int(addr, 16):x}"


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
    return {
        "path": p,
        "md5": hashlib.md5(p.read_bytes()).hexdigest(),
        "size_bytes": p.stat().st_size,
        "elf_type": hdr["elf_type"],
        "pie": hdr["pie"],
        "image_base": base,
        "p_align": palign,
        "symbols": syms,
        "offsets_from_base": {n: int(s["addr"], 16) - base for n, s in syms.items()},
        "delta_dtor_call": da - ca,
        "delta_llist_passthru": ll - ia,
        "dynsym_exported": dynsym_exported(p),
        "missing_symbols": missing,
        "lane": "noleak_abs_addr" if not hdr["pie"] else "leak_required_aslr",
    }


def emit_raw(prof: dict, name: str, flavor: str, counterpart_md5: str | None,
             binary: str) -> dict:
    """Legacy tool schema (unchanged keys, as consumed by earlier reports)."""
    p = prof["path"]
    out = {
        "binary": binary,
        "name": name,
        "flavor": flavor,
        "size_bytes": prof["size_bytes"],
        "md5": prof["md5"],
        "elf_type": prof["elf_type"],
        "pie": prof["pie"],
        "image_base": f"0x{prof['image_base']:x}",
        "p_align": f"0x{prof['p_align']:x}",
        "symbols": {n: fmt(s["addr"]) for n, s in prof["symbols"].items()},
        "symbol_binding": {n: s["binding"] for n, s in prof["symbols"].items()},
        "offsets_from_base": {n: f"0x{v:x}" for n, v in
                              prof["offsets_from_base"].items()},
        "delta_dtor_minus_call": f"0x{prof['delta_dtor_call']:x}",
        "delta_llist_minus_passthru": f"0x{prof['delta_llist_passthru']:x}",
        "dynsym_exported": prof["dynsym_exported"],
        "dynsym_exported_count": len(prof["dynsym_exported"]),
        "missing_symbols": prof["missing_symbols"],
        "lane": prof["lane"],
        # leak-lane constants (PIE): measured from the live 14-byte discloser
        "leak_offset": "TBD_measure_live_probe",
        "target_offset": f"0x{int(prof['symbols']['zif_passthru']['addr'], 16) - prof['image_base']:x}"
                         if not prof["pie"] else "TBD_from_leak_chunk_anchor",
    }
    if counterpart_md5 == prof["md5"]:
        out["duplicate_of"] = str(prof["counterpart"])
    return out


def emit_curated(prof: dict, name: str, counterpart_md5: str, binary: str) -> dict:
    """Byte-compatible with the hand-curated addresses/*.json schema
    (plain_cgi.json / realapps_np_fpm.json): same keys, same value formats."""
    p = prof["path"]
    out = {
        "binary": binary,
        "duplicate_of": str(prof["counterpart"])
        if counterpart_md5 == prof["md5"] else None,
        "md5": prof["md5"],
        "size_bytes": prof["size_bytes"],
        "elf_type": prof["elf_type"],
        "image_base": f"0x{prof['image_base']:x}",
        "p_align": f"0x{prof['p_align']:x}",
        "symbols": {n: fmt(s["addr"]) for n, s in prof["symbols"].items()},
        "offsets_from_base": {n: f"0x{v:x}" for n, v in
                              prof["offsets_from_base"].items()},
        "delta_dtor_call": f"0x{prof['delta_dtor_call']:x}",
        "delta_llist_passthru": f"0x{prof['delta_llist_passthru']:x}",
        "dynsym_exported": prof["dynsym_exported"],
    }
    if not out["duplicate_of"]:
        del out["duplicate_of"]
    return out


def profile_to_json(prof: dict, name: str, flavor: str, schema: str,
                    binary: str) -> dict:
    counterpart = prof.get("counterpart")
    counterpart_md5 = None
    if counterpart is not None and counterpart.is_file():
        counterpart_md5 = hashlib.md5(counterpart.read_bytes()).hexdigest()
        if counterpart_md5 != prof["md5"]:
            print(f"profile_builder: WARNING counterpart md5 mismatch for "
                  f"{counterpart} ({counterpart_md5} != {prof['md5']}) "
                  f"-- stale/partially rebuilt tree; duplicate_of omitted",
                  file=sys.stderr)
    prof["counterpart_md5"] = counterpart_md5
    if schema == "curated":
        return emit_curated(prof, name, counterpart_md5, binary)
    return emit_raw(prof, name, flavor, counterpart_md5, binary)


def main() -> int:
    import argparse
    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--outdir", default=str(repo / "addresses" / "generated"))
    ap.add_argument("--schema", choices=["raw", "curated"], default="raw")
    ap.add_argument("--force", action="store_true", help="overwrite an existing "
                    "output file even when its md5 differs (refused by default)")
    ap.add_argument("--allow-unknown-root", action="store_true")
    args = ap.parse_args()
    if args.allow_unknown_root:
        LAB_ROOTS.append(Path("/"))

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    exit_code = 0
    for binary in args.binaries:
        prof = build_profile(binary)
        if "error" in prof:
            print(json.dumps({"binary": binary, "error": prof["error"]},
                             sort_keys=True))
            print(f"profile_builder: ERROR {binary}: {prof['error']}",
                  file=sys.stderr)
            exit_code = 1
            continue
        hashed = prof["md5"]

        name, flavor, sapi, counterpart = name_and_counterpart(Path(binary).resolve())
        prof["counterpart"] = counterpart
        artifact = outdir / name
        summary = {
            "artifact": str(artifact),
            "binary": binary,
            "name": name,
            "pie": prof["pie"],
            "image_base": f"0x{prof['image_base']:x}",
            "zif_passthru": fmt(prof["symbols"]["zif_passthru"]["addr"]),
            "zif_passthru_from_base":
                f"0x{prof['offsets_from_base']['zif_passthru']:x}",
            "llist_from_base":
                f"0x{prof['offsets_from_base']['zend_llist_remove_tail']:x}",
            "delta_dtor_minus_call": f"0x{prof['delta_dtor_call']:x}",
            "error": prof["missing_symbols"] or None,
        }
        if artifact.is_file():
            try:
                old = json.loads(artifact.read_text())
                old_md5 = old.get("md5")
            except (ValueError, json.JSONDecodeError):
                old_md5 = None
            if old_md5 == hashed:
                summary["status"] = "ok (identical md5 already profiled; kept)"
                print(json.dumps(summary, sort_keys=True))
                continue
            elif args.force:
                summary["status"] = "OVERWRITTEN with --force on md5 mismatch " \
                                    f"(old md5 {old_md5})"
            else:
                summary["status"] = "REFUSED: existing output has different md5 " \
                                    f"({old_md5} != {hashed}); use --force to overwrite"
                summary["error"] = "overwrite refused"
                print(json.dumps(summary, sort_keys=True))
                print(f"profile_builder: REFUSED overwrite {artifact} "
                      f"(md5 {old_md5} != {hashed}); --force to override",
                      file=sys.stderr)
                exit_code = 1
                continue
        else:
            summary["status"] = "written"
        prof_json = profile_to_json(prof, name, flavor, args.schema, binary)
        artifact.write_text(json.dumps(prof_json, indent=2, sort_keys=True) + "\n")
        print(json.dumps(summary, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
