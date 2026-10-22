#!/usr/bin/env python3
"""Static verification of the matrix FPM binaries: symbols, DWARF offsets,
serializer table bytes, passthru body.  Writes static.json + static.tsv.

Every number in the receipt comes from this script; nothing is copied from a
previous receipt.
"""
import hashlib, json, os, re, subprocess, sys

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERS = ['7.0.33', '7.1.33', '7.2.34', '7.3.33', '8.0.30', '8.2.35', '8.3.36']

GDB = r'''set pagination off
set confirm off
printf "EXEC_SIZE=%ld\n", (long)sizeof(zend_execute_data)
printf "THIS_OFF=%ld\n", (long)((char*)&((zend_execute_data*)0)->This-(char*)0)
printf "PS_GLOBALS=%p\n", (void*)&ps_globals
printf "PS_SER_OFF=%ld\n", (long)((char*)&ps_globals.serializer-(char*)&ps_globals)
printf "BG_GLOBALS=%p\n", (void*)&basic_globals
printf "BG_UNSER_OFF=%ld\n", (long)((char*)&basic_globals.unserialize-(char*)&basic_globals)
printf "BG_UNSER_SIZE=%ld\n", (long)sizeof(basic_globals.unserialize)
printf "PS_SERIALIZERS=%p\n", (void*)&ps_serializers
printf "PSER_SIZE=%ld\n", (long)sizeof(ps_serializers[0])
printf "PSER0=%s|%p|%p\n", ps_serializers[0].name, (void*)ps_serializers[0].encode, (void*)ps_serializers[0].decode
printf "PSER1=%s|%p|%p\n", ps_serializers[1].name, (void*)ps_serializers[1].encode, (void*)ps_serializers[1].decode
printf "PSER2=%s|%p|%p\n", ps_serializers[2].name, (void*)ps_serializers[2].encode, (void*)ps_serializers[2].decode
printf "PSER3NAME=%p\n", (void*)ps_serializers[3].name
printf "PSER3ENC=%p\n", (void*)ps_serializers[3].encode
printf "UNSER_SIZE=%ld\n", (long)sizeof(struct php_unserialize_data)
printf "UNSER_LAST_OFF=%ld\n", (long)((char*)&((struct php_unserialize_data*)0)->last-(char*)0)
printf "UNSER_FIRST_DTOR_OFF=%ld\n", (long)((char*)&((struct php_unserialize_data*)0)->first_dtor-(char*)0)
printf "UNSER_LAST_DTOR_OFF=%ld\n", (long)((char*)&((struct php_unserialize_data*)0)->last_dtor-(char*)0)
printf "DTOR_SIZE=%ld\n", (long)sizeof(var_dtor_entries)
printf "DTOR_DATA_OFF=%ld\n", (long)((char*)&((var_dtor_entries*)0)->data-(char*)0)
printf "DTOR_USED_OFF=%ld\n", (long)((char*)&((var_dtor_entries*)0)->used_slots-(char*)0)
printf "DTOR_DATA_MAX=%ld\n", (long)(sizeof(((var_dtor_entries*)0)->data)/sizeof(zval))
quit
'''


def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, **kw)


def sym(nm, name):
    m = re.search(r'^([0-9a-f]+)\s+\S\s+%s$' % re.escape(name), nm, re.M)
    return int(m.group(1), 16) if m else None


def main():
    out = {}
    for v in VERS:
        p = os.path.join(R, 'build', 'php-' + v, 'sapi', 'fpm', 'php-fpm')
        d = {'version': v, 'binary': p}
        d['md5'] = hashlib.md5(open(p, 'rb').read()).hexdigest()
        d['sha256'] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        d['size'] = os.path.getsize(p)
        eh = run(['readelf', '-h', p]).stdout
        d['elf'] = re.search(r'Type:\s+(\S+)', eh).group(1)
        d['banner'] = run([p, '-v']).stdout.split('\n')[0].strip()
        nm = run(['nm', '-a', p]).stdout
        for s in ('ps_serializers', 'ps_globals', 'zif_system', 'zif_passthru',
                  'php_session_decode', 'ps_srlzr_decode_php_binary',
                  'ps_srlzr_encode_php_binary', 'php_exec_ex', 'php_exec'):
            d[s] = sym(nm, s)
        # DWARF
        gf = os.path.join(R, 'gdb', 'vcheck.gdb')
        open(gf, 'w').write(GDB)
        g = run(['gdb', '-q', '-batch', '-x', gf, p])
        txt = g.stdout + g.stderr
        open(os.path.join(R, 'log', 'static-%s.gdb.txt' % v), 'w').write(txt)
        for line in txt.splitlines():
            m = re.match(r'^([A-Z0-9_]+)=(.*)$', line)
            if not m:
                continue
            k, val = m.group(1), m.group(2)
            if k.startswith('PSER'):
                parts = val.split('|')
                if len(parts) == 3:
                    name, enc, dec = parts
                    idx = int(k[4])
                    if idx == 3:
                        continue
                    d.setdefault('serializers', {})['entry%d' % idx] = {
                        'name': name, 'encode': enc, 'decode': dec}
                continue
            if val.startswith('0x'):
                d[k.lower()] = int(val, 16)
            else:
                try:
                    d[k.lower()] = int(val)
                except ValueError:
                    d[k.lower()] = val
        if 'pser0' not in d and 'serializers' in d:
            pass
        # sanity: entry names in DWARF print via PSER lines
        d['serializer_order'] = [d['serializers']['entry%d' % i]['name']
                                 for i in (0, 1, 2)]
        # frame geometry
        ex = d['exec_size']
        al = (ex + 7) & ~7
        slot = (al + 16 - 1) // 16
        d['frame_slot_zvals'] = slot
        d['num_args_off'] = d['this_off'] + 12
        d['arg1_off'] = slot * 16
        d['type_off'] = d['arg1_off'] + 8
        d['key_len'] = ((d['type_off'] + 8) // 8) * 8
        d['A'] = d['ps_serializers'] + 0x40
        d['A_align16'] = (d['A'] % 16) == 0
        d['old_dtor'] = d['dtor_data_off'] == 0
        d['real_decode_entry2'] = d['serializers']['entry2']['decode']
        d['real_decode_sym'] = d['ps_srlzr_decode_php_binary']
        # passthru / system bodies
        for name in ('zif_system', 'zif_passthru'):
            a = d[name]
            dis = run(['objdump', '-d', '--start-address=%d' % a,
                       '--stop-address=%d' % (a + 0x30), p]).stdout
            d[name + '_body'] = [l.strip() for l in dis.splitlines()
                                 if re.match(r'^\s+[0-9a-f]+:', l)]
        d['passthru_mode3'] = any('$0x3,%edx' in l for l in d['zif_passthru_body'])
        d['system_mode1'] = any('$0x1,%edx' in l for l in d['zif_system_body'])
        out[v] = d
        print(v, json.dumps({k: d[k] for k in (
            'md5', 'elf', 'ps_serializers', 'A', 'A_align16', 'zif_system',
            'zif_passthru', 'ps_globals', 'ps_ser_off', 'bg_unser_off',
            'exec_size', 'arg1_off', 'type_off', 'key_len', 'old_dtor',
            'frame_slot_zvals', 'serializer_order', 'passthru_mode3',
            'real_decode_sym', 'real_decode_entry2')}))
    json.dump(out, open(os.path.join(R, 'static.json'), 'w'), indent=1)
    # tsv
    cols = ['version', 'md5', 'elf', 'ps_serializers', 'A', 'zif_system',
            'zif_passthru', 'ps_globals', 'ps_ser_off', 'bg_unser_off',
            'exec_size', 'arg1_off', 'type_off', 'key_len', 'old_dtor',
            'frame_slot_zvals', 'real_decode_entry2']
    with open(os.path.join(R, 'static.tsv'), 'w') as fp:
        fp.write('\t'.join(cols) + '\n')
        for v in VERS:
            d = out[v]
            row = []
            for c in cols:
                x = d[c]
                row.append(hex(x) if isinstance(x, int) and c not in
                           ('ps_ser_off', 'bg_unser_off', 'exec_size', 'arg1_off',
                            'type_off', 'key_len', 'frame_slot_zvals', 'ps_serializers')
                           else str(x))
            fp.write('\t'.join(row) + '\n')


if __name__ == '__main__':
    main()
