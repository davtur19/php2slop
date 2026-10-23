#!/usr/bin/env python3
"""Resolve .deb download URLs from a Debian/Ubuntu archive by package name.

Usage: resolve_deb.py <base-url> <suite> <component,...> <pkg> [<pkg> ...]
Prints: pkg<TAB>version<TAB>arch<TAB>url
Handles both flat Packages.gz and by-hash layouts (deb.debian.org serves plain).
"""
import gzip, io, sys, urllib.request, re

def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()

def main():
    base, suite, comps = sys.argv[1], sys.argv[2], sys.argv[3].split(',')
    pkgs = set(sys.argv[4:])
    found = {}
    for comp in comps:
        for arch in ('amd64', 'all'):
            url = f"{base}/dists/{suite}/{comp}/binary-{arch}/Packages.gz"
            try:
                data = gzip.decompress(fetch(url)).decode('utf-8', 'replace')
            except Exception as e:
                print(f"# WARN {url}: {e}", file=sys.stderr)
                continue
            for para in data.split('\n\n'):
                if not para.strip():
                    continue
                fields = {}
                key = None
                for line in para.splitlines():
                    if line[:1] in (' ', '\t'):
                        continue
                    if ':' in line:
                        key, val = line.split(':', 1)
                        fields[key] = val.strip()
                name = fields.get('Package')
                if name in pkgs and name not in found:
                    found[name] = (fields.get('Version'), fields.get('Architecture'), f"{base}/{fields.get('Filename')}")
    for p in sorted(pkgs):
        if p in found:
            print('\t'.join([p, *found[p]]))
        else:
            print(f"{p}\tNOT_FOUND")

main()
