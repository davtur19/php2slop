#!/usr/bin/env python3
"""Resolve RPM download URLs from a yum/dnf repo by package name.

Usage: resolve_rpm.py <repo-base-url-with-repodata> <pkg> [<pkg> ...]
Prints: pkg<TAB>version-release<TAB>arch<TAB>url
"""
import gzip, io, sys, urllib.request, xml.etree.ElementTree as ET

NS = {'c': 'http://linux.duke.edu/metadata/common',
      'r': 'http://linux.duke.edu/metadata/repo'}

def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()

def main():
    base = sys.argv[1].rstrip('/')
    wanted = set(sys.argv[2:])
    repomd = ET.fromstring(fetch(base + '/repodata/repomd.xml'))
    primary = None
    for data in repomd.findall('r:data', NS):
        if data.get('type') == 'primary':
            for loc in data.findall('r:location', NS):
                primary = loc.get('href')
    if not primary:
        sys.exit('no primary in repomd')
    blob = fetch(base + '/' + primary)
    if primary.endswith('.zst'):
        try:
            import zstandard
            blob = zstandard.ZstdDecompressor().decompress(blob, max_output_size=600*1024*1024)
        except Exception as e:
            sys.exit(f'zst unsupported: {e}')
    elif primary.endswith('.gz'):
        blob = gzip.decompress(blob)
    root = ET.fromstring(blob)
    found = {}
    for pkg in root.findall('c:package', NS):
        name = pkg.findtext('c:name', namespaces=NS)
        if name not in wanted or name in found:
            continue
        arch = pkg.findtext('c:arch', namespaces=NS)
        ver = pkg.find('c:version', NS)
        v = f"{ver.get('ver')}-{ver.get('rel')}"
        loc = pkg.find('c:location', NS).get('href')
        found[name] = (v, arch, base + '/' + loc)
    for p in sorted(wanted):
        print('\t'.join([p, *found[p]]) if p in found else f"{p}\tNOT_FOUND")

main()
