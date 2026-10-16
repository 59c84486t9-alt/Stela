#!/usr/bin/env python3
"""Package an inspected fixed-address linked image for QEMU Multiboot1.

LLVM owns ELF parsing. This host tool requires its observed PT_LOAD geometry to
be one linear file mapping, verifies the linked address-fields header, and copies
exact initialized bytes. QEMU's original Multiboot loader owns loading and BSS
zeroing; this is neither a runtime ELF loader nor an ARM execution path.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def package(elf, output, llvm):
    raw = elf.read_bytes()
    headers = subprocess.check_output([str(llvm / 'llvm-objdump'), '-p', str(elf)], text=True)
    symbols = subprocess.check_output([str(llvm / 'llvm-nm'), '--defined-only', '--format=posix', str(elf)], text=True)
    loads = []
    rows = headers.splitlines()
    for index, row in enumerate(rows):
        match = re.fullmatch(r'\s*LOAD off\s+(0x[0-9a-f]+) vaddr\s+(0x[0-9a-f]+) paddr\s+(0x[0-9a-f]+) align 2\*\*(\d+)', row)
        if match:
            extent = re.fullmatch(r'\s*filesz\s+(0x[0-9a-f]+) memsz\s+(0x[0-9a-f]+) flags ([rwx-]+)', rows[index + 1])
            if not extent:
                raise ValueError('unrecognized LLVM LOAD extent')
            offset, virtual, physical = (int(value, 16) for value in match.groups()[:3])
            alignment = int(match[4])
            loads.append(dict(offset=offset, virtual=virtual, physical=physical, alignment=alignment,
                              file_bytes=int(extent[1], 16), memory_bytes=int(extent[2], 16), flags=extent[3]))
    names = {'__image_start', '__load_end', '__image_end', 'stela_multiboot_header', 'stela_start32'}
    found = {}
    for row in symbols.splitlines():
        fields = row.split()
        if fields and fields[0] in names:
            found[fields[0]] = int(fields[2], 16)
    if found.keys() != names or not loads:
        raise ValueError('missing actual linked image symbols/LOADs')
    start, end, bss_end = (found[n] for n in ('__image_start', '__load_end', '__image_end'))
    bias = start - loads[0]['offset']
    previous = start
    for load in loads:
        if load['virtual'] != load['physical'] or load['physical'] < previous:
            raise ValueError('nonidentity or overlapping LOAD')
        if load['file_bytes'] > load['memory_bytes'] or load['offset'] + load['file_bytes'] > len(raw):
            raise ValueError('invalid actual LOAD extent')
        if load['file_bytes'] and load['physical'] - load['offset'] != bias:
            raise ValueError('LOADs are not one linear initialized file mapping')
        if load['file_bytes'] and load['physical'] + load['file_bytes'] > end:
            raise ValueError('initialized LOAD outside declared address-fields extent')
        previous = load['physical'] + load['memory_bytes']
    if not (start < end <= bss_end < 0x10000000) or previous != bss_end:
        raise ValueError('invalid linked image/BSS reservation')
    image = raw[start - bias:end - bias]
    header_offset = found['stela_multiboot_header'] - start
    if header_offset < 0 or header_offset + 32 > min(len(image), 8192) or header_offset % 4:
        raise ValueError('Multiboot header not in first aligned 8KiB')
    header = struct.unpack_from('<8I', image, header_offset)
    expected = (found['stela_multiboot_header'], start, end, bss_end, found['stela_start32'])
    if header[0] != 0x1badb002 or header[1] != 0x10003 or sum(header[:3]) & 0xffffffff or header[3:] != expected:
        raise ValueError('linked Multiboot address-fields/checksum mismatch')
    output.mkdir(parents=True, exist_ok=True)
    flat = output / 'stela-multiboot.bin'
    flat.write_bytes(image)
    (output / 'llvm-program-headers.txt').write_text(headers)
    (output / 'llvm-image-symbols.json').write_text(json.dumps(found, indent=2) + '\n')
    report = dict(elf=dict(path=str(elf), sha256=sha(raw), bytes=len(raw)),
                  flat=dict(path=str(flat.resolve()), sha256=sha(image), bytes=len(image)),
                  linked_symbols=found, multiboot_header=list(header), loads=loads,
                  bss_zero_bytes=bss_end - end,
                  claim='Exact host packaging; no QEMU execution or OS boot claim.')
    (output / 'image-binding.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--llvm-bin', type=Path, default=Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin'))
    args = parser.parse_args()
    package(args.elf.resolve(), args.output.resolve(), args.llvm_bin)
