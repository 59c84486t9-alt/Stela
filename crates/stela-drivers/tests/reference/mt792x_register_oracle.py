#!/usr/bin/env python3
"""Compile unchanged pinned Linux PCI register mappers with ASan/UBSan.

Usage: mt792x_register_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
The actual PCI/MMIO boundary is a serialized state model, not physical proof.
Only valid full-word fixed/direct/L1 addresses are compared: the donor's
one-past fixed-window endpoints and unqualified Connac3 L2 are excluded.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=False)
hashes = {
    'mt7921/pci.c': '271c5d4e04f28b9508d700c986a3a797d8d6e78f2b6f9fa7611df145a1614ff1',
    'mt7925/pci.c': '82a03775d716db6f65e0dc25960a19773e08f8a31aeb77cb91a30fe1da508937',
    'mt7921/mt7921.h': '370d21968a2fd423f4b745be820e83d06f336b17913616da487551a52797baab',
    'mt7921/regs.h': '4a7633c0304b8db77c4fd6c5b2786dd6af08b7ae2331a8b31757b9750173cf1c',
    'mt7925/regs.h': '5232f74ab0c131ec36084ddd6a44b231b1cc7a1c6171a26f21e5949060a8fdab',
}
texts = {}
for name, digest in hashes.items():
    raw = (source/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(file, name):
    text = texts[file]
    match = re.search(r'^(?:static (?:inline )?)?(?:void|u32)\s*\n?' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


prelude = r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
typedef uint32_t u32;
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define unlikely(x) (x)
#define dev_err(...) ((void)0)
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m)) & (m))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
struct mt76_connac_reg_map { u32 phys, maps, size; };
struct mt76_dev { u32 selector; };
struct bus_ops {
 u32 (*rr)(struct mt76_dev *,u32);
 void (*wr)(struct mt76_dev *,u32,u32);
 u32 (*rmw)(struct mt76_dev *,u32,u32,u32);
};
struct mt792x_dev {
 struct mt76_dev mt76;
 struct bus_ops *bus_ops;
 u32 backup_l1, backup_l2;
};
struct operation { u32 kind, offset, value; };
static struct operation ops[32];
static u32 nops;
static u32 selector_offset;
static u32 rr(struct mt76_dev *d,u32 offset) {
 u32 value=offset==selector_offset?d->selector:offset^0x5aa5c0de;
 if(nops==32)abort();ops[nops++]=(struct operation){0,offset,value};return value;
}
static void wr(struct mt76_dev *d,u32 offset,u32 value) {
 if(nops==32)abort();ops[nops++]=(struct operation){1,offset,value};
 if(offset==selector_offset)d->selector=value;
}
static u32 rmw(struct mt76_dev *d,u32 offset,u32 mask,u32 value) {
 u32 result=(rr(d,offset)&~mask)|value;wr(d,offset,result);return result;
}
#define mt76_rr(d,a) rr(&(d)->mt76,a)
#define mt76_rmw_field(d,a,m,v) rmw(&(d)->mt76,a,m,FIELD_PREP(m,v))
static bool is_mt7928(struct mt76_dev *d) { (void)d;return false; }
'''
main = r'''
int main(void) {
 struct bus_ops bus={rr,wr,rmw};
 for(size_t i=0;i<ARRAY_SIZE(addresses);i++) {
  struct mt792x_dev d={.mt76={.selector=0xdec0beef},.bus_ops=&bus};nops=0;
  selector_offset=MT_HIF_REMAP_L1;
  u32 address=addresses[i], mapped=MAPPER(&d,address);
  u32 hdr[]={address,mapped,nops};
  if(fwrite(hdr,sizeof(hdr),1,stdout)!=1)abort();
  if(fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();
 }
 return 0;
}
'''
manifest = {'linux_commit': 'a804c5742bff224d4cb4d25dd383554d598be32b', 'source_sha256': hashes, 'traces': {}}
for chip in [7921, 7922, 7925]:
    connac3 = chip == 7925
    path = 'mt7925/pci.c' if connac3 else 'mt7921/pci.c'
    table = 'default_fixed_map' if connac3 else 'fixed_map'
    body = re.search(r'static const struct mt76_connac_reg_map '+table+r'\[\] = \{(.*?)\n\t\};', texts[path], re.S).group(1)
    maps = [tuple(int(x, 16) for x in triple) for triple in re.findall(r'\{\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+)\s*\}', body)]
    addresses = set([0, 4, 0x100, 0x1fc, 0xffffc, 0x100000, 0x1ffffc] if connac3 else [0, 4, 0x100, 0x1fc, 0xffffc])
    for physical, mapped, size in maps:
        if not size:
            continue
        for offset in [0, 4, size//2//4*4, size-8, size-4]:
            address = physical+offset
            # Only inputs for which the unchanged donor reaches the same
            # full-word mapping. Inclusive earlier endpoints are excluded.
            earlier = next((p for p in maps if p[0] <= address <= p[0]+p[2]), None)
            if earlier and address+4 <= earlier[0]+earlier[2]:
                addresses.add(address)
    for base, end in [(0x18000000,0x18c00000),(0x70000000,0x78000000),(0x7c000000,0x7c400000)]:
        for address in [base,base+4,base+0x140,base+0x10000,base+0x12344,end-4]:
            addresses.add(address)
    # Dynamic-range samples can also hit the donor's inclusive fixed ends.
    addresses = {address for address in addresses if not any(
        size and address == physical+size for physical, _mapped, size in maps)}
    header = texts['mt7925/regs.h' if connac3 else 'mt7921/regs.h']
    names = ['MT_HIF_REMAP_L1', 'MT_HIF_REMAP_L1_MASK',
             'MT_HIF_REMAP_L1_OFFSET', 'MT_HIF_REMAP_L1_BASE', 'MT_HIF_REMAP_BASE_L1']
    names += ['MT_HIF_REMAP_L2', 'MT_HIF_REMAP_BASE_L2'] if connac3 else ['MT_INFRA_CFG_BASE', 'MT_INFRA']
    defines = ''
    for name in names:
        match = re.search(r'^#define '+name+r'(?:\([^\n]*?\))?\s+[^\n]+', header, re.M)
        assert match, name
        defines += match.group()+'\n'
    helpers = ('\n'.join(function(path,n) for n in ['mt7925_reg_remap_restore','mt7925_reg_map_l1','mt7925_reg_map_l2','__mt7925_reg_addr']) if connac3 else function('mt7921/mt7921.h','mt7921_reg_map_l1')+'\n'+function(path,'__mt7921_reg_addr'))
    code = prelude+defines+helpers+'\nstatic u32 addresses[]={'+','.join(hex(x) for x in sorted(addresses))+'};\n#define MAPPER '+('__mt7925_reg_addr' if connac3 else '__mt7921_reg_addr')+'\n'+main
    cpath = out/f'mt{chip}.c'
    cpath.write_text(code)
    binary = out/f'mt{chip}'
    subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(cpath),'-o',str(binary)],check=True)
    trace = subprocess.run([str(binary)],check=True,capture_output=True).stdout
    (out/f'mt{chip}.bin').write_bytes(trace)
    manifest['traces'][str(chip)]={'records':len(addresses),'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest(),'c_sha256':hashlib.sha256(code.encode()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest['traces'],indent=2))
