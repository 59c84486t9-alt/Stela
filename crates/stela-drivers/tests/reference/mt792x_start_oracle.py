#!/usr/bin/env python3
"""Compile unchanged pinned WFDMA prefetch/enable helpers with ASan/UBSan.

Usage: mt792x_start_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
The register boundary is modeled. IRQ enabling is retained in donor evidence
and explicitly excluded by Rust's polling profile, never claimed equivalent.
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
    'mt792x_dma.c': '8c017d74ba5890665b4f38ad694d9dcde5c680b4683b0d07fbfce61b4a98098e',
    'mt792x_regs.h': '6c3d946ff97e6952d8ff702cc0f74c6cc77f64c2e04129d1fdd2ed0024869557',
}
texts = {}
for name, digest in hashes.items():
    raw = (source/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(name):
    text = texts['mt792x_dma.c']
    match = re.search(r'^(?:static )?(?:void|int)\s*\n?'+name+r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


helpers = '\n'.join(function(n) for n in [
    'mt7925_dma_prefetch_setup','mt7925_wfdma_setup',
    'mt7927_dma_prefetch_setup','mt7927_wfdma_setup',
    'mt7928_dma_prefetch_setup','mt7928_wfdma_setup',
    'mt792x_dma_prefetch','mt792x_dma_enable'])
# Preserve original multiline macro text, including its continuations.
definitions = {}
lines = iter(texts['mt792x_regs.h'].splitlines(keepends=True))
for line in lines:
    while line.rstrip().endswith('\\'):
        line += next(lines)
    match = re.match(r'^#define ([A-Za-z0-9_]+)(?:\([^\n]*?\))?\s+(.+)', line, re.S)
    if match:
        definitions[match.group(1)] = (line, match.group(2))
names = set(re.findall(r'\b[A-Za-z0-9_]+\b', helpers)) & definitions.keys()
while True:
    expanded = names | {token for name in names for token in re.findall(r'\b[A-Za-z0-9_]+\b', definitions[name][1]) if token in definitions}
    if expanded == names:
        break
    names = expanded
defines = ''.join(definitions[name][0] for name in sorted(names))
prefetch = re.search(r'^#define PREFETCH[^\n]+',texts['mt792x_dma.c'],re.M).group()+'\n'
prelude = r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m)) & (m))
struct mt76_dev { bool connac3; };
struct masks { u32 all_complete_mask; };
struct irq_map { struct masks tx,rx; };
struct mt792x_dev { struct mt76_dev mt76;struct irq_map *irq_map; };
struct operation { u32 kind,address,value; };
static struct operation ops[256];static u32 nops;
static u32 regs[0x200000/4];
static u32 mapped(u32 a) {
 if(a>=0x7c020000 && a<0x7c030000)return 0xd0000+a-0x7c020000;
 if(a>=0x54000000 && a<0x54001000)return 0x2000+a-0x54000000;
 return a;
}
static u32 rr(struct mt792x_dev *d,u32 a) {
 (void)d;a=mapped(a);if(a%4 || a>=sizeof(regs) || nops==256)abort();
 u32 v=regs[a/4];ops[nops++]=(struct operation){0,a,v};return v;
}
static void wr(struct mt792x_dev *d,u32 a,u32 v) {
 (void)d;a=mapped(a);if(a%4 || a>=sizeof(regs) || nops==256)abort();
 ops[nops++]=(struct operation){1,a,v};regs[a/4]=v;
}
static void rmw(struct mt792x_dev *d,u32 a,u32 m,u32 v) { wr(d,a,(rr(d,a)&~m)|v); }
#define mt76_rr(d,a) rr(d,a)
#define mt76_wr(d,a,v) wr(d,a,v)
#define mt76_rmw(d,a,m,v) rmw(d,a,m,v)
#define mt76_clear(d,a,m) rmw(d,a,m,0)
#define mt76_set(d,a,v) rmw(d,a,0,v)
static bool is_mt7928(struct mt76_dev *d) { (void)d;return false; }
static bool is_mt7927(struct mt76_dev *d) { (void)d;return false; }
static bool is_mt7902(struct mt76_dev *d) { (void)d;return false; }
static bool is_mt7925(struct mt76_dev *d) { return d->connac3; }
static void mt76_connac_irq_enable(struct mt76_dev *d,u32 mask) {
 (void)d;if(nops==256)abort();ops[nops++]=(struct operation){2,0,mask};
}
'''
main = r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;struct irq_map irq={{0x100},{0x200}};
 struct mt792x_dev d={.mt76={.connac3=atoi(argv[1])==7925},.irq_map=&irq};
 regs[0xd4208/4]=0x5a228055 & ~(1U|(1U<<2)|(1U<<15)|(1U<<28)|(1U<<27)|(1U<<21));
 if(mt792x_dma_enable(&d))abort();
 if(fwrite(&nops,sizeof(nops),1,stdout)!=1 || fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();
 return 0;
}
'''
code = prelude+defines+prefetch+helpers+'\n'+main
(out/'start.c').write_text(code)
subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(out/'start.c'),'-o',str(out/'start')],check=True)
manifest = {'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','source_sha256':hashes,'c_sha256':hashlib.sha256(code.encode()).hexdigest(),'traces':{}}
for chip in [7921,7922,7925]:
    trace = subprocess.run([str(out/'start'),str(chip)],check=True,capture_output=True).stdout
    (out/f'mt{chip}.bin').write_bytes(trace)
    manifest['traces'][str(chip)]={'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest['traces'],indent=2))
