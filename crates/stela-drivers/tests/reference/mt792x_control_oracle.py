#!/usr/bin/env python3
"""Compile unchanged pinned ownership/DMA-disable helpers with ASan/UBSan.

Usage: mt792x_control_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
The serialized success-path register model is not physical hardware evidence.
Polling parameters and all register operations are retained in immutable traces.
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
    'mt792x_core.c': '6bbd6b23ef25cf30fdc6c8a1396850dfdfd2b5e876a7ca85a1a89b641f9cb716',
    'mt792x_dma.c': '8c017d74ba5890665b4f38ad694d9dcde5c680b4683b0d07fbfce61b4a98098e',
    'mt792x_regs.h': '6c3d946ff97e6952d8ff702cc0f74c6cc77f64c2e04129d1fdd2ed0024869557',
    'mt792x.h': '8e235c73c8c155e1aba21e4e871a921319c1e670c76ef913faaf9ba72d13111d',
}
texts = {}
for name, digest in hashes.items():
    raw = (source/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(file, name):
    text = texts[file]
    match = re.search(r'^int '+name+r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


helpers = function('mt792x_core.c','__mt792xe_mcu_drv_pmctrl')+'\n'+function('mt792x_dma.c','mt792x_dma_disable')
definitions = {}
for file in ['mt792x.h', 'mt792x_regs.h']:
    for line in texts[file].splitlines():
        match = re.match(r'^#define ([A-Za-z0-9_]+)(?:\([^\n]*?\))?\s+([^\n]+)', line)
        if match:
            definitions[match.group(1)] = (line, match.group(2))
names = set(re.findall(r'\b[A-Za-z0-9_]+\b', helpers)) & definitions.keys()
while True:
    expanded = names | {token for name in names for token in re.findall(r'\b[A-Za-z0-9_]+\b', definitions[name][1]) if token in definitions}
    if expanded == names:
        break
    names = expanded
defines = '\n'.join(definitions[name][0] for name in sorted(names))+'\n'
prelude = r'''// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint32_t u32;
#define BIT(x) (1U<<(x))
#define GENMASK(h,l) ((~0U<<(l)) & (~0U>>(31-(h))))
#define dev_err(...) ((void)0)
struct mt76_dev { void *dev; };
struct mt792x_dev { struct mt76_dev mt76; bool aspm_supported; };
struct operation { u32 kind,address,value; };
struct poll { u32 address,mask,expected,timeout,tick; };
static struct operation ops[64];static u32 nops;
static struct poll polls[16];static u32 npolls;
static u32 own=4,glo=0x5a228055,ext=0xa5a50040,sw=0xaabb0000,rst=0xc0ff00ff;
static u32 mapped(u32 a) {
 if(a>=0x7c060000 && a<0x7c070000)return 0xe0000+a-0x7c060000;
 if(a>=0x7c020000 && a<0x7c030000)return 0xd0000+a-0x7c020000;
 return a;
}
static u32 *reg(u32 a) {
 switch(mapped(a)) {
 case 0xe0010:return &own;case 0xd4208:return &glo;case 0xd42b0:return &ext;
 case 0xd6004:return &sw;case 0xd4100:return &rst;default:abort();
 }
}
static u32 rr(struct mt792x_dev *d,u32 a) {
 (void)d;u32 v=*reg(a);if(nops==64)abort();ops[nops++]=(struct operation){0,mapped(a),v};return v;
}
static void wr(struct mt792x_dev *d,u32 a,u32 v) {
 (void)d;if(nops==64)abort();ops[nops++]=(struct operation){1,mapped(a),v};
 if(mapped(a)==0xe0010 && v==2)own&=~4U;else *reg(a)=v;
}
#define mt76_wr(d,a,v) wr(d,a,v)
#define mt76_clear(d,a,m) wr(d,a,rr(d,a)&~(m))
#define mt76_set(d,a,v) wr(d,a,rr(d,a)|(v))
static bool poll_tick(struct mt792x_dev *d,u32 a,u32 m,u32 e,u32 timeout,u32 tick) {
 if(npolls==16)abort();polls[npolls++]=(struct poll){a,m,e,timeout,tick};return (rr(d,a)&m)==e;
}
#define mt76_poll_msec_tick(d,a,m,e,t,k) poll_tick(d,a,m,e,t,k)
static void usleep_range(int low,int high) { (void)low;(void)high;abort(); }
static bool is_mt7927(struct mt76_dev *d) { (void)d;return false; }
'''
main = r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;bool force=atoi(argv[1])!=0;struct mt792x_dev d={0};
 if(__mt792xe_mcu_drv_pmctrl(&d) || mt792x_dma_disable(&d,force))abort();
 u32 header[]={nops,npolls};
 if(fwrite(header,sizeof(header),1,stdout)!=1 || fwrite(ops,sizeof(*ops),nops,stdout)!=nops || fwrite(polls,sizeof(*polls),npolls,stdout)!=npolls)abort();
 return 0;
}
'''
code = prelude+defines+helpers+'\n'+main
(out/'control.c').write_text(code)
subprocess.run(['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(out/'control.c'),'-o',str(out/'control')],check=True)
manifest = {'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','source_sha256':hashes,'c_sha256':hashlib.sha256(code.encode()).hexdigest(),'traces':{}}
for force in [False, True]:
    name = 'force' if force else 'stop'
    trace = subprocess.run([str(out/'control'),str(int(force))],check=True,capture_output=True).stdout
    (out/f'{name}.bin').write_bytes(trace)
    manifest['traces'][name]={'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest['traces'],indent=2))
