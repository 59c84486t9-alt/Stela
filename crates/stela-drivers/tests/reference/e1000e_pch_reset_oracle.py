#!/usr/bin/env python3
"""Compare the unchanged pinned 82579 global-reset prefix under ASan/UBSan.

Usage: e1000e_pch_reset_oracle.py E1000E_DIRECTORY FRESH_OUTPUT_DIRECTORY
The oracle runs the complete original reset function; the trace ends at its
get_cfg_done boundary. Only actual stores, STATUS flush/poll reads and delays
are compared. Extra Stela read-only qualification and reset-clear verification
are excluded explicitly; their failures are covered by adverse models.
This is not evidence for post-reset PHY/NVM or packet queues.
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
    'ich8lan.c': 'f4dcb5d894aaf10f3e4a823bd041d698e5a76e91d478878f58ab008782bd1756',
    'ich8lan.h': '1740953124712287bce427e567ded42650de7488cd10ca8efcf148e65e69e5d3',
    'mac.c': '7b2c5d5676660fc94f09d615cc517c01315f58befa70311f4d9e1cde9d686050',
    'defines.h': '2f1000c156609dc033e079595b36201dd8afdda5f2eefa2aa8136629f8cb93d6',
    'regs.h': 'd88b2d94c0e44ea791b01a9958788bd43993f39e41fa19a102313fef5420c45f',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(file, name):
    text = texts[file]
    match = re.search(r'^(?:static )?(?:void|s32)\s*\n?' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


functions = [
    ('ich8lan.c', 'e1000_acquire_swflag_ich8lan'),
    ('ich8lan.c', 'e1000_gate_hw_phy_config_ich8lan'),
    ('mac.c', 'e1000e_disable_pcie_master'),
    ('ich8lan.c', 'e1000_reset_hw_ich8lan'),
]
helpers = '\n\n'.join(function(file, name) for file, name in functions)
macros = {}
for text in texts.values():
    lines = iter(text.splitlines())
    for line in lines:
        if not line.startswith('#define '):
            continue
        parts = [line]
        while parts[-1].endswith('\\'):
            parts.append(next(lines))
        macros[re.match(r'#define\s+(\w+)', line).group(1)] = '\n'.join(parts)
names = set(re.findall(r'\b[A-Z][A-Z0-9_]+\b', helpers)) & macros.keys()
# er32/ew32 token-paste the actual register definitions.
names |= {'E1000_' + n for n in re.findall(r'e[wr]32\((\w+)', helpers)}
while True:
    dependencies = set(re.findall(r'\b[A-Z][A-Z0-9_]+\b', '\n'.join(macros[n] for n in names))) & macros.keys()
    if dependencies <= names:
        break
    names |= dependencies
definitions = '\n'.join(macros[name] for name in sorted(names)) + '\n'
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;
#define BIT(n) (1u<<(n))
#define e_dbg(...) do { if(0)fprintf(stderr,__VA_ARGS__); } while(0)
#define __E1000_ACCESS_SHARED_RESOURCE 0
enum { e1000_ich8lan, e1000_pchlan, e1000_pch2lan, e1000_pch_ptp };
struct e1000_hw;
struct e1000_adapter { unsigned long state; };
struct e1000_dev_spec_ich8lan { bool nvm_k1_enabled; };
struct e1000_hw {
 struct e1000_adapter *adapter;
 struct { u32 type; } mac;
 struct { struct { s32 (*check_reset_block)(struct e1000_hw*); s32 (*get_cfg_done)(struct e1000_hw*); } ops; } phy;
 struct { struct e1000_dev_spec_ich8lan ich8lan; } dev_spec;
};
struct operation { u32 kind,address,value; };
static struct operation ops[4096];static u32 nops,prefix;
static u32 registers[0x6000/4],busy;
static uint64_t now,quiet;
static void record(u32 kind,u32 address,u32 value) { if(nops==4096)abort();ops[nops++]=(struct operation){kind,address,value}; }
static void udelay(u32 n) { now+=n;record(2,n,0); }
static void mdelay(u32 n) { udelay(n*1000); }
static void msleep(u32 n) { mdelay(n); }
static void usleep_range(u32 low,u32 high) { (void)high;udelay(low); }
static bool test_and_set_bit(unsigned n,unsigned long *p) { bool old=(*p&(1ul<<n))!=0;*p|=1ul<<n;return old; }
static void clear_bit(unsigned n,unsigned long *p) { *p&=~(1ul<<n); }
static u32 model_read(u32 at) {
 if(now<quiet||at/4>=sizeof(registers)/sizeof(*registers))abort();
 u32 value=registers[at/4];
 if(at==8&&busy){--busy;value|=1u<<19;}
 if(at==8)record(0,at,value);
 return value;
}
static void model_write(u32 at,u32 value) {
 if(now<quiet||at/4>=sizeof(registers)/sizeof(*registers))abort();record(1,at,value);
 if(at==0&&(value&(1u<<26))){registers[0]=value&~((1u<<26)|(1u<<31));registers[0xf00/4]&=~(1u<<5);quiet=now+20000;}
 else registers[at/4]=value;
}
#define er32(name) ((void)hw, model_read(E1000_##name))
#define ew32(name,value) model_write(E1000_##name,value)
#define e1e_flush() ((void)model_read(8))
static s32 check_reset(struct e1000_hw *hw) { (void)hw;return 0; }
static s32 cfg_done(struct e1000_hw *hw) { (void)hw;prefix=nops;return 0; }
static s32 e1000_post_phy_reset_ich8lan(struct e1000_hw *hw) { (void)hw;return 0; }
static s32 e1000_read_nvm(struct e1000_hw *hw,u16 at,u16 count,u16 *data) { (void)hw;(void)at;(void)count;*data=0;return 0; }
'''
main = r'''
int main(void) {
 const u32 cases[]={0,2,799};
 for(u32 i=0;i<3;i++) {
  struct e1000_adapter adapter={0};struct e1000_hw hw={.adapter=&adapter};
  hw.mac.type=e1000_pch2lan;hw.phy.ops.check_reset_block=check_reset;hw.phy.ops.get_cfg_done=cfg_done;
  memset(registers,0,sizeof(registers));registers[0xf00/4]=64u<<16;registers[0x5b54/4]=0x40;
  nops=prefix=0;now=quiet=0;busy=cases[i];
  if(e1000_reset_hw_ich8lan(&hw)||!prefix||adapter.state)abort();
  u32 header[]={cases[i],prefix};
  if(fwrite(header,sizeof(header),1,stdout)!=1||fwrite(ops,sizeof(*ops),prefix,stdout)!=prefix)abort();
 }
 return 0;
}
'''
cpath = out / 'pch_reset.c'
cpath.write_text(prelude + definitions + helpers + main)
binary = out / 'pch_reset'
command = ['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror', str(cpath), '-o', str(binary)]
subprocess.run(command, check=True)
trace = out / 'trace.bin'
with trace.open('wb') as file:
    subprocess.run([str(binary.resolve())], stdout=file, check=True)


def binding(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


manifest = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', source_sha256=hashes,
                unchanged_functions=[name for _, name in functions], cases=3, command=command,
                artifacts=[binding(p) for p in (cpath, binary, trace)],
                limits=['Unmanaged 82579 global-reset prefix only; ordered model, no physical hardware',
                        'Post-reset/get_cfg_done are explicit boundary stubs; no PHY/NVM/queue proof',
                        'Only stores, STATUS reads and minimum delays compared; extra Stela qualifications separately fault-tested'])
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(binding(trace)))
