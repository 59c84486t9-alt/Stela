#!/usr/bin/env python3
"""Execute unchanged 82579 post-reset/LCD/OEM helpers with ASan/UBSan.

Usage: e1000e_pch_post_oracle.py E1000E_DIRECTORY FRESH_OUTPUT_DIRECTORY
The trace compares ordered logical PHY reads/writes, gate changes and minimum
post-reset delays. Logical PHY and immutable NVM accessors are model boundaries;
the separate unchanged MDIC/HV and flash-engine oracles cover their transport.
Stela prevalidates the complete LCD script before writing it, so flash reads
and semaphore operations are intentionally outside this normalized comparison.
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
    'phy.h': '08ad67fb4d47bc9bcf985cad117f84571ab0498057347b2a7187c27a9639a022',
    'defines.h': '2f1000c156609dc033e079595b36201dd8afdda5f2eefa2aa8136629f8cb93d6',
    'regs.h': 'd88b2d94c0e44ea791b01a9958788bd43993f39e41fa19a102313fef5420c45f',
    'hw.h': 'f6eb7a08efd4b1dfa760fb8945c0e4d4fc9fc9af84b543129ab499115af7b4d0',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(name):
    text = texts['ich8lan.c']
    match = re.search(r'^(?:static )?(?:void|s32)\s*\n?' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


functions = [
    'e1000_acquire_swflag_ich8lan', 'e1000_release_swflag_ich8lan',
    'e1000_check_reset_block_ich8lan', 'e1000_gate_hw_phy_config_ich8lan',
    '__e1000_access_emi_reg_locked', 'e1000_write_emi_reg_locked',
    'e1000_set_mdio_slow_mode_hv', 'e1000_lv_phy_workarounds_ich8lan',
    'e1000_write_smbus_addr', 'e1000_sw_lcd_config_ich8lan',
    'e1000_oem_bits_config_ich8lan', 'e1000_post_phy_reset_ich8lan',
]
helpers = '\n\n'.join(function(name) for name in functions)
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
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define fallthrough ((void)0)
#define e_dbg(...) do { if(0)fprintf(stderr,__VA_ARGS__); } while(0)
#define __E1000_ACCESS_SHARED_RESOURCE 0
enum { e1000_ich8lan, e1000_ich9lan, e1000_ich10lan, e1000_pchlan,
 e1000_pch2lan, e1000_pch_lpt, e1000_pch_spt, e1000_pch_cnp,
 e1000_pch_tgp,e1000_pch_adp,e1000_pch_mtp,e1000_pch_lnp,e1000_pch_ptp,e1000_pch_nvp };
enum { e1000_phy_igp_3, e1000_phy_82579, e1000_phy_i217 };
struct e1000_hw;
struct pci { u16 device; };
struct e1000_adapter { unsigned long state; struct pci *pdev; };
struct e1000_phy_info { u32 type; struct { s32 (*acquire)(struct e1000_hw*); void (*release)(struct e1000_hw*); s32 (*check_reset_block)(struct e1000_hw*); } ops; };
struct e1000_hw { struct e1000_adapter *adapter; struct { u32 type; } mac; struct e1000_phy_info phy; };
struct operation { u32 kind,address,value; };
static struct operation ops[256];static u32 nops;
static u32 registers[0x6000/4];static u16 phy[65536],emi[65536],words[2048],emi_address;
static s32 e1000_acquire_swflag_ich8lan(struct e1000_hw*);
static void e1000_release_swflag_ich8lan(struct e1000_hw*);
static void record(u32 kind,u32 at,u32 value) { if(nops==256)abort();ops[nops++]=(struct operation){kind,at,value}; }
static void udelay(u32 n) { if(n>=10000)record(2,n,0); }
static void mdelay(u32 n) { udelay(n*1000); }
static void usleep_range(u32 low,u32 high) { (void)high;udelay(low); }
static bool test_and_set_bit(unsigned n,unsigned long *p) { bool old=(*p&(1ul<<n))!=0;*p|=1ul<<n;return old; }
static void clear_bit(unsigned n,unsigned long *p) { *p&=~(1ul<<n); }
static u32 model_read(u32 at) { if(at/4>=sizeof(registers)/sizeof(*registers))abort();return registers[at/4]; }
static void model_write(u32 at,u32 value) {
 if(at/4>=sizeof(registers)/sizeof(*registers))abort();
 if(at==0xf00&&((registers[at/4]^value)&0x80))record(1,at,value&~0x20u);
 registers[at/4]=value;
}
#define er32(name) ((void)hw,model_read(E1000_##name))
#define ew32(name,value) model_write(E1000_##name,value)
static s32 phy_read(struct e1000_hw *hw,u32 at,u16 *value) {
 if(!hw->adapter->state||at>=65536)abort();*value=at==17?emi[emi_address]:phy[at];record(10,at,*value);return 0;
}
static s32 phy_write(struct e1000_hw *hw,u32 at,u16 value) {
 if(!hw->adapter->state||at>=65536)abort();record(11,at,value);
 if(at==16)emi_address=value;else if(at==17)emi[emi_address]=value;else phy[at]=value;return 0;
}
static s32 phy_read_unlocked(struct e1000_hw *hw,u32 at,u16 *value) {
 s32 result=hw->phy.ops.acquire(hw);if(result)return result;result=phy_read(hw,at,value);hw->phy.ops.release(hw);return result;
}
static s32 phy_write_unlocked(struct e1000_hw *hw,u32 at,u16 value) {
 s32 result=hw->phy.ops.acquire(hw);if(result)return result;result=phy_write(hw,at,value);hw->phy.ops.release(hw);return result;
}
#define e1e_rphy_locked phy_read
#define e1e_wphy_locked phy_write
#define e1e_rphy phy_read_unlocked
#define e1e_wphy phy_write_unlocked
#define e1000_read_phy_reg_hv_locked phy_read
#define e1000_write_phy_reg_hv_locked phy_write
static s32 e1000_read_nvm(struct e1000_hw *hw,u16 at,u16 count,u16 *data) {
 (void)hw;if((u32)at+count>2048)abort();memcpy(data,words+at,count*sizeof(*data));return 0;
}
static s32 e1000_hv_phy_workarounds_ich8lan(struct e1000_hw *hw) { (void)hw;abort(); }
'''
main = r'''
int main(void) {
 for(u32 sw=0;sw<2;sw++)for(u32 count=0;count<=4;count+=4)
 for(u32 oem=0;oem<4;oem++)for(u32 strap=0;strap<2;strap++) {
  struct pci pci={.device=0x1503};struct e1000_adapter adapter={.pdev=&pci};struct e1000_hw hw={.adapter=&adapter};
  hw.mac.type=e1000_pch2lan;hw.phy.type=e1000_phy_82579;
  hw.phy.ops.acquire=e1000_acquire_swflag_ich8lan;hw.phy.ops.release=e1000_release_swflag_ich8lan;hw.phy.ops.check_reset_block=e1000_check_reset_block_ich8lan;
  memset(registers,0,sizeof(registers));memset(phy,0,sizeof(phy));memset(emi,0,sizeof(emi));memset(words,0,sizeof(words));emi_address=0;nops=0;
  registers[0x5b54/4]=0x40;registers[0xf00/4]=(64u<<16)|0x80;
  registers[0x28/4]=sw?(1u<<27):0;registers[0xf08/4]=count<<16;
  registers[0xf10/4]=(oem&1?2u:0)|(oem&2?0x40u:0);registers[0xc/4]=strap?0x55u<<17:0;
  registers[0xe00/4]=strap?0xa5c7:0x5a38;
  phy[(769u<<5)|16]=0x5252;phy[(769u<<5)|17]=0x77f7;
  phy[(768u<<5)|26]=0xa511;phy[(768u<<5)|30]=0x9632;phy[(768u<<5)|25]=0xa09c;
  const u16 lcd[]={769u<<5,31,0x125a,20,772u<<5,31,0x5601,21};memcpy(words+128,lcd,sizeof(lcd));
  if(e1000_post_phy_reset_ich8lan(&hw)||adapter.state)abort();
  u32 header[]={sw,count,oem,strap,nops};
  if(fwrite(header,sizeof(header),1,stdout)!=1||fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();
 }
 return 0;
}
'''
cpath = out / 'pch_post.c'
cpath.write_text(prelude + definitions + helpers + main)
binary = out / 'pch_post'
command = ['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror', str(cpath), '-o', str(binary)]
subprocess.run(command, check=True)
trace = out / 'trace.bin'
with trace.open('wb') as file:
    subprocess.run([str(binary.resolve())], stdout=file, check=True)


def binding(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


manifest = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b', source_sha256=hashes,
                unchanged_functions=functions, cases=32, command=command,
                artifacts=[binding(p) for p in (cpath, binary, trace)],
                limits=['Logical PHY and immutable NVM accessors are model boundaries; separate transport oracles required',
                        '82579 unmanaged post-reset/LCD/OEM only; no LPT/SPT, physical or queue proof',
                        'Complete LCD preflight intentionally changes flash/semaphore order; normalized PHY effects, gate changes and minimum delays compared'])
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(binding(trace)))
