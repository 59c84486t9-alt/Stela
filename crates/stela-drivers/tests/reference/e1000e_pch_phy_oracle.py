#!/usr/bin/env python3
"""Run unchanged pinned Linux PCH PHY helpers under ASan/UBSan.

Usage: e1000e_pch_phy_oracle.py E1000E_DIRECTORY FRESH_OUTPUT_DIRECTORY
The MMIO/MDIO backend is a deterministic ordered model, not physical proof.
Only the no-retry 82579/I217 PHY-access profile is exercised. A wrapper adds
Stela's pre-access management qualification and acknowledged release readback.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=False)
hashes = {'ich8lan.c': 'f4dcb5d894aaf10f3e4a823bd041d698e5a76e91d478878f58ab008782bd1756',
 'ich8lan.h': '1740953124712287bce427e567ded42650de7488cd10ca8efcf148e65e69e5d3',
 'phy.c': '9be29547dd94354cfd5b55160ca36c1b5ffef49ffd14294f6defb0b3d04c81ad',
 'phy.h': '08ad67fb4d47bc9bcf985cad117f84571ab0498057347b2a7187c27a9639a022',
 'defines.h': '2f1000c156609dc033e079595b36201dd8afdda5f2eefa2aa8136629f8cb93d6',
 'regs.h': 'd88b2d94c0e44ea791b01a9958788bd43993f39e41fa19a102313fef5420c45f'}
texts = {}
for name, digest in hashes.items():
    raw = (source/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(file, name):
    text = texts[file]
    match = re.search(r'^(?:static (?:inline )?)?(?:void|u32|s32)\s*\n?' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


# Retain each complete macro definition, including continued source lines.
macros = {}
for text in texts.values():
    lines = iter(text.splitlines())
    for line in lines:
        if not line.startswith('#define '):
            continue
        parts = [line]
        while parts[-1].endswith('\\'):
            parts.append(next(lines))
        definition = '\n'.join(parts)
        name = re.match(r'#define\s+(\w+)', line).group(1)
        macros[name] = definition

names = ['E1000_MDIC', 'E1000_EXTCNF_CTRL', 'E1000_FWSM', 'E1000_PHY_CTRL',
         'E1000_EXTCNF_CTRL_SWFLAG', 'PHY_CFG_TIMEOUT', 'SW_FLAG_TIMEOUT',
         'E1000_ERR_PHY', 'E1000_ERR_CONFIG', 'E1000_ERR_PARAM',
         'E1000_MDIC_REG_MASK', 'E1000_MDIC_REG_SHIFT', 'E1000_MDIC_PHY_SHIFT',
         'E1000_MDIC_OP_WRITE', 'E1000_MDIC_OP_READ', 'E1000_MDIC_READY',
         'E1000_MDIC_ERROR', 'E1000_GEN_POLL_TIMEOUT', 'MAX_PHY_REG_ADDRESS',
         'MAX_PHY_MULTI_PAGE_REG', 'IGP01E1000_PHY_PAGE_SELECT', 'BM_PORT_CTRL_PAGE',
         'BM_WUC_PAGE', 'BM_WUC_ADDRESS_OPCODE', 'BM_WUC_DATA_OPCODE',
         'BM_WUC_ENABLE_REG', 'BM_WUC_ENABLE_BIT', 'BM_WUC_HOST_WU_BIT',
         'BM_WUC_ME_WU_BIT', 'BM_PHY_REG_PAGE', 'BM_PHY_REG_NUM',
         'IGP_PAGE_SHIFT', 'PHY_PAGE_SHIFT', 'PHY_UPPER_SHIFT', 'HV_INTC_FC_PAGE_START',
         'I82578_ADDR_REG', 'I82577_ADDR_REG', 'E1000_PHY_CTRL_GBE_DISABLE']
definitions = '\n'.join(macros[name] for name in names)+'\n'
functions = [
    ('ich8lan.c','e1000_acquire_swflag_ich8lan'),
    ('ich8lan.c','e1000_release_swflag_ich8lan'),
    ('phy.c','e1000e_read_phy_reg_mdic'),
    ('phy.c','e1000e_write_phy_reg_mdic'),
    ('phy.c','e1000_set_page_igp'),
    ('phy.c','e1000_get_phy_addr_for_hv_page'),
    ('phy.c','e1000_access_phy_debug_regs_hv'),
    ('phy.c','e1000_enable_phy_wakeup_reg_access_bm'),
    ('phy.c','e1000_disable_phy_wakeup_reg_access_bm'),
    ('phy.c','e1000_access_phy_wakeup_reg_bm'),
    ('phy.c','__e1000_read_phy_reg_hv'),
    ('phy.c','__e1000_write_phy_reg_hv'),
]
helpers = '\n\n'.join(function(file,name) for file,name in functions)
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32;
#define BIT(n) (1u<<(n))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define e_dbg(...) do { if(0)fprintf(stderr,__VA_ARGS__); } while(0)
#define __E1000_ACCESS_SHARED_RESOURCE 0
enum { e1000_pch2lan, e1000_pch_lpt, e1000_pchlan };
enum { e1000_phy_82579, e1000_phy_i217, e1000_phy_82578 };
struct e1000_hw;
struct e1000_adapter { unsigned long state; };
struct e1000_phy_ops { s32 (*acquire)(struct e1000_hw*); void (*release)(struct e1000_hw*); };
struct e1000_phy_info { u32 addr, type, revision, retry_count; bool retry_enabled; struct e1000_phy_ops ops; };
struct e1000_hw { struct e1000_adapter *adapter; struct e1000_phy_info phy; struct { u32 type; } mac; };
struct operation { u32 kind, address, value; };
static struct operation ops[256];static u32 nops;
struct word { u8 address;u16 page,index,value; };
static struct word words[64];static u32 nwords;
static u32 ext,command;static u16 page,debug_addr,wake_addr;
static void record(u32 kind,u32 address,u32 value) { if(nops==256)abort();ops[nops++]=(struct operation){kind,address,value}; }
static bool test_and_set_bit(unsigned n,unsigned long *p) { bool old=(*p&(1ul<<n))!=0;*p|=1ul<<n;return old; }
static void clear_bit(unsigned n,unsigned long *p) { *p&=~(1ul<<n); }
static void udelay(u32 n) { record(2,n,0); }
static void mdelay(u32 n) { udelay(n*1000); }
static void key(u8 address,u16 index,u16 *p,u16 *r) {
 *p=index<=15?0:page;*r=index;
 if(address==1&&page==800&&index==18)*r=wake_addr;
 else if(address==2&&index==17){*p=0xffff;*r=debug_addr;}
}
static u16 load(u8 address,u16 index) {
 u16 p,r;key(address,index,&p,&r);
 for(u32 i=0;i<nwords;i++)if(words[i].address==address&&words[i].page==p&&words[i].index==r)return words[i].value;
 return (u16)(0xa55a^((u16)address<<8)^(u16)(p*5)^r);
}
static void store(u8 address,u16 index,u16 value) {
 if(address==1&&index==31){page=value>>5;return;}
 if(address==1&&page==800&&index==17){wake_addr=value;return;}
 if(address==2&&index==16){debug_addr=value;return;}
 u16 p,r;key(address,index,&p,&r);
 for(u32 i=0;i<nwords;i++)if(words[i].address==address&&words[i].page==p&&words[i].index==r){words[i].value=value;return;}
 if(nwords==64)abort();words[nwords++]=(struct word){address,p,r,value};
}
static u32 model_read(u32 address) {
 u32 value;switch(address){case 0xf00:value=ext;break;case 0x5b54:value=0x40;break;case 0x20:value=command;break;default:abort();}
 record(0,address,value);return value;
}
static void model_write(u32 address,u32 value) {
 record(1,address,value);
 if(address==0xf00){ext=value;return;}
 if(address!=0x20)abort();u8 phy=(value>>21)&31;u16 index=(value>>16)&31,data;
 if(value&(1u<<26)){data=(u16)value;store(phy,index,data);}else data=load(phy,index);
 command=(value&~0xffffu)|data|(1u<<28);
}
#define er32(name) model_read(E1000_##name)
#define ew32(name,value) model_write(E1000_##name,value)
'''
main = r'''
int main(void) {
 static const u16 pages[]={0,1,2,3,767,768,769,770,776,800,801,2047};
 static const u16 registers[]={0,15,16,17,31};
 static const u16 extended[]={32,63,70,127,0x1234,0xffff};
 for(u32 kind=0;kind<2;kind++)for(u32 caseid=0;caseid<66;caseid++)for(u32 write=0;write<2;write++) {
  u16 p=caseid<60?pages[caseid/5]:800;
  u16 reg=caseid<60?registers[caseid%5]:extended[caseid-60];
  u32 offset=(reg&31)|((u32)p<<5)|((u32)(reg&~31u)<<16);
  struct e1000_adapter adapter={0};struct e1000_hw hw={.adapter=&adapter};
  hw.mac.type=kind?e1000_pch_lpt:e1000_pch2lan;hw.phy.type=kind?e1000_phy_i217:e1000_phy_82579;
  hw.phy.ops.acquire=e1000_acquire_swflag_ich8lan;hw.phy.ops.release=e1000_release_swflag_ich8lan;
  nops=0;nwords=0;ext=0xa5000800;command=0;page=debug_addr=wake_addr=0;
  if(model_read(E1000_FWSM)!=0x40)abort();
  u16 data=0x9876;s32 result=write?__e1000_write_phy_reg_hv(&hw,offset,data,false,false):__e1000_read_phy_reg_hv(&hw,offset,&data,false,false);
  if(result||adapter.state||model_read(E1000_EXTCNF_CTRL)!=0xa5000800)abort();
  u32 header[]={kind,p,reg,write,0x9876,data,nops};
  if(fwrite(header,sizeof(header),1,stdout)!=1||fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();
 }
 return 0;
}
'''
cpath=out/'pch_phy.c';cpath.write_text(prelude+definitions+helpers+main)
binary=out/'pch_phy'
command=['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Wall','-Wextra','-Werror',str(cpath),'-o',str(binary)]
subprocess.run(command,check=True)
trace=out/'trace.bin'
with trace.open('wb') as file:subprocess.run([str(binary.resolve())],stdout=file,check=True)
def binding(path):
    b=path.read_bytes();return dict(path=str(path),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
manifest=dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',source_sha256=hashes,unchanged_functions=[name for file,name in functions],cases=264,command=command,artifacts=[binding(p) for p in [cpath,binary,trace]],limits=['Ordered MMIO/MDIO model; no actual PCH hardware or MAC/network admission','No-retry 82579/I217 access profile; no ME coexistence/reset/NVM/ULP/datapath proof'])
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(binding(trace)))
