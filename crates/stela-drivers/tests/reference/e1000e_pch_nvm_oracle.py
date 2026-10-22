#!/usr/bin/env python3
"""Compile unchanged pinned Linux PCH NVM helpers under ASan/UBSan.

Usage: e1000e_pch_nvm_oracle.py E1000E_DIRECTORY FRESH_OUTPUT_DIRECTORY
The fixture implements ordered MMIO and an actual byte-array flash model.
It has one serialized owner, immutable NVM/shadow state and valid banks.
It does not establish physical flash operation or full PCH network support.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
assert sys.byteorder=='little', 'trace format requires little-endian host'
hashes={'ich8lan.c': 'f4dcb5d894aaf10f3e4a823bd041d698e5a76e91d478878f58ab008782bd1756',
 'ich8lan.h': '1740953124712287bce427e567ded42650de7488cd10ca8efcf148e65e69e5d3',
 'defines.h': '2f1000c156609dc033e079595b36201dd8afdda5f2eefa2aa8136629f8cb93d6',
 'regs.h': 'd88b2d94c0e44ea791b01a9958788bd43993f39e41fa19a102313fef5420c45f',
 'hw.h': 'f6eb7a08efd4b1dfa760fb8945c0e4d4fc9fc9af84b543129ab499115af7b4d0',
 'e1000.h': '625a663bc9eebf711ff024219b3e23d86d38dcd4e4b855c2109ecfbb7edc4002'}
texts={}
for name,digest in hashes.items():
    raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()

def block(file,pattern):
    text=texts[file];match=re.search(pattern,text,re.M);assert match,pattern
    at,depth=match.end(),1
    while depth:
        depth+=(text[at]=='{')-(text[at]=='}');at+=1
    return text[match.start():at]

names=['e1000_init_nvm_params_ich8lan','e1000_flash_cycle_init_ich8lan','e1000_flash_cycle_ich8lan','e1000_read_flash_data_ich8lan','e1000_read_flash_data32_ich8lan','e1000_read_flash_word_ich8lan','e1000_read_flash_byte_ich8lan','e1000_read_flash_dword_ich8lan','e1000_valid_nvm_bank_detect_ich8lan','e1000_read_nvm_ich8lan','e1000_read_nvm_spt']
helpers='\n\n'.join(block('ich8lan.c',r'^static s32\s*\n?'+name+r'\([^;{}]*?\)\n\{') for name in names)
unions='\n'.join(block('ich8lan.c',r'^union '+name+r' \{')+';' for name in ['ich8_hws_flash_status','ich8_hws_flash_ctrl'])
macros={}
for text in texts.values():
    lines=iter(text.splitlines())
    for line in lines:
        if not line.startswith('#define '):continue
        parts=[line]
        while parts[-1].endswith('\\'):parts.append(next(lines))
        macros[re.match(r'#define\s+(\w+)',line).group(1)]='\n'.join(parts)
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',helpers))|{'E1000_STRAP','E1000_FWSM','E1000_EECD'}
while True:
    expanded=needed|{token for name in needed if name in macros for token in re.findall(r'\b[A-Z][A-Z0-9_]+\b',macros[name])}
    if expanded==needed:break
    needed=expanded
constants='\n'.join(macros[name] for name in sorted(needed) if name in macros)+'\n'
prelude=r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int32_t s32;
#define BIT(n) (1u<<(n))
#define fallthrough ((void)0)
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define e_dbg(...) do {if(0)fprintf(stderr,__VA_ARGS__);}while(0)
enum {e1000_ich8lan,e1000_ich9lan,e1000_ich10lan,e1000_pchlan,e1000_pch2lan,e1000_pch_lpt,e1000_pch_spt,e1000_pch_cnp,e1000_pch_tgp,e1000_pch_adp,e1000_pch_mtp,e1000_pch_lnp,e1000_pch_ptp,e1000_pch_nvp};
enum {e1000_nvm_flash_sw};
struct e1000_hw;
struct nvm_ops {s32(*acquire)(struct e1000_hw*);void(*release)(struct e1000_hw*);};
struct e1000_nvm_info {u32 type,flash_base_addr,flash_bank_size,word_size;struct nvm_ops ops;};
struct shadow {bool modified;u16 value;};
struct e1000_dev_spec_ich8lan {struct shadow shadow_ram[2048];};
struct e1000_hw {struct {u32 type;}mac;struct e1000_nvm_info nvm;struct {struct e1000_dev_spec_ich8lan ich8lan;}dev_spec;void*flash_address;void*hw_addr;};
struct op {u32 kind,address,value;};static struct op ops[4096];static u32 nops;
static u8 memory[16384],mac_window[0x10000];static u32 layout,address,data,errors,delay_reads,pending;static bool active;
static u16 status,control;
static void record(u32 kind,u32 at,u32 value){if(nops==4096)abort();ops[nops++]=(struct op){kind,at,value};}
static void udelay(u32 us){record(4,us,0);}
static u16 get_status(void){if(active){if(!pending){active=false;status=(status&~32u)|1;if(errors){errors--;status|=2;}}else pending--;}return status;}
static void set_status(u16 value){status&=~(value&7u);}
static void set_control(u16 value){control=value&~1u;if(value&1){if(value&6)abort();u32 size=((value>>8)&3)+1;if(address+size>sizeof(memory))abort();data=0xf0f0f0f0;for(u32 i=0;i<size;i++)data=(data&~(0xffu<<(i*8)))|((u32)memory[address+i]<<(i*8));pending=delay_reads;active=true;status=(status&~7u)|32;}}
static u32 readmac(u32 at){u32 value;if(at==0x5b54)value=0x40;else if(at==0xc)value=2;else abort();record(0x10,at,value);return value;}
static u16 read16flash(u32 at){u16 value;if(at==4)value=get_status();else if(at==6&&layout<2)value=control;else abort();record(0,at,value);return value;}
static u32 read32flash(u32 at){u32 value;if(at==0)value=(3<<16)|2;else if(at==4&&layout==2)value=get_status()|((u32)control<<16);else if(at==16)value=data;else abort();record(1,at,value);return value;}
static void write16flash(u32 at,u16 value){if(layout==2)abort();record(2,at,value);if(at==4)set_status(value);else if(at==6)set_control(value);else abort();}
static void write32flash(u32 at,u32 value){record(3,at,value);if(at==4&&layout==2){set_status((u16)value);set_control(value>>16);}else if(at==8)address=value;else abort();}
#define er32(name) readmac(E1000_##name)
#define er16flash(name) read16flash(name)
#define er32flash(name) read32flash(name)
#define ew16flash(name,value) write16flash(name,value)
#define ew32flash(name,value) write32flash(name,value)
static s32 acquire(struct e1000_hw*hw){(void)hw;return 0;}
static void release(struct e1000_hw*hw){(void)hw;}
'''
main=r'''
static void image(u32 bank){
 memset(memory,0,sizeof(memory));u32 base=layout==2?0:0x2000;
 for(u32 b=0;b<2;b++){
  u16 words[2048];for(u32 i=0;i<2048;i++)words[i]=(u16)(i*17)^(b<<12);
  words[0]=0x1102;words[1]=0x3322;words[2]=0x5544;words[3]|=1;words[0x19]|=0x40;words[0x13]=(words[0x13]&0x3fff)|(b==bank?0x8000:0);
  u16 sum=0;for(u32 i=0;i<63;i++)sum+=words[i];words[63]=0xbaba-sum;
  for(u32 i=0;i<2048;i++){memory[base+b*4096+i*2]=words[i]&0xff;memory[base+b*4096+i*2+1]=words[i]>>8;}
 }
}
int main(void){
 static const u16 offsets[]={0,1,7,2046,2047,0};static const u16 lengths[]={1,2,5,2,1,64};static const u32 delays[]={0,1,3};
 for(layout=0;layout<3;layout++)for(u32 bank=0;bank<2;bank++)for(u32 c=0;c<6;c++)for(u32 error=0;error<3;error++)for(u32 d=0;d<3;d++)for(u32 busy=0;busy<2;busy++){
  struct e1000_hw hw={0};hw.mac.type=layout==0?e1000_pch2lan:layout==1?e1000_pch_lpt:e1000_pch_spt;hw.nvm.ops.acquire=acquire;hw.nvm.ops.release=release;hw.flash_address=memory;hw.hw_addr=mac_window;
  nops=0;errors=error;delay_reads=delays[d];pending=delay_reads;active=busy;status=0x4001|(busy?32:0);control=0x4400;address=data=0;image(bank);
  if(readmac(E1000_FWSM)!=0x40||e1000_init_nvm_params_ich8lan(&hw))abort();
  u16 result[64]={0};s32 rc=layout==2?e1000_read_nvm_spt(&hw,offsets[c],lengths[c],result):e1000_read_nvm_ich8lan(&hw,offsets[c],lengths[c],result);if(rc)abort();
  u32 header[]={layout,bank,offsets[c],lengths[c],error,delays[d],busy,nops};
  if(fwrite(header,sizeof(header),1,stdout)!=1)abort();for(u32 i=0;i<lengths[c];i++){u32 word=result[i];if(fwrite(&word,sizeof(word),1,stdout)!=1)abort();}if(fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();
 }
 return 0;
}
'''
cpath=out/'pch_nvm.c';cpath.write_text(prelude+constants+unions+helpers+main)
binary=out/'pch_nvm';command=['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Wall','-Wextra','-Werror',str(cpath),'-o',str(binary)]
subprocess.run(command,check=True)
trace=out/'trace.bin'
with trace.open('wb')as file:subprocess.run([str(binary.resolve())],stdout=file,check=True)
def binding(path):
    b=path.read_bytes();return dict(path=str(path),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
(out/'manifest.json').write_text(json.dumps(dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',source_sha256=hashes,unchanged_functions=names,source_unions=['ich8_hws_flash_status','ich8_hws_flash_ctrl'],cases=648,command=command,artifacts=[binding(p)for p in [cpath,binary,trace]],limits=['Serialized immutable NVM model; no real flash/PCH traffic','Invalid-bank fallback/checksum repair/persistent writes are excluded; Stela refuses those profiles explicitly']),indent=2)+'\n')
print(json.dumps(binding(trace)))
