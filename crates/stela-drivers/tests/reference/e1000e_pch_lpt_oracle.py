#!/usr/bin/env python3
"""Execute unchanged LPT reset, post-reset, LTR, SHRA and EEE-off helpers.

Usage: e1000e_pch_lpt_oracle.py E1000E_DIRECTORY FRESH_OUTPUT_DIRECTORY
The trace compares ordered logical PHY reads/writes, gate changes and minimum
post-reset delays. Logical PHY and immutable NVM accessors are model boundaries;
the separate unchanged MDIC/HV and flash-engine oracles cover their transport.
The reset prefix compares every store, STATUS observation and minimum delay
through get_cfg_done. LTR compares PBA reads and LTRV writes; SHRA compares
actual address registers, readback and STATUS flushes under each ownership cap.
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
    'mac.c': '7b2c5d5676660fc94f09d615cc517c01315f58befa70311f4d9e1cde9d686050',
    'hw.h': 'f6eb7a08efd4b1dfa760fb8945c0e4d4fc9fc9af84b543129ab499115af7b4d0',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()


def function(name):
    text = texts['mac.c' if name == 'e1000e_disable_pcie_master' else 'ich8lan.c']
    match = re.search(r'^(?:static )?(?:void|s32|u32|int)\s*\n?' + name + r'\([^;{}]*?\)\n\{', text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


functions = [
    'e1000_acquire_swflag_ich8lan', 'e1000_release_swflag_ich8lan',
    'e1000_check_reset_block_ich8lan', 'e1000_gate_hw_phy_config_ich8lan',
    '__e1000_access_emi_reg_locked', 'e1000_read_emi_reg_locked', 'e1000_write_emi_reg_locked',
    'e1000_set_mdio_slow_mode_hv', 'e1000_lv_phy_workarounds_ich8lan',
    'e1000_write_smbus_addr', 'e1000_sw_lcd_config_ich8lan',
    'e1000_oem_bits_config_ich8lan', 'e1000_post_phy_reset_ich8lan',
    'e1000_set_eee_pchlan', 'e1000_rar_get_count_pch_lpt',
    'e1000_rar_set_pch_lpt', 'e1000_platform_pm_pch_lpt',
    'e1000e_disable_pcie_master', 'e1000_reset_hw_ich8lan',
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
names |= {'E1000_STATUS', 'E1000_LTRV_SCALE_SHIFT'}
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
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef int32_t s32;
#define BIT(n) (1u<<(n))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define max_t(type,a,b) ((type)(a)>(type)(b)?(type)(a):(type)(b))
#define DIV_ROUND_UP(a,b) (((a)+(b)-1)/(b))
#define PCI_LTR_VALUE_MASK E1000_LTRV_VALUE_MASK
#define PCI_LTR_SCALE_SHIFT E1000_LTRV_SCALE_SHIFT
#define MII_LPA 5
#define LPA_100FULL 0x100
#define fallthrough ((void)0)
#define e_dbg(...) do { if(0)fprintf(stderr,__VA_ARGS__); } while(0)
#define __E1000_ACCESS_SHARED_RESOURCE 0
enum { e1000_ich8lan,e1000_ich9lan,e1000_ich10lan,e1000_pchlan,e1000_pch2lan,e1000_pch_lpt,
 e1000_pch_spt,e1000_pch_cnp,e1000_pch_tgp,e1000_pch_adp,e1000_pch_mtp,e1000_pch_lnp,e1000_pch_ptp,e1000_pch_nvp };
enum { e1000_phy_igp_3,e1000_phy_82579,e1000_phy_i217 };
struct e1000_hw;
struct pci {u16 device,snoop,nosnoop;};
struct e1000_adapter {unsigned long state;struct pci *pdev;u32 max_frame_size;};
struct e1000_phy_info {u32 type;struct {s32 (*acquire)(struct e1000_hw*);void (*release)(struct e1000_hw*);s32 (*check_reset_block)(struct e1000_hw*);s32 (*get_cfg_done)(struct e1000_hw*);} ops;};
struct e1000_dev_spec_ich8lan {bool nvm_k1_enabled;bool eee_disable;u16 eee_lp_ability;};
struct e1000_hw {struct e1000_adapter *adapter;struct {u32 type,rar_entry_count;struct {s32 (*get_link_up_info)(struct e1000_hw*,u16*,u16*);}ops;}mac;struct e1000_phy_info phy;struct{struct e1000_dev_spec_ich8lan ich8lan;}dev_spec;};
struct operation {u32 kind,address,value;};
static struct operation ops[4096];static u32 nops,mode,current_speed,prefix,busy;static u64 now,quiet;
static u32 registers[0x6000/4];static u16 phy[65536],emi[65536],words[2048],emi_address;
static s32 e1000_acquire_swflag_ich8lan(struct e1000_hw*);
static void e1000_release_swflag_ich8lan(struct e1000_hw*);
static void record(u32 kind,u32 at,u32 value){if(nops==4096)abort();ops[nops++]=(struct operation){kind,at,value};}
static void udelay(u32 n){now+=n;if(mode==4||(n>=10000&&(mode==0||mode==3)))record(2,n,0);}
static void mdelay(u32 n){udelay(n*1000);}
static void msleep(u32 n){mdelay(n);}
static void usleep_range(u32 low,u32 high){(void)high;udelay(low);}
static bool test_and_set_bit(unsigned n,unsigned long *p){bool old=(*p&(1ul<<n))!=0;*p|=1ul<<n;return old;}
static void clear_bit(unsigned n,unsigned long *p){*p&=~(1ul<<n);}
static u32 model_read(u32 at){
 if(now<quiet||at/4>=sizeof(registers)/sizeof(*registers))abort();u32 value=registers[at/4];
 if(mode==4&&at==8&&busy){--busy;value|=1u<<19;}
 if((mode==4&&at==8)||(mode==1&&at==0x1000)||(mode==2&&(at==8||(at>=0x5400&&at<0x5460))))record(0,at,value);
 return value;
}
static void model_write(u32 at,u32 value){
 if(now<quiet||at/4>=sizeof(registers)/sizeof(*registers))abort();
 if(mode==4)record(1,at,value);
 if(((mode==0||mode==3)&&at==0xf00&&((registers[at/4]^value)&0x80)))record(1,at,value&~0x20u);
 if((mode==1&&at==0xf8)||(mode==2&&at>=0x5400&&at<0x5460))record(1,at,value);
 if(mode==4&&at==0&&(value&(1u<<26))){registers[0]=value&~((1u<<26)|(1u<<31));registers[0xf00/4]&=~(1u<<5);quiet=now+20000;}else registers[at/4]=value;
}
#define er32(name) ((void)hw,model_read(E1000_##name))
#define ew32(name,value) model_write(E1000_##name,value)
#define e1e_flush() ((void)model_read(8))
static s32 phy_read(struct e1000_hw *hw,u32 at,u16 *value){
 if(!hw->adapter->state||at>=65536)abort();*value=at==17?emi[emi_address]:phy[at];if(mode==0||mode==3)record(10,at,*value);return 0;
}
static s32 phy_write(struct e1000_hw *hw,u32 at,u16 value){
 if(!hw->adapter->state||at>=65536)abort();if(mode==0||mode==3)record(11,at,value);
 if(at==16)emi_address=value;else if(at==17)emi[emi_address]=value;else phy[at]=value;return 0;
}
static s32 phy_read_unlocked(struct e1000_hw *hw,u32 at,u16 *value){s32 r=hw->phy.ops.acquire(hw);if(r)return r;r=phy_read(hw,at,value);hw->phy.ops.release(hw);return r;}
static s32 phy_write_unlocked(struct e1000_hw *hw,u32 at,u16 value){s32 r=hw->phy.ops.acquire(hw);if(r)return r;r=phy_write(hw,at,value);hw->phy.ops.release(hw);return r;}
#define e1e_rphy_locked phy_read
#define e1e_wphy_locked phy_write
#define e1e_rphy phy_read_unlocked
#define e1e_wphy phy_write_unlocked
#define e1000_read_phy_reg_hv_locked phy_read
#define e1000_write_phy_reg_hv_locked phy_write
static s32 e1000_read_nvm(struct e1000_hw *hw,u16 at,u16 count,u16 *data){(void)hw;if((u32)at+count>2048)abort();memcpy(data,words+at,count*sizeof(*data));return 0;}
static s32 e1000_hv_phy_workarounds_ich8lan(struct e1000_hw *hw){(void)hw;abort();}
static s32 link_info(struct e1000_hw *hw,u16 *speed,u16 *duplex){(void)hw;*speed=(u16)current_speed;*duplex=2;return 0;}
static int pci_read_config_word(struct pci *pci,u32 at,u16 *value){if(at==0xa8)*value=pci->snoop;else if(at==0xaa)*value=pci->nosnoop;else abort();return 0;}
static void reset_model(void){memset(registers,0,sizeof(registers));memset(phy,0,sizeof(phy));memset(emi,0,sizeof(emi));memset(words,0,sizeof(words));emi_address=0;nops=prefix=busy=0;now=quiet=0;registers[0x5b54/4]=0x40;registers[0xf00/4]=(64u<<16)|0x80;}
static s32 cfg_done(struct e1000_hw *hw){(void)hw;prefix=nops;return 0;}
static void output(u32 a,u32 b,u32 c,u32 d){u32 header[]={mode,a,b,c,d,nops};if(fwrite(header,sizeof(header),1,stdout)!=1||fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();}
'''
main = r'''
int main(void){
 struct pci pci={.device=0x153b,.snoop=0x1003,.nosnoop=0x1003};
 struct e1000_adapter adapter={.pdev=&pci,.max_frame_size=1518};struct e1000_hw hw={.adapter=&adapter};
 hw.mac.type=e1000_pch_lpt;hw.mac.rar_entry_count=12;hw.mac.ops.get_link_up_info=link_info;hw.phy.type=e1000_phy_i217;
 hw.phy.ops.acquire=e1000_acquire_swflag_ich8lan;hw.phy.ops.release=e1000_release_swflag_ich8lan;hw.phy.ops.check_reset_block=e1000_check_reset_block_ich8lan;
 mode=0;
 for(u32 sw=0;sw<2;sw++)for(u32 count=0;count<=4;count+=4)for(u32 oem=0;oem<4;oem++)for(u32 freq=1;freq<=3;freq++){
  reset_model();adapter.state=0;registers[0x28/4]=sw?(1u<<27):0;registers[0xf08/4]=count<<16;
  registers[0xf10/4]=(oem&1?2u:0)|(oem&2?0x40u:0);registers[0xc/4]=(freq<<12)|((freq&1)?0x55u<<17:0);registers[0xe00/4]=(freq&1)?0xa5c7:0x5a38;
  phy[(769u<<5)|16]=0x5252;phy[(769u<<5)|17]=0x77f7;phy[(768u<<5)|26]=0xa511;phy[(768u<<5)|30]=0x9632;phy[(768u<<5)|25]=0xa09c;
  const u16 lcd[]={769u<<5,31,0x125a,20,772u<<5,31,0x5601,21};memcpy(words+128,lcd,sizeof(lcd));
  if(e1000_post_phy_reset_ich8lan(&hw)||adapter.state)abort();output(sw,count,oem,freq);
 }
 mode=1;const u32 speeds[]={10,100,1000},receive[]={2,26,64},limits[]={1,127,1023};
 for(u32 s=0;s<3;s++)for(u32 r=0;r<3;r++)for(u32 scale=0;scale<6;scale++)for(u32 v=0;v<3;v++)for(u32 req=0;req<2;req++){
  reset_model();current_speed=speeds[s];registers[0x1000/4]=receive[r];pci.snoop=(u16)((scale<<10)|limits[v]|(req?0x8000:0));pci.nosnoop=(u16)((scale<<10)|(limits[v]/2)|(req?0:0x8000));
  if(e1000_platform_pm_pch_lpt(&hw,true))abort();output(current_speed,receive[r],pci.snoop,pci.nosnoop);
 }
 reset_model();if(e1000_platform_pm_pch_lpt(&hw,false))abort();output(0,26,0x1003,0x1003);
 mode=2;u8 station[]={2,0x11,0x22,0x33,0x44,0x55},zero[6]={0};
 for(u32 lock=0;lock<8;lock++){
  reset_model();adapter.state=0;registers[8/4]=0x83;registers[0x5b54/4]|=lock<<7;
  for(u32 i=0;i<11;i++){registers[(0x5408+i*8)/4]=0x12340000|i;registers[(0x540c+i*8)/4]=0xabcd0000|i;}
  u32 count=e1000_rar_get_count_pch_lpt(&hw);if(e1000_rar_set_pch_lpt(&hw,station,0))abort();
  for(u32 index=1;index<12;index++)(void)e1000_rar_set_pch_lpt(&hw,zero,index);
  if(adapter.state)abort();output(lock,count,0,0);
 }
 mode=3;const u16 controls[]={0,0x7fff,0xffff};
 for(u32 i=0;i<3;i++){
  reset_model();adapter.state=0;hw.dev_spec.ich8lan.eee_disable=true;phy[(772u<<5)|20]=controls[i];emi[0x9401]=0x3c00;
  if(e1000_acquire_swflag_ich8lan(&hw))abort();if(e1000_write_emi_reg_locked(&hw,0x8001,0))abort();e1000_release_swflag_ich8lan(&hw);
  if(e1000_set_eee_pchlan(&hw)||adapter.state)abort();output(controls[i],0,0,0);
 }
 mode=4;const u32 pending[]={0,2,799};hw.phy.ops.get_cfg_done=cfg_done;
 for(u32 i=0;i<3;i++){
  reset_model();adapter.state=0;busy=pending[i];
  if(e1000_reset_hw_ich8lan(&hw)||!prefix||adapter.state)abort();nops=prefix;output(pending[i],0,0,0);
 }
 return 0;
}
'''
cpath = out / 'pch_lpt.c'
cpath.write_text(prelude + definitions + helpers + main)
binary = out / 'pch_lpt'
command = ['clang', '-std=c11', '-O1', '-g', '-fwrapv', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror', str(cpath), '-o', str(binary)]
subprocess.run(command, check=True)
trace = out / 'trace.bin'
with trace.open('wb') as file:
    subprocess.run([str(binary.resolve())], stdout=file, check=True)


def binding(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


manifest = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',source_sha256=hashes,
                unchanged_functions=functions,unchanged_function_sha256={name:hashlib.sha256(function(name).encode()).hexdigest() for name in functions},cases={'post_reset':48,'ltr':325,'shared_addresses':8,'eee_disabled':3,'global_reset_prefix':3},command=command,
                artifacts=[binding(p) for p in (cpath,binary,trace)],
                limits=['Logical PHY and immutable NVM are model boundaries; prior MDIC/HV/flash oracles required',
                        'Exact unmanaged153a/153b/15a0/15a1 cohort; no ULP-dependent variants or physical proof',
                        'Post/EEE normalize logical PHY effects; RAR normalizes owned address accesses and flushes; LTR compares PBA reads and LTRV writes',
                        'Reset trace ends at get_cfg_done; actual stores, STATUS reads and delays compare; extra Stela qualification/reset-clear reads are separately fault-tested',
                        'Actual config is immutable and captured before Stela initialization; donor config reads occur during link policy',
                        'Clang -fwrapv defines donor promoted bool left shift into bit31 without changing donor bytes; ASan and remaining UBSan checks stay enabled',
                        'LTR cases keep donor u32 wrap boundaries observationally inactive; separate native u64 tests cover legal limits above u32 range'])
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(binding(trace)))
