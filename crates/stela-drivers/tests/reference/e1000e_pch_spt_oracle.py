#!/usr/bin/env python3
"""Execute unchanged SPT reset/post, ULP exit, link and owned-ring flush helpers.

Usage: e1000e_pch_spt_oracle.py E1000E_DIRECTORY FRESH_OUTPUT_DIRECTORY [spt|cnp|tgp|adp|mtp|ptp]
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

source, out = map(Path, sys.argv[1:3])
requested = sys.argv[3] if len(sys.argv) == 4 else "spt"
assert requested in ("spt", "cnp", "tgp", "adp", "mtp", "ptp")
out.mkdir(parents=True, exist_ok=False)
hashes = {
    'ich8lan.c': 'f4dcb5d894aaf10f3e4a823bd041d698e5a76e91d478878f58ab008782bd1756',
    'ich8lan.h': '1740953124712287bce427e567ded42650de7488cd10ca8efcf148e65e69e5d3',
    'phy.h': '08ad67fb4d47bc9bcf985cad117f84571ab0498057347b2a7187c27a9639a022',
    'defines.h': '2f1000c156609dc033e079595b36201dd8afdda5f2eefa2aa8136629f8cb93d6',
    'regs.h': 'd88b2d94c0e44ea791b01a9958788bd43993f39e41fa19a102313fef5420c45f',
    'mac.c': '7b2c5d5676660fc94f09d615cc517c01315f58befa70311f4d9e1cde9d686050',
    'netdev.c': '771cc6e1d44d40d3cd6204ba4800c3289e145ea4ca97455f341007c3aaf76827',
    'phy.c': '9be29547dd94354cfd5b55160ca36c1b5ffef49ffd14294f6defb0b3d04c81ad',
    'e1000.h': '625a663bc9eebf711ff024219b3e23d86d38dcd4e4b855c2109ecfbb7edc4002',
    'nvm.c': 'ee30e2fd2ed6464404b92ffc120cea9d1937a696878a37244d30ace179a88cda',
    'hw.h': 'f6eb7a08efd4b1dfa760fb8945c0e4d4fc9fc9af84b543129ab499115af7b4d0',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()

# Resolve both source table joins, not a product-suffix/PHY heuristic.
ids = {name:int(value,16) for name,value in re.findall(r'^#define\s+(E1000_DEV_ID_\w+)\s+0x([0-9A-Fa-f]+)',texts['hw.h'],re.M)}
boards = dict(re.findall(r'\[(board_pch_\w+)\]\s*=\s*&(e1000_pch_\w+_info)',texts['netdev.c']))
infos = dict(re.findall(r'const struct e1000_info (e1000_pch_\w+_info) = \{\s*\.mac\s*=\s*(e1000_pch_\w+)',texts['ich8lan.c']))
rows = re.findall(r'PCI_VDEVICE\(INTEL,\s*(E1000_DEV_ID_\w+)\),\s*\.driver_data\s*=\s*(board_pch_\w+)',texts['netdev.c'])
cohort_boards = ('board_pch_mtp','board_pch_ptp') if requested in ('mtp','ptp') else ('board_pch_spt','board_pch_cnp','board_pch_tgp','board_pch_adp')
inventory = [dict(symbol=name,device=ids[name],board=board,mac=infos[boards[board]]) for name,board in rows if board in cohort_boards]
assert len(inventory)==len({r['device'] for r in inventory})==(14 if requested in ('mtp','ptp') else 39)
selected_mac='e1000_pch_'+requested
selected=[r for r in inventory if r['mac']==selected_mac]
assert selected
(out/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')


def function(name):
    text = texts['nvm.c' if name == 'e1000e_validate_nvm_checksum_generic' else 'netdev.c' if name in ['e1000_flush_tx_ring','e1000_flush_rx_ring','e1000_flush_desc_rings'] else 'phy.c' if name in ['e1000e_disable_phy_retry','e1000e_enable_phy_retry','e1000e_phy_has_link_generic','e1000e_check_downshift','__e1000_read_kmrn_reg','__e1000_write_kmrn_reg','e1000e_read_kmrn_reg_locked','e1000e_write_kmrn_reg_locked','e1000e_read_phy_reg_mdic','e1000e_write_phy_reg_mdic'] else 'mac.c' if name in ['e1000e_disable_pcie_master','e1000e_get_speed_and_duplex_copper'] else 'ich8lan.c']
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
    'e1000e_disable_phy_retry','e1000e_enable_phy_retry',
    'e1000_toggle_lanphypc_pch_lpt','e1000_disable_ulp_lpt_lp',
    'e1000e_phy_has_link_generic','e1000e_get_speed_and_duplex_copper',
    'e1000e_check_downshift','e1000_check_for_copper_link_ich8lan',
    'e1000_flush_tx_ring','e1000_flush_rx_ring','e1000_flush_desc_rings',
    'e1000e_validate_nvm_checksum_generic','e1000_validate_nvm_checksum_ich8lan',
    '__e1000_read_kmrn_reg','__e1000_write_kmrn_reg','e1000e_read_kmrn_reg_locked','e1000e_write_kmrn_reg_locked',
    'e1000_configure_k1_ich8lan','e1000e_read_phy_reg_mdic','e1000e_write_phy_reg_mdic',
    'e1000_initialize_hw_bits_ich8lan','e1000_reconfigure_k1_params','e1000_init_hw_ich8lan',
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
#define FIELD_PREP(mask,value) (((value)<<__builtin_ctz(mask))&(mask))
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
#define MII_BMSR 1
#define BMSR_LSTATUS 4
#define SPEED_10 10
#define SPEED_100 100
#define SPEED_1000 1000
#define HALF_DUPLEX 1
#define FULL_DUPLEX 2
#define e_warn(...) do{(void)adapter;e_dbg(__VA_ARGS__);}while(0)
#define wmb() __asm__ volatile("" ::: "memory")
#define cpu_to_le64(v) ((u64)(v))
#define cpu_to_le32(v) ((u32)(v))
#define BUG_ON(v) do{if(v)abort();}while(0)
enum {e1000_ulp_state_unknown,e1000_ulp_state_off,e1000_ulp_state_on};
struct e1000_tx_desc {u64 buffer_addr;union{u32 data;}lower;union{u32 data;}upper;};
_Static_assert(sizeof(struct e1000_tx_desc)==16,"actual legacy TX descriptor width");
struct e1000_ring {u32 next_to_use,count;u64 dma;struct e1000_tx_desc desc[32];};
enum { e1000_ich8lan,e1000_ich9lan,e1000_ich10lan,e1000_pchlan,e1000_pch2lan,e1000_pch_lpt,
 e1000_pch_spt,e1000_pch_cnp,e1000_pch_tgp,e1000_pch_adp,e1000_pch_mtp,e1000_pch_lnp,e1000_pch_ptp,e1000_pch_nvp };
enum { e1000_phy_m88,e1000_phy_gg82563,e1000_phy_bm,e1000_phy_igp_2,e1000_phy_igp_3,e1000_phy_82578,e1000_phy_82579,e1000_phy_i217 };
struct e1000_hw;
struct pci {u16 device,snoop,nosnoop,descriptor;};
struct e1000_adapter;
struct e1000_phy_info {u32 type,addr,retry_count;bool retry_enabled,speed_downgraded;struct {s32 (*acquire)(struct e1000_hw*);void (*release)(struct e1000_hw*);s32 (*check_reset_block)(struct e1000_hw*);s32 (*get_cfg_done)(struct e1000_hw*);s32(*read_reg_locked)(struct e1000_hw*,u32,u16*);s32(*write_reg_locked)(struct e1000_hw*,u32,u16);} ops;};
struct e1000_dev_spec_ich8lan {u32 ulp_state;bool nvm_k1_enabled;bool eee_disable;u16 eee_lp_ability;};
struct e1000_hw {struct e1000_adapter *adapter;struct e1000_mac_info {u32 type,rar_entry_count,mta_reg_count;bool get_link_status,autoneg;struct {void(*config_collision_dist)(struct e1000_hw*);s32(*id_led_init)(struct e1000_hw*);s32(*setup_link)(struct e1000_hw*);s32 (*get_link_up_info)(struct e1000_hw*,u16*,u16*);}ops;}mac;struct e1000_phy_info phy;struct{struct e1000_dev_spec_ich8lan ich8lan;}dev_spec;};
struct e1000_adapter {unsigned long state;struct pci *pdev;u32 flags2,max_frame_size;struct e1000_ring *tx_ring;struct e1000_hw hw;};
struct operation {u32 kind,address,value;};
static struct operation ops[32768];static u32 nops,mode,current_speed,prefix,busy,power_busy,hide_smb,flush_kind;static u32 repair_attempts,checksum_calls;static bool power_pending;static u32 mdi_attempts,mdi_failures,mdi_kind;static u64 now,quiet;
static struct pci *current_pci;
static u32 registers[0x6000/4];static u16 phy[65536],emi[65536],words[2048],emi_address;
static s32 e1000_acquire_swflag_ich8lan(struct e1000_hw*);
static void e1000_release_swflag_ich8lan(struct e1000_hw*);
static void record(u32 kind,u32 at,u32 value){if(nops==32768)abort();ops[nops++]=(struct operation){kind,at,value};}
static void udelay(u32 n){now+=n;if((mode>=11&&n!=0)||((mode==5||mode==7)&&n!=0)||mode==4||(n>=10000&&(mode==0||mode==3)))record(2,n,0);}
static void mdelay(u32 n){udelay(n*1000);}
static void msleep(u32 n){mdelay(n);}
static void usleep_range(u32 low,u32 high){(void)high;udelay(low);}
static bool test_and_set_bit(unsigned n,unsigned long *p){bool old=(*p&(1ul<<n))!=0;*p|=1ul<<n;return old;}
static void clear_bit(unsigned n,unsigned long *p){*p&=~(1ul<<n);}
static u32 model_read(u32 at){
 if(now<quiet||at/4>=sizeof(registers)/sizeof(*registers))abort();u32 value=registers[at/4];
 if(mode==5&&at==0x18&&power_pending){if(power_busy)--power_busy;else{value|=4;registers[at/4]=value;power_pending=false;}}
 if(mode==4&&at==8&&busy){--busy;value|=1u<<19;}
 if(mode>=11)record(0,at,value);
 if((mode==8&&at==0x5f04)||(mode==5&&(at==0||at==8||at==0x18||at==0x3c||at==0xe4))||(mode==6&&(at==0x410||at==0x24||at==0x10||at==0xf18||at==0x1000))||mode==7||(mode==4&&at==8)||(mode==1&&at==0x1000)||(mode==2&&(at==8||(at>=0x5400&&at<0x5460))))record(0,at,value);
 return value;
}
static void model_write(u32 at,u32 value){
 if(now<quiet||at/4>=sizeof(registers)/sizeof(*registers))abort();
 if(mode>=11)record(1,at,value);
 if((mode==8&&at==0x5f04)||mode==4||mode==7||(mode==5&&(at==0||at==0x18||at==0x3c||at==0xe4))||(mode==6&&(at==0x410||at==0x24||at==0x10||at==0xf8)))record(1,at,value);
 if(at==0x34){u32 index=(value>>16)&31;if(value&(1u<<21))value=(value&~0xffffu)|emi[index];else emi[index]=(u16)value;}
 if(mode==13&&at==0x20){mdi_attempts++;if(mdi_attempts<=mdi_failures){if(mdi_kind==0)value&=~(1u<<28);else if(mdi_kind==1)value|=(1u<<28)|(1u<<30);else value=(value&~(31u<<16))|(1u<<28)|(7u<<16);}else value|=(1u<<28);}
 if(mode==5&&at==0&&(registers[0]&(1u<<16))&&!(value&(1u<<16))){power_pending=true;registers[0x18/4]&=~4u;if(hide_smb)phy[(769u<<5)|23]|=1;}
 if(mode==7&&at==0x3818&&flush_kind==1)current_pci->descriptor=0;
 if(mode==7&&at==0x100&&(value&2)&&flush_kind==2&&((registers[0x2828/4]&0x3fff)==0x11f))current_pci->descriptor=0;
 if(((mode==0||mode==3)&&at==0xf00&&((registers[at/4]^value)&0x80)))record(1,at,value&~0x20u);
 if((mode==1&&at==0xf8)||(mode==2&&at>=0x5400&&at<0x5460))record(1,at,value);
 if((mode==4||mode==12)&&at==0&&(value&(1u<<26))){registers[0]=value&~((1u<<26)|(1u<<31));registers[0xf00/4]&=~(1u<<5);quiet=now+20000;}else registers[at/4]=value;
}
#define er32(name) ((void)hw,model_read(E1000_##name))
#define ew32(name,value) model_write(E1000_##name,value)
#define e1e_flush() ((void)model_read(8))
static s32 phy_read(struct e1000_hw *hw,u32 at,u16 *value){
 if(!hw->adapter->state||at>=65536)abort();*value=at==17?emi[emi_address]:phy[at];if(mode==5&&at==((769u<<5)|23)&&hide_smb&&!(registers[0x18/4]&(1u<<11))){record(12,at,0);return -2;}
 if(mode==0||mode==3||mode==5||mode==6||mode==11)record(10,at,*value);return 0;
}
static s32 phy_write(struct e1000_hw *hw,u32 at,u16 value){
 if(!hw->adapter->state||at>=65536)abort();if(mode==0||mode==3||mode==5||mode==6||mode==11)record(11,at,value);
 if(at==16)emi_address=value;else if(at==17)emi[emi_address]=value;else {bool switching=mode==5&&at==((769u<<5)|23)&&(phy[at]&1)&&!(value&1);phy[at]=value;if(switching){hide_smb=0;return -2;}}return 0;
}
static s32 phy_read_unlocked(struct e1000_hw *hw,u32 at,u16 *value){s32 r=hw->phy.ops.acquire(hw);if(r)return r;r=phy_read(hw,at,value);hw->phy.ops.release(hw);return r;}
static s32 phy_write_unlocked(struct e1000_hw *hw,u32 at,u16 value){s32 r=hw->phy.ops.acquire(hw);if(r)return r;r=phy_write(hw,at,value);hw->phy.ops.release(hw);return r;}
#define e1e_rphy_locked phy_read
#define e1e_wphy_locked phy_write
#define e1e_rphy phy_read_unlocked
#define e1e_wphy phy_write_unlocked
#define e1000_read_phy_reg_hv_locked phy_read
#define e1000_write_phy_reg_hv_locked phy_write
static void __ew32(struct e1000_hw *hw,unsigned long at,u32 value){(void)hw;model_write((u32)at,value);}
static s32 e1000_write_nvm(struct e1000_hw *hw,u16 at,u16 count,u16 *data){(void)hw;(void)at;(void)count;(void)data;repair_attempts++;return -3;}
static s32 e1000e_update_nvm_checksum(struct e1000_hw *hw){(void)hw;abort();}
static void e1000e_init_rx_addrs(struct e1000_hw *hw,u16 count){(void)hw;(void)count;}
static void e1000e_set_pcie_no_snoop(struct e1000_hw *hw,u32 value){(void)hw;(void)value;}
static void e1000_clear_hw_cntrs_ich8lan(struct e1000_hw *hw){(void)hw;}
static s32 e1000_configure_k1_ich8lan(struct e1000_hw *hw,bool enabled);
static s32 e1000e_read_kmrn_reg_locked(struct e1000_hw*,u32,u16*);
static s32 e1000e_write_kmrn_reg_locked(struct e1000_hw*,u32,u16);
static s32 e1000_phy_hw_reset_ich8lan(struct e1000_hw *hw){(void)hw;abort();}
static s32 no_action(struct e1000_hw *hw){(void)hw;return 0;}
static s32 e1000_read_nvm(struct e1000_hw *hw,u16 at,u16 count,u16 *data){(void)hw;if((u32)at+count>2048)abort();memcpy(data,words+at,count*sizeof(*data));return 0;}
static s32 e1000_hv_phy_workarounds_ich8lan(struct e1000_hw *hw){(void)hw;abort();}
static s32 link_info(struct e1000_hw *hw,u16 *speed,u16 *duplex){(void)hw;*speed=(u16)current_speed;*duplex=2;return 0;}
static int pci_read_config_word(struct pci *pci,u32 at,u16 *value){if(at==0xa8)*value=pci->snoop;else if(at==0xaa)*value=pci->nosnoop;else if(at==0xe4){*value=pci->descriptor;if(mode==7)record(7,at,*value);}else abort();return 0;}
static void reset_model(void){memset(registers,0,sizeof(registers));memset(phy,0,sizeof(phy));memset(emi,0,sizeof(emi));memset(words,0,sizeof(words));emi_address=0;nops=prefix=busy=power_busy=hide_smb=flush_kind=repair_attempts=checksum_calls=mdi_attempts=mdi_failures=mdi_kind=0;power_pending=false;now=quiet=0;registers[0x5b54/4]=0x40;registers[0xf00/4]=(64u<<16)|0x80;}
static s32 cfg_done(struct e1000_hw *hw){(void)hw;prefix=nops;return 0;}
static s32 e1000_phy_hw_reset(struct e1000_hw *hw){(void)hw;prefix=nops;return 0;}
static s32 e1000_k1_gig_workaround_hv(struct e1000_hw*hw,bool link){(void)hw;(void)link;abort();}
static s32 e1000_k1_workaround_lpt_lp(struct e1000_hw*hw,bool link){(void)hw;(void)link;abort();}
static s32 e1000_k1_workaround_lv(struct e1000_hw*hw){(void)hw;abort();}
static s32 e1000_link_stall_workaround_hv(struct e1000_hw*hw){(void)hw;abort();}
static void collision_dist(struct e1000_hw*hw){(void)hw;}
static s32 e1000e_config_fc_after_link_up(struct e1000_hw*hw){(void)hw;return 0;}
static void output(u32 a,u32 b,u32 c,u32 d){u32 header[]={mode,a,b,c,d,nops};if(fwrite(header,sizeof(header),1,stdout)!=1||fwrite(ops,sizeof(*ops),nops,stdout)!=nops)abort();}
'''
main = r'''
int main(void){
 struct pci pci={.device=0x1570,.snoop=0x1003,.nosnoop=0x1003};
 struct e1000_adapter adapter={.pdev=&pci,.max_frame_size=1518};struct e1000_hw *hw_ptr=&adapter.hw;
#define hw (*hw_ptr)
 hw.adapter=&adapter;
 current_pci=&pci;hw.mac.type=e1000_pch_spt;hw.mac.rar_entry_count=12;hw.mac.ops.get_link_up_info=link_info;hw.phy.type=e1000_phy_i217;
 hw.phy.ops.acquire=e1000_acquire_swflag_ich8lan;hw.phy.ops.release=e1000_release_swflag_ich8lan;hw.phy.ops.check_reset_block=e1000_check_reset_block_ich8lan;hw.phy.ops.read_reg_locked=phy_read;hw.phy.ops.write_reg_locked=phy_write;
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

 mode=5;const u32 powers[]={0,2,20},ulp[]={0,0x1234,0xffff};
 for(u32 p=0;p<3;p++)for(u32 hidden=0;hidden<2;hidden++)for(u32 force=0;force<2;force++)for(u32 u=0;u<3;u++){
  reset_model();adapter.state=0;hw.dev_spec.ich8lan.ulp_state=e1000_ulp_state_unknown;power_busy=powers[p];hide_smb=hidden;
  registers[0x18/4]=0x1000;registers[0x3c/4]=0x5abc1234;registers[0xe4/4]=0xaaaa00ff;
  phy[(769u<<5)|23]=0xa500|force;phy[(770u<<5)|17]=0x9332;phy[(779u<<5)|16]=(u16)ulp[u];
  if(e1000_disable_ulp_lpt_lp(&hw,true)||adapter.state||!prefix)abort();nops=prefix;output(powers[p],hidden,force,ulp[u]);
 }
 mode=6;const u32 statuses[]={0,2,3,0x42,0x43,0x83};const u16 gaps[]={0,0x40,0x60,0xfffc};
 hw.mac.autoneg=true;hw.mac.ops.config_collision_dist=collision_dist;
 for(u32 s=0;s<6;s++)for(u32 a=0;a<2;a++)for(u32 g=0;g<4;g++){
  reset_model();adapter.state=0;hw.mac.get_link_status=true;hw.dev_spec.ich8lan.eee_disable=true;
  registers[8/4]=statuses[s];registers[0x410/4]=0x76543210;registers[0x24/4]=0xabcdef00;registers[0x10/4]=0x23456789|(a?0:0x80000000u);registers[0xf18/4]=a?0x80000000u:0;registers[0x1000/4]=26;
  current_speed=(statuses[s]&0x80)?1000:(statuses[s]&0x40)?100:10;pci.snoop=pci.nosnoop=0x1003;
  phy[1]=(statuses[s]&2)?0x24:0;phy[(772u<<5)|28]=0xf812;phy[(770u<<5)|17]=0xa533;phy[(776u<<5)|20]=gaps[g];phy[(772u<<5)|20]=0xffff;emi[0x9401]=0x3c00;
  if(e1000_check_for_copper_link_ich8lan(&hw))abort();output(statuses[s],a,gaps[g],0);
 }
 mode=7;struct e1000_ring ring={.count=32,.dma=0x12345000};adapter.tx_ring=&ring;const u32 tails[]={0,1,31};
 for(u32 scenario=0;scenario<5;scenario++)for(u32 t=0;t<3;t++){
  reset_model();memset(ring.desc,0xcc,sizeof(ring.desc));ring.next_to_use=tails[t];pci.descriptor=scenario?0x100:0;flush_kind=scenario;
  registers[0x5bbc/4]=0x9234;registers[0x3808/4]=scenario==4?0:512;registers[0x400/4]=0x12345670;registers[0x3818/4]=tails[t];registers[0x100/4]=0x76543212;registers[0x2828/4]=0xa5a53fff;registers[8/4]=0x83;
  e1000_flush_desc_rings(&adapter);
  if(scenario>=1&&scenario<=3){const struct e1000_tx_desc *d=&ring.desc[tails[t]];record(21,0,d->buffer_addr==ring.dma);record(21,8,d->lower.data);record(21,12,d->upper.data);record(21,16,ring.next_to_use);}
  output(scenario,tails[t],0,0);
 }

 mode=8;const u32 debug[]={0x12345678,0xabcdef12};hw.mac.mta_reg_count=32;hw.mac.ops.id_led_init=no_action;hw.mac.ops.setup_link=no_action;
 for(u32 i=0;i<2;i++){
  reset_model();adapter.state=0;registers[0x5f04/4]=debug[i];
  if(e1000_init_hw_ich8lan(&hw)||adapter.state)abort();output(debug[i],0,0,0);
 }
 mode=9;
 for(u32 marker=0;marker<2;marker++)for(u32 check=0;check<3;check++){
  reset_model();words[0]=0x1102;words[1]=0x3322;words[2]=0x5544;words[3]=(u16)marker;words[19]=0x8000;words[25]=0x40;
  u16 sum=0;for(u32 i=0;i<63;i++)sum=(u16)(sum+words[i]);words[63]=(u16)(0xbaba-sum);if(check==1)words[63]^=1;if(check==2)words[63]=0xffff;
  s32 result=e1000_validate_nvm_checksum_ich8lan(&hw);u32 kind=repair_attempts?2:result?1:0;output(marker,check,kind,0);
 }
 return 0;
}
'''
if requested in ('mtp','ptp'):
    extra = r'''
 mode=11;const u32 fexts[]={0,0x00c00000,0xa5a5ffff};const u16 kcfgs[]={0,2,0xfffe},timeouts[]={0,0xfc0,0xffff};
 for(u32 f=0;f<3;f++)for(u32 disable=0;disable<2;disable++)for(u32 k=0;k<3;k++)for(u32 t=0;t<3;t++){
  reset_model();adapter.state=1;adapter.flags2=disable?FLAG2_DISABLE_K1:0;
  registers[0x5bc0/4]=fexts[f];registers[0x18/4]=0x1234a5a5;registers[0]=0x98765b21;emi[7]=kcfgs[k];phy[(770u<<5)|21]=timeouts[t];
  if(e1000_reconfigure_k1_params(&hw)||adapter.state!=1)abort();output(fexts[f],disable,kcfgs[k],timeouts[t]);
 }
 mode=12;const u32 extvals[]={0,8,0xabcdefef};
 for(u32 i=0;i<3;i++){
  reset_model();adapter.state=0;registers[0x18/4]=extvals[i];
  if(e1000_reset_hw_ich8lan(&hw)||adapter.state)abort();output(extvals[i],0,0,0);
 }
 mode=13;hw.phy.addr=1;hw.phy.retry_count=2;
 for(u32 write=0;write<2;write++)for(u32 enabled=0;enabled<2;enabled++)for(u32 failed=0;failed<4;failed++)for(u32 kind=0;kind<3;kind++){
  reset_model();adapter.state=1;hw.phy.retry_enabled=enabled;mdi_failures=failed;mdi_kind=kind;u16 value=0x5a5a;
  s32 result=write?e1000e_write_phy_reg_mdic(&hw,21,0x5a5a):e1000e_read_phy_reg_mdic(&hw,21,&value);
  output(write,enabled,failed,(kind<<16)|(result?1:0));
 }
'''
    main = main.replace(' return 0;\n}\n',extra+' return 0;\n}\n')
main = main.replace('hw.mac.type=e1000_pch_spt;', 'hw.mac.type='+selected_mac+';').replace('.device=0x1570', '.device='+hex(selected[0]['device']))
main = main.replace(' return 0;\n}\n', ' mode=10;\n'+''.join('reset_model();output('+str(r['device'])+','+str(('e1000_pch_spt','e1000_pch_cnp','e1000_pch_tgp','e1000_pch_adp','e1000_pch_mtp','e1000_pch_ptp').index(r['mac']))+',0,0);\n' for r in selected)+' return 0;\n}\n')
cpath = out / 'pch_spt.c'
cpath.write_text(prelude + definitions + helpers + main)
binary = out / 'pch_spt'
command = ['clang', '-std=c11', '-O1', '-g', '-fwrapv', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror', str(cpath), '-o', str(binary)]
subprocess.run(command, check=True)
trace = out / 'trace.bin'
with trace.open('wb') as file:
    subprocess.run([str(binary.resolve())], stdout=file, check=True)


def binding(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


manifest = dict(linux_commit='a804c5742bff224d4cb4d25dd383554d598be32b',source_sha256=hashes,
                unchanged_functions=functions,unchanged_function_sha256={name:hashlib.sha256(function(name).encode()).hexdigest() for name in functions},cases={'post_reset':48,'ltr':325,'shared_addresses':8,'eee_disabled':3,'global_reset_prefix':3,'ulp_exit':36,'link':48,'descriptor_flush':15,'dma_clock_policy':2,'nvm_validation':6,'pci_inventory':len(selected),**({'k1_configuration':54,'mdic_retry':48,'reset_dpg':3} if requested in ('mtp','ptp') else {})},command=command,
                family=requested,pci_inventory=inventory,selected_inventory=selected,artifacts=[binding(p) for p in (cpath,binary,trace,out/'inventory.json')],
                limits=['Clock comparison isolates FFLT_DBG from the unchanged full init_hw helper; unrelated callback boundaries are explicit no-effect model adapters',
                        'NVM outcome comparison uses unchanged family+generic validators; source repair attempts return a read-only adapter error and native refuses RepairRequired without issuing a write',
                        'Logical PHY and immutable NVM are model boundaries; prior MDIC/HV/flash oracles required',
                        'Exact source-table SPT/CNP/TGP/ADP cohorts; no MTP+ or physical proof',
                        'Post/EEE normalize logical PHY effects; RAR normalizes owned address accesses and flushes; LTR compares PBA reads and LTRV writes',
                        'ULP trace ends before forced hardware PHY reset callback; all preceding actual MAC effects, logical PHY reads/writes and delays compare; native readiness/post-reset composition is separately modeled',
                        'Link compares actual ordered logical PHY and affected MAC registers; cached STATUS/ICR observations, source collision/flow-control callbacks and native idempotent advertisement reassertion are explicit normalization boundaries',
                        'Owned descriptor-flush compares all MAC/config accesses and delays plus dummy descriptor bytes; native final RX status recheck is extra safety qualification',
                        'Reset trace ends at get_cfg_done; actual stores, STATUS reads and delays compare; extra Stela qualification/reset-clear reads are separately fault-tested',
                        'Only actual LTR config is immutable and captured before Stela initialization; E4 descriptor status stays live. Donor LTR reads occur during link policy',
                        'Clang -fwrapv defines donor promoted bool left shift into bit31 without changing donor bytes; ASan and remaining UBSan checks stay enabled',
                        'LTR cases keep donor u32 wrap boundaries observationally inactive; separate native u64 tests cover legal limits above u32 range'])
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(binding(trace)))
