#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2007-2015, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Execute unchanged pinned Intel ownership/reset/APM/clock helpers.

Usage: iwlwifi_power_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
The CSR/periphery, sleep, PCI capability and MEI models are synchronous fixtures.
Compare actual control writes and minimum legal delays, excluding read-address
selection writes and diagnostic monitor output. No hardware/PCI/IRQ proof.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source,out=map(Path,sys.argv[1:])
expected={
 'pcie/gen1_2/trans.c':'8ed5c442313a5c2858f3e42b84d68bec726c7f4061e6f34db13c5ce0137a59ee',
 'iwl-io.c':'22109ecf57f16fb8299a8e55e0170b9ede9be19e0a392ce54c776796fff30738',
 'iwl-csr.h':'', 'iwl-prph.h':'2f42247b527b9a2176b1486f23768443a5cba30406ba879c1ff3f78b4d75387a'}
# CSR hash below is filled from the already pinned source manifest by the
# checked-in constant, never from an untrusted runtime manifest.
expected['iwl-csr.h']='9bc1643e0fa9725450e88f1235172b9d4326bb77a9df3c5b6fb1d56c15d134e7'
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()


def function(text,name):
 match=re.search(r'^(?:static[^;{}]*?|(?:int|void)\s+)[^;{}]*?\b'+name+r'\([^;{}]*?\)\n\{',text,re.M)
 assert match,name
 at,depth=match.end(),1
 while depth:
  depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[match.start():at]


def define(name):
 for text in [texts['iwl-csr.h'],texts['iwl-prph.h']]:
  match=re.search(r'^#define\s+'+name+r'\s+[^\n]+',text,re.M)
  if match:return match.group(0)
 raise AssertionError(name)


names=['PRPH_BASE','CSR_BASE','CSR_HW_IF_CONFIG_REG','CSR_MBOX_SET_REG','CSR_MBOX_SET_REG_OS_ALIVE','CSR_HW_IF_CONFIG_REG_PCI_OWN_SET','CSR_DBG_LINK_PWR_MGMT_REG','CSR_RESET_LINK_PWR_MGMT_DISABLED','CSR_HW_IF_CONFIG_REG_WAKE_ME','CSR_RESET','CSR_GP_CNTRL','CSR_GP_CNTRL_REG_FLAG_SW_RESET','CSR_RESET_REG_FLAG_SW_RESET','CSR_GIO_REG','CSR_GIO_REG_VAL_L0S_DISABLED','CSR_GIO_CHICKEN_BITS','CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER','CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX','CSR_DBG_HPET_MEM_REG','CSR_DBG_HPET_MEM_REG_VAL','CSR_HW_IF_CONFIG_REG_HAP_WAKE','CSR_ANA_PLL_CFG','CSR50_ANA_PLL_CFG_VAL','CSR_GP_CNTRL_REG_FLAG_INIT_DONE','CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY','CSR_GP_CNTRL_REG_FLAG_BZ_MAC_ACCESS_REQ','CSR_GP_CNTRL_REG_FLAG_MAC_INIT','CSR_GP_CNTRL_REG_FLAG_MAC_STATUS','PREG_PRPH_WPROT_9000','PREG_PRPH_WPROT_22000','HPM_DEBUG','PERSISTENCE_BIT','PREG_WFPM_ACCESS','OSC_CLK','OSC_CLK_FORCE_CONTROL','APMG_BASE','APMG_CLK_EN_REG','APMG_CLK_VAL_DMA_CLK_RQT','APMG_PCIDEV_STT_REG','APMG_PCIDEV_STT_VAL_L1_ACT_DIS','APMG_RTC_INT_STT_REG','APMG_RTC_INT_STT_RFKILL']
prelude=r'''// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Intel copyrights retained by the generating script.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1u<<(n))
#define IWL_DEVICE_FAMILY_8000 8
#define IWL_DEVICE_FAMILY_9000 9
#define IWL_DEVICE_FAMILY_22000 22
#define IWL_DEVICE_FAMILY_AX210 23
#define IWL_DEVICE_FAMILY_BZ 24
#define IWL_DEBUG_INFO(...) ((void)0)
#define IWL_DEBUG_POWER(...) ((void)0)
#define IWL_ERR(...) ((void)0)
#define IWL_EXPORT_SYMBOL(x)
#define IWL_POLL_INTERVAL 10
#define HW_READY_TIMEOUT 50
#define STATUS_DEVICE_ENABLED 1
#define PCI_EXP_LNKCTL 0x10
#define PCI_EXP_LNKCTL_ASPM_L0S 1
#define PCI_EXP_LNKCTL_ASPM_L1 2
#define PCI_EXP_DEVCTL2 0x28
#define PCI_EXP_DEVCTL2_LTR_EN 0x400
struct base {int pll_cfg,apmg_not_supported;};
struct iwl_mac_cfg {int device_family,bisr_workaround;struct base *base;};
struct cfg {int host_interrupt_operation_mode;};
struct iwl_trans_pcie {int pm_support,ltr_enabled;void *pci_dev;};
struct iwl_trans {struct iwl_mac_cfg *mac_cfg;struct cfg *cfg;struct iwl_trans_pcie pcie;bool csme_own;unsigned long status;};
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
static u32 csr[1024],hpm,wprot;static unsigned attempts,grant_after;static bool clock_ready,mei_connected;
static u32 iwl_read32(struct iwl_trans *t,u32 reg){(void)t;if(reg==0x88)return 0;return csr[reg/4];}
static void effect(u32 reg,u32 value){if(reg!=0x448)printf("w %x %x\n",reg,value);}
static void iwl_write32(struct iwl_trans *t,u32 reg,u32 value){
 (void)t;effect(reg,value);
 if(reg==0&&(value&0x400000)){attempts++;if(attempts<grant_after)value&=~0x400000u;}
 if(reg==0x20&&(value&0x80)){csr[0]&=~0x400000u;csr[0x24/4]&=~5u;}
 if(reg==0x24&&(value&4)&&clock_ready)value|=1;
 csr[reg/4]=value;
}
static void iwl_set_bit(struct iwl_trans *t,u32 reg,u32 mask){iwl_write32(t,reg,iwl_read32(t,reg)|mask);}
static void delay(unsigned us){printf("d %u\n",us);}
#define udelay(x) delay(x)
#define usleep_range(a,b) delay(a)
#define msleep(x) delay((x)*1000)
#define mdelay(x) delay((x)*1000)
static bool iwl_mei_is_connected(void){return mei_connected;}
static void pcie_capability_read_word(void *dev,unsigned reg,u16 *value){(void)dev;(void)reg;*value=0;}
static void set_bit(unsigned b,unsigned long *v){*v|=1ul<<b;}
static bool iwl_trans_is_hw_error_value(u32 v){return((v&~0xfu)==0xa5a5a5a0)||((v&~0xfu)==0x5a5a5a50);}
static u32 iwl_read_umac_prph_no_grab(struct iwl_trans *t,u32 addr){(void)t;return addr==0xa03440?hpm:wprot;}
static void iwl_write_umac_prph_no_grab(struct iwl_trans *t,u32 addr,u32 val){(void)t;effect(0x444,(addr&0xfffff)|(3<<24));effect(0x44c,val);hpm=val;}
static u32 iwl_read_prph(struct iwl_trans *t,u32 reg){(void)t;(void)reg;abort();}
static void iwl_write_prph(struct iwl_trans *t,u32 reg,u32 val){(void)t;(void)reg;(void)val;abort();}
static void iwl_set_bits_prph(struct iwl_trans *t,u32 reg,u32 val){(void)t;(void)reg;(void)val;abort();}
static void iwl_pcie_dump_host_monitor(struct iwl_trans *t){(void)t;}
int iwl_pcie_gen1_2_activate_nic(struct iwl_trans *t);
static int iwl_trans_activate_nic(struct iwl_trans *t){return iwl_pcie_gen1_2_activate_nic(t);}
'''
functions=function(texts['iwl-io.c'],'iwl_poll_bits_mask')+r'''
static int iwl_poll_bits(struct iwl_trans *t,u32 reg,u32 mask,int timeout){return iwl_poll_bits_mask(t,reg,mask,mask,timeout);}
'''
for name in ['iwl_pcie_set_hw_ready','iwl_pcie_prepare_card_hw','iwl_trans_pcie_sw_reset','iwl_trans_pcie_clear_persistence_bit','iwl_pcie_gen1_2_activate_nic','iwl_pcie_apm_config','iwl_pcie_apm_init']:
 functions+=function(texts['pcie/gen1_2/trans.c'],name)+'\n'
main=r'''
int main(void){
 for(unsigned scenario=0;scenario<12;scenario++){
  unsigned family=scenario>=6?23:22;unsigned kind=scenario%6;
  memset(csr,0,sizeof(csr));csr[0]=0x1000;csr[0x100/4]=0x400;csr[0x240/4]=0x1234;csr[0x3c/4]=0x100;csr[0x24/4]=kind==5?0:0x08000000;
  hpm=(kind==0?0x01230000:0x01231000);wprot=kind==2?0x1000:0;attempts=0;grant_after=kind==3?3:1;clock_ready=kind!=4;mei_connected=false;
  struct base base={.apmg_not_supported=1};struct iwl_mac_cfg mac={.device_family=family,.bisr_workaround=family==22,.base=&base};struct cfg cfg={0};struct iwl_trans trans={.mac_cfg=&mac,.cfg=&cfg};
  printf("case %u\n",scenario);effect(12,0);effect(8,0xffffffff);effect(16,0xffffffff);
  int rc=iwl_pcie_prepare_card_hw(&trans);if(!rc)rc=iwl_trans_pcie_clear_persistence_bit(&trans);if(!rc)rc=iwl_trans_pcie_sw_reset(&trans,true);if(!rc)rc=iwl_pcie_apm_init(&trans);
  printf("result %s\n",rc==0?"ok":rc==-ETIMEDOUT?"timeout":rc==-EPERM?"protected":"unexpected");
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-power.c';unit.write_text(prelude+'\n'.join(define(n) for n in names)+'\n'+functions+main)
exe=out/'linux-iwlwifi-power';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
