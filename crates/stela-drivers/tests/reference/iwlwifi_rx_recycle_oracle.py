#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2003-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Run unchanged source RX restock/descriptor/producer functions.
Usage: iwlwifi_rx_recycle_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
The wrapper supplies an enabled coherent MQ/shadow-register source profile and
FIFO completion/free-list events; no real device DMA or IRQ work executes.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'pcie/gen1_2/rx.c':'e257d2cebc47481fcb2c59e40ef442a1b920c91788212c4c4e953cd1447a94a7',
 'pcie/gen1_2/internal.h':'572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
 'iwl-fh.h':'646b7150a6d88d07cbbac5a127e796ea61ec9b8132dcd9b3e6e6be5211293a1a',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def body(text,name,struct=False):
 pattern=(r'^struct '+name+r'\s*\{')if struct else (r'^static void '+name+r'\([^;{}]*?\)\n\{')
 match=re.search(pattern,text,re.M);assert match,name
 at,depth=match.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 if struct:at=text.index(';',at)+1
 return text[match.start():at]
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef u16 __le16;typedef u64 __le64;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) (x)
#define cpu_to_le64(x) (x)
#define BUILD_BUG_ON(x) _Static_assert(!(x),"layout")
#define WARN_ON(x) assert(!(x))
#define IWL_DEBUG_RX(...) ((void)0)
#define IWL_DEBUG_INFO(...) ((void)0)
#define lockdep_assert_held(...) ((void)0)
#define spin_lock_bh(...) ((void)0)
#define spin_unlock_bh(...) ((void)0)
#define STATUS_DEVICE_ENABLED 0
#define STATUS_TPOWER_PMI 1
#define CSR_UCODE_DRV_GP1 0x54
#define CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP 1
#define CSR_GP_CNTRL 0x24
#define CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ 8
#define FH_RSCSR_CHNL0_WPTR 0x20 /* unexecuted legacy SQ branch */
#define HBUS_TARG_WRPTR 0x460
#define HBUS_TARG_WRPTR_RX_Q(n) ((n)<<16) /* unexecuted BZ+ branch */
#define IWL_DEVICE_FAMILY_AX210 1
#define IWL_DEVICE_FAMILY_BZ 2
#define round_down(x,n) ((x)&~((n)-1))
struct list_head{struct list_head *next,*prev;};
static void head(struct list_head *h){h->next=h->prev=h;}
static void add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
#define list_first_entry(h,t,m) ((t*)((char*)((h)->next)-offsetof(t,m)))
struct iwl_rx_mem_buffer{struct list_head list;u64 page_dma;u16 vid;bool invalid;};
struct iwl_rxq{unsigned write,write_actual,queue_size,free_count,id;struct list_head rx_free;void *bd;bool need_update;int lock;};
struct base_cfg{bool shadow_reg_enable;};
struct mac_cfg{struct base_cfg *base;bool mq_rx_supported;unsigned device_family;};
struct iwl_trans_pcie{u64 supported_dma_mask;};
struct iwl_trans{struct mac_cfg *mac_cfg;unsigned long status;struct iwl_trans_pcie pcie;u32 reg,value;};
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
static bool test_bit(unsigned n,unsigned long *status){return (*status>>n)&1;}
static u32 iwl_read32(struct iwl_trans *t,u32 reg){(void)t;(void)reg;return 0;}
static void iwl_set_bit(struct iwl_trans *t,u32 reg,u32 bit){(void)t;(void)reg;(void)bit;assert(0);}
static void iwl_write32(struct iwl_trans *t,u32 reg,u32 value){t->reg=reg;t->value=value;assert(reg==0x1c80);}
'''
prelude+=re.search(r'^#define RFH_Q0_FRBDCB_WIDX_TRG[^\n]+',texts['iwl-fh.h'],re.M).group()+'\n'
prelude+=re.search(r'^#define RFH_Q_FRBDCB_WIDX_TRG\(q\)[^\n]+',texts['iwl-fh.h'],re.M).group()+'\n'
prelude+=body(texts['pcie/gen1_2/internal.h'],'iwl_rx_transfer_desc',True)+'\n'
prelude+='\n'.join(body(texts['pcie/gen1_2/rx.c'],n)for n in ['iwl_pcie_rxq_inc_wr_ptr','iwl_pcie_restock_bd','iwl_pcie_rxmq_restock'])
main=r'''
int main(void){
 for(unsigned family=0;family<2;family++){
  struct base_cfg base={.shadow_reg_enable=true};struct mac_cfg mac={.base=&base,.mq_rx_supported=true,.device_family=family};
  struct iwl_trans t={.mac_cfg=&mac,.status=1,.pcie={.supported_dma_mask=family?0x7ff:0xfff}};
  union{u64 old[32];struct iwl_rx_transfer_desc modern[32];}ring={0};
  struct iwl_rxq q={.queue_size=32,.bd=&ring};head(&q.rx_free);
  struct iwl_rx_mem_buffer buffers[31]={0};
  for(unsigned n=0;n<31;n++){buffers[n].page_dma=(n+1)*4096;buffers[n].vid=n+1;add_tail(&buffers[n].list,&q.rx_free);q.free_count++;}
  iwl_pcie_rxmq_restock(&t,&q);printf("initial %u %u %u\n",family,q.write,q.write_actual);assert(t.value==24);
  for(unsigned cycle=0;cycle<=520;cycle++){
   unsigned slot=cycle&31,vid=family?ring.modern[slot].rbid:ring.old[slot]&0xfff;
   assert(vid&&vid<=31);struct iwl_rx_mem_buffer *rxb=&buffers[vid-1];
   add_tail(&rxb->list,&q.rx_free);q.free_count++;
   iwl_pcie_rxmq_restock(&t,&q);assert(q.free_count==0&&t.value==q.write_actual);
   printf("recycle %u %u %u %u %u %u\n",family,cycle,slot,vid,q.write,q.write_actual);
  }
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-rx-recycle.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-rx-recycle'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
