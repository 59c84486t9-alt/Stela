#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2003-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged Intel sentinel allocator, TB reclamation and queue index helpers.
Usage: iwlwifi_hcmd_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
No complete HCMD enqueue, real DMA or firmware completion is executed.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'pcie/gen1_2/trans.c':'8ed5c442313a5c2858f3e42b84d68bec726c7f4061e6f34db13c5ce0137a59ee',
 'fw/api/debug.h':'82ddff404b4a53830ca1cf4cb6ce10de54a403fd4abb1d8fb0d1a16b92e3a8c1',
 'iwl-trans.c':'8f9e38c3553069830d6995a358063bb6cb0e9da7136f8fe9c8d3fbf64e4f077d',
 'fw/api/cmdhdr.h':'702ed4cc19d4f29ca035f1af395298743c52d7b364fc5ec842dc5952ef4ef848',
 'iwl-fh.h':'646b7150a6d88d07cbbac5a127e796ea61ec9b8132dcd9b3e6e6be5211293a1a',
 'pcie/gen1_2/internal.h':'572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
 'pcie/gen1_2/tx-gen2.c':'ae940c3298e8024d98842833189077f0f7d079367679865d94618422933ba759',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()

def body(text, name, struct=False):
    if struct:
        pattern = r'^struct ' + name + r'\s*\{'
    else:
        pattern = r'^(?:static[^;{}]*?|(?:int|void)\s+)[^;{}]*?\b' + name + r'\([^;{}]*?\)\n\{'
    match = re.search(pattern, text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    if struct:
        at = text.index(';', at) + 1
    return text[match.start():at]

prelude=r"""
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#ifndef ERFKILL
#define ERFKILL 132 /* unused Linux error branch in these normalization cases */
#endif
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef u16 __le16;typedef u32 __le32;typedef u64 __le64;typedef u64 dma_addr_t;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) ((u16)(x))
#define le16_to_cpu(x) ((u16)(x))
#define upper_32_bits(x) ((u32)((u64)(x)>>32))
#define put_unaligned_le64(x,p) do{u64 v=(x);memcpy((p),&v,8);}while(0)
#define IWL_TFH_NUM_TBS 25
#define CMD_SEND_IN_RFKILL 4
#define CMD_ASYNC 1
#define CMD_WANT_SKB 2
#define STATUS_RFKILL_OPMODE 0
#define STATUS_FW_ERROR 1
#define IWL_TRANS_FW_ALIVE 1
#define REPLY_ERROR 2
#define DEF_ID(opcode) ((1<<8)|(opcode))
#define WARN(x,...) (!!(x))
#define WARN_ON(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define unlikely(x) (x)
#define IWL_ERR(...) ((void)0)
#define lock_map_acquire_read(...) ((void)0)
#define lock_map_release(...) ((void)0)
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
struct iwl_dma_ptr{void *addr;u64 dma;size_t size;};
struct iwl_trans_pcie{struct{struct{unsigned max_tbs;}tfd;}txqs;struct iwl_dma_ptr invalid_tx_cmd;};
struct base_cfg{unsigned max_tfd_queue_size;};struct mac_cfg{struct base_cfg *base;};
#define INVALID_WR_PTR_CMD 6
#define DEBUG_GROUP 15
#define IWL_FIRST_TB_SIZE_ALIGN 64
#define BIT(n) (1U<<(n))
#define DMA_TO_DEVICE 1
#define le64_to_cpu(x) (x)
static unsigned unmaps;
static void dma_unmap_single(void *dev,u64 addr,u16 size,int dir){(void)dev;assert(addr&&size&&dir==DMA_TO_DEVICE);unmaps++;}
#define dma_unmap_page dma_unmap_single
struct iwl_cmd_meta{unsigned sg_offset,tbs;};
struct iwl_txq{unsigned n_window;u64 first_tb_dma;};
struct iwl_pcie_first_tb_buf{u8 buf[IWL_FIRST_TB_SIZE_ALIGN];};
struct iwl_trans{struct mac_cfg *mac_cfg;void *dev;struct{bool wide_cmd_header;}conf;int state;unsigned long status,sync_cmd_lockdep_map;struct iwl_trans_pcie pcie;};
struct iwl_host_cmd{u32 id,flags;void *resp_pkt;};
static bool test_bit(int bit,unsigned long *status){return (*status>>bit)&1;}
static int iwl_pcie_alloc_dma_ptr(struct iwl_trans *t,struct iwl_dma_ptr *p,size_t n){(void)t;p->addr=calloc(1,n);p->dma=0x1234000;p->size=n;return p->addr?0:-ENOMEM;}
static int iwl_trans_pcie_send_hcmd(struct iwl_trans *t,struct iwl_host_cmd *cmd){(void)t;(void)cmd;return 0;}
"""
for n in ['iwl_cmd_header','iwl_cmd_header_wide']:prelude+=body(texts['fw/api/cmdhdr.h'],n,True)+'\n'
for n in ['iwl_tfh_tb','iwl_tfh_tfd']:prelude+=body(texts['iwl-fh.h'],n,True)+'\n'
functions='\n'.join([
 *(body(texts['fw/api/cmdhdr.h'],n)for n in ['iwl_cmd_opcode','iwl_cmd_groupid','iwl_cmd_version','iwl_cmd_id']),
 body(texts['iwl-trans.c'],'iwl_trans_send_cmd'),
 body(texts['pcie/gen1_2/internal.h'],'iwl_txq_crosses_4g_boundary'),
 *(body(texts['pcie/gen1_2/tx-gen2.c'],n)for n in ['iwl_txq_gen2_get_num_tbs','iwl_txq_gen2_set_tb']),
 *(body(texts['pcie/gen1_2/internal.h'],n)for n in ['iwl_txq_get_first_tb_dma','iwl_txq_get_cmd_index','iwl_txq_inc_wrap','iwl_txq_set_tfd_invalid_gen2']),
 body(texts['pcie/gen1_2/trans.c'],'iwl_pcie_alloc_invalid_tx_cmd'),
 body(texts['pcie/gen1_2/tx-gen2.c'],'iwl_txq_gen2_tfd_unmap')])
main=r"""
static void hex(void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((u8*)p)[i]);puts("");}
int main(void){
 struct base_cfg base={.max_tfd_queue_size=256};struct mac_cfg mac={.base=&base};
 struct iwl_trans t={.mac_cfg=&mac,.pcie={.txqs={.tfd={.max_tbs=25}}}};
 if(iwl_pcie_alloc_invalid_tx_cmd(&t))return 2;
 printf("invalid ");hex(t.pcie.invalid_tx_cmd.addr,t.pcie.invalid_tx_cmd.size);
 struct iwl_tfh_tfd invalid={0};iwl_txq_set_tfd_invalid_gen2(&t,&invalid);
 printf("sentinel ");hex(&invalid,sizeof(invalid));
 unsigned points[]={0,31,32,127,128,255,256,65534,65535};
 for(unsigned family=0;family<2;family++){
  base.max_tfd_queue_size=family?65536:256;
  struct iwl_txq q={.n_window=family?128:32,.first_tb_dma=0x3456000};
  for(unsigned i=0;i<sizeof(points)/sizeof(points[0]);i++){
   unsigned index=points[i],slot=iwl_txq_get_cmd_index(&q,index);
   printf("index %u %u %u %d %llu\n",family,index,slot,iwl_txq_inc_wrap(&t,index),(unsigned long long)iwl_txq_get_first_tb_dma(&q,slot));
  }
 }
 for(unsigned count=1;count<=25;count++){
  struct iwl_tfh_tfd f={0};struct iwl_cmd_meta meta={0};
  for(unsigned i=0;i<count;i++)iwl_txq_gen2_set_tb(&t,&f,0x100000+(i+1)*0x10000,20+i);
  unmaps=0;iwl_txq_gen2_tfd_unmap(&t,&meta,&f);
  printf("reclaim %u %u ",count,unmaps);hex(&f,12);
 }
 free(t.pcie.invalid_tx_cmd.addr);
 return 0;
}
"""
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-hcmd.c';unit.write_text(prelude+functions+main);exe=out/'linux-iwlwifi-hcmd'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
