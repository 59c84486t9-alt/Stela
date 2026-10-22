#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2003-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged host command normalization/TFH-TB helpers and exact header layouts.
Usage: iwlwifi_command_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
No complete HCMD enqueue, firmware execution, DMA or completion is modeled.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
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
struct iwl_trans_pcie{struct{struct{unsigned max_tbs;}tfd;}txqs;};
struct iwl_trans{void *dev;struct{bool wide_cmd_header;}conf;int state;unsigned long status,sync_cmd_lockdep_map;struct iwl_trans_pcie pcie;};
struct iwl_host_cmd{u32 id,flags;void *resp_pkt;};
static bool test_bit(int bit,unsigned long *status){return (*status>>bit)&1;}
static int iwl_trans_pcie_send_hcmd(struct iwl_trans *t,struct iwl_host_cmd *cmd){(void)t;(void)cmd;return 0;}
"""
for n in ['iwl_cmd_header','iwl_cmd_header_wide']:prelude+=body(texts['fw/api/cmdhdr.h'],n,True)+'\n'
for n in ['iwl_tfh_tb','iwl_tfh_tfd']:prelude+=body(texts['iwl-fh.h'],n,True)+'\n'
functions='\n'.join([
 *(body(texts['fw/api/cmdhdr.h'],n)for n in ['iwl_cmd_opcode','iwl_cmd_groupid','iwl_cmd_version','iwl_cmd_id']),
 body(texts['iwl-trans.c'],'iwl_trans_send_cmd'),
 body(texts['pcie/gen1_2/internal.h'],'iwl_txq_crosses_4g_boundary'),
 *(body(texts['pcie/gen1_2/tx-gen2.c'],n)for n in ['iwl_txq_gen2_get_num_tbs','iwl_txq_gen2_set_tb'])])
main=r"""
static void hex(void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((u8*)p)[i]);puts("");}
int main(void){
 struct iwl_trans t={.conf={.wide_cmd_header=true},.state=1,.pcie={.txqs={.tfd={.max_tbs=25}}}};
 printf("layout %zu %zu %zu %zu %zu\n",sizeof(struct iwl_cmd_header_wide),offsetof(struct iwl_cmd_header_wide,length),offsetof(struct iwl_cmd_header_wide,version),sizeof(struct iwl_tfh_tb),sizeof(struct iwl_tfh_tfd));
 unsigned versions[]={0,1,99},groups[]={0,1,5,12};
 for(unsigned g=0;g<4;g++)for(unsigned v=0;v<3;v++)for(unsigned op=0;op<256;op++){
  struct iwl_host_cmd cmd={.id=iwl_cmd_id(op,groups[g],versions[v])};if(iwl_trans_send_cmd(&t,&cmd))return 2;
  // This wrapper populates the unchanged ABI struct; full enqueue is not run.
  struct iwl_cmd_header_wide hdr={.cmd=iwl_cmd_opcode(cmd.id),.group_id=iwl_cmd_groupid(cmd.id),.sequence=0x1fcd,.length=0x1234,.version=iwl_cmd_version(cmd.id)};
  printf("header %u %u %u ",groups[g],versions[v],op);hex(&hdr,sizeof(hdr));
 }
 for(unsigned count=1;count<=25;count++){
  struct iwl_tfh_tfd tfd={0};
  for(unsigned i=0;i<count;i++){u64 address=0x123400000000ULL+i*0x10000+3;u16 len=1+i*197;if(iwl_txq_gen2_set_tb(&t,&tfd,address,len)!=(int)i)return 3;}
  printf("tfd %u ",count);hex(&tfd,sizeof(tfd));
  if(count==25&&iwl_txq_gen2_set_tb(&t,&tfd,0,1)!=-EINVAL)return 4;
 }
 return 0;
}
"""
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-command.c';unit.write_text(prelude+functions+main);exe=out/'linux-iwlwifi-command'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
