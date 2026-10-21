#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2021-2026 Intel Corporation
"""Unchanged Linux inline MEM_DESC and reduced-power selectors on bounded fixtures.
Usage: iwlwifi_uefi_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
No GetVariable, EFI ownership, vendor authentication, DMA or hardware is modeled.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:])
expected={'fw/uefi.c':'7e57fe0ff11291e6f3c77aedd2f5ca539e825b279497f7a7e89f796d8f829738','fw/uefi.h':'68ec89d9660c9a7de8acde98af29abcabf00a8ed4cc8057def5e6fbcb452a1e0'}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def function(name):
 text=texts['fw/uefi.c'];match=re.search(r'^(?:static )?int '+name+r'\([^;{}]*?\)\n\{',text,re.M);assert match,name
 at,depth=match.end(),1
 while depth:
  depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[match.start():at]
prelude=r'''// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2020-2026 Intel Corporation
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint32_t __le32;typedef uint16_t __le16;
#define __packed __attribute__((packed))
#define BIT(n) (1u<<(n))
#define IWL_PNVM_REDUCED_CAP_BIT BIT(25)
#define IWL_CFG_RF_TYPE_FM 0x112
#define IWL_UCODE_TLV_MEM_DESC 7
#define IWL_UCODE_TLV_SEC_RT 19
#define IWL_UCODE_TLV_HW_TYPE 58
#define IWL_UCODE_TLV_PNVM_VERSION 62
#define IWL_UCODE_TLV_PNVM_SKU 64
#define IPC_DRAM_MAP_ENTRY_NUM_MAX 64
#define IWL_DEBUG_FW(...) ((void)0)
#define IWL_ERR(...) ((void)0)
#define le32_to_cpu(x) ((u32)(x))
#define cpu_to_le32(x) ((u32)(x))
#define le32_to_cpup(x) (*(x))
#define le16_to_cpup(x) (*(x))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
struct iwl_ucode_tlv {__le32 type,length;u8 data[];} __packed;
struct iwl_sku_id {__le32 data[3];} __packed;
struct iwl_pnvm_section {__le32 offset;const u8 data[];} __packed;
struct iwl_pnvm_image {struct {const void *data;u32 len;}chunks[64];u32 n_chunks,version;};
struct iwl_trans {struct {u32 hw_rev,hw_rf_id;}info;bool reduced_cap_sku;};
'''
desc=re.search(r'struct iwl_uefi_pnvm_mem_desc \{.*?\} __packed;',texts['fw/uefi.c'],re.S);assert desc
prelude+=desc.group(0)+'\n'
main=r'''
static uint64_t fnv(const void *ptr,size_t n){const u8 *p=ptr;uint64_t h=0xcbf29ce484222325ULL;for(size_t i=0;i<n;i++){h^=p[i];h*=0x100000001b3ULL;}return h;}
static u8 bytes[8192];static size_t used;
static void tlv(u32 type,const void *p,u32 n){memcpy(bytes+used,&type,4);memcpy(bytes+used+4,&n,4);memcpy(bytes+used+8,p,n);u32 aligned=ALIGN(n,4);memset(bytes+used+8+n,0xee,aligned-n);used+=8+aligned;}
int main(void){
 struct iwl_trans t={0};
 for(u32 sku=1;sku<=2;sku++){
  u32 id[3]={sku,0,0};tlv(64,id,12);u8 sec[]={0,0,0,0,0xaa};tlv(19,sec,5);
  for(unsigned j=0;j<2;j++){u8 desc[]={0,0,0,0,3,0,0,0,0,0xaa,0xbb};u32 addr=j?0x12345678:0xfffffff0;memcpy(desc,&addr,4);desc[8]=sku;tlv(7,desc,11);}
 }
 for(u32 sku=0;sku<=2;sku++){
  u32 id[3]={sku,0,0};struct iwl_pnvm_image p={0};int rc=iwl_uefi_reduce_power_parse(&t,bytes,used,&p,id);
  printf("case %u %s %u\n",sku,rc==0?"ok":rc==-ENOENT?"missing":"unexpected",p.n_chunks);
  if(!rc)for(unsigned j=0;j<p.n_chunks;j++){u32 address;memcpy(&address,(const u8*)p.chunks[j].data-8,4);printf("chunk %x %u %016llx\n",address,p.chunks[j].len,(unsigned long long)fnv(p.chunks[j].data,p.chunks[j].len));}
 }
 for(unsigned n=0;n<=64;n++){
  struct iwl_pnvm_image p={.n_chunks=n};u8 d[]={0,0,0,0,1,0,0,0,0xaa};int rc=iwl_uefi_handle_tlv_mem_desc(&t,d,9,&p);
  printf("limit %u %s %u\n",n,rc==0?"ok":rc==-EINVAL?"invalid":"unexpected",p.n_chunks);
 }
 return 0;
}
'''

out.mkdir(parents=True,exist_ok=True)
unit=out/'linux-iwlwifi-uefi.c'
unit.write_text(prelude+function('iwl_uefi_handle_tlv_mem_desc')+function('iwl_uefi_reduce_power_section')+function('iwl_uefi_reduce_power_parse')+main)
exe=out/'linux-iwlwifi-uefi'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
