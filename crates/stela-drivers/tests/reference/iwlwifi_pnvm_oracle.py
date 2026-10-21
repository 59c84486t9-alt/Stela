#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2020-2026 Intel Corporation
"""Run unchanged PNVM SKU/hardware selection against the pinned actual asset.

Usage: iwlwifi_pnvm_oracle.py SOURCE_DIRECTORY PNVM_IMAGE OUTPUT_DIRECTORY
Only valid real-asset selection executes in C. Malformed-input refusal is tested
in Rust, avoiding the donor's unchecked SEC_RT subtraction. No hardware proof.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,image,out=map(Path,sys.argv[1:])
expected={'fw/pnvm.c':'11c59247652d4528e86e0c52d99d6344bfcd32a43deeb536ed0d2cc797d1b983','iwl-csr.h':'9bc1643e0fa9725450e88f1235172b9d4326bb77a9df3c5b6fb1d56c15d134e7'}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
assert hashlib.sha256(image.read_bytes()).hexdigest()=='9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0'


def function(name):
 text=texts['fw/pnvm.c'];match=re.search(r'^static int '+name+r'\([^;{}]*?\)\n\{',text,re.M);assert match,name
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
static int iwl_uefi_handle_tlv_mem_desc(struct iwl_trans *t,const void *d,size_t n,struct iwl_pnvm_image *p){(void)t;(void)d;(void)n;(void)p;abort();}
'''
for macro in ['CSR_HW_REV_TYPE','CSR_HW_RFID_TYPE']:
 match=re.search(r'^#define\s+'+macro+r'\([^\n]+',texts['iwl-csr.h'],re.M);assert match;prelude+=match.group(0)+'\n'
main=r'''
static uint64_t fnv(const void *ptr,size_t n){const u8 *p=ptr;uint64_t h=0xcbf29ce484222325ULL;for(size_t i=0;i<n;i++){h^=p[i];h*=0x100000001b3ULL;}return h;}
int main(int argc,char **argv){
 if(argc!=2)return 2;FILE *f=fopen(argv[1],"rb");if(!f)return 3;fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);u8 *bytes=malloc(n);if(fread(bytes,1,n,f)!=(size_t)n)return 4;fclose(f);
 u32 skus[]={0x610d0,0x510d0,0x4510d0,0x4610d0,0,0xabcdef};
 for(unsigned i=0;i<sizeof(skus)/sizeof(skus[0]);i++){
  __le32 sku[3]={skus[i],0,0};struct iwl_trans t={.info={.hw_rev=0x420,.hw_rf_id=0x10d000}};struct iwl_pnvm_image p={0};
  int rc=iwl_pnvm_parse(&t,bytes,n,&p,sku);printf("case %x %s %x %u\n",skus[i],rc==0?"ok":rc==-ENOENT?"missing":"unexpected",p.version,p.n_chunks);
  if(!rc)for(unsigned j=0;j<p.n_chunks;j++){u32 marker;memcpy(&marker,(const u8 *)p.chunks[j].data-4,4);printf("chunk %u %016llx %x\n",p.chunks[j].len,(unsigned long long)fnv(p.chunks[j].data,p.chunks[j].len),marker);}
 }free(bytes);return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-pnvm.c';unit.write_text(prelude+function('iwl_pnvm_handle_section')+function('iwl_pnvm_parse')+main)
exe=out/'linux-iwlwifi-pnvm';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve()),str(image.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'pnvm_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
