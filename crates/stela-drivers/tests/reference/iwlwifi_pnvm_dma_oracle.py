#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2018-2026 Intel Corporation
"""Unchanged Linux PNVM/reduced-power DMA helper oracle under sanitizers.
Usage: iwlwifi_pnvm_dma_oracle.py SOURCE_DIRECTORY PNVM_IMAGE OUTPUT_DIRECTORY
The wrapper frames known valid real-asset groups; source selection is separately
verified by the PNVM oracle. Deterministic allocation is not real hardware.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,image,out=map(Path,sys.argv[1:])
expected={
 'pcie/ctxt-info-v2.c':'7909fe854927a094b84ca84a94532229fe243cba2af2a2dd29a2ae3f021f007f',
 'pcie/iwl-context-info-v2.h':'fb618ab579a40cb5a0fb80c399479199e97b3d1c27761e05832c4a5fdadbf3b1',
 'pcie/ctxt-info.c':'ceb5fd9d56027508b002bfea4fbba53492657e08229425dcf90385c0770d7a62',
 'iwl-trans.h':'96d1daa1a251e4c1c4d96a3f625db7cc207d0051375010aa7790830cf730a3c4',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
assert hashlib.sha256(image.read_bytes()).hexdigest()=='9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0'

def body(text, name, struct=False):
    if struct:
        pattern = r'^struct ' + name + r'\s*\{'
    else:
        pattern = r'^(?:static[^;{}]*?|(?:int|void)\s+)[^;{}]*?\b' + name + r'\s*\([^;{}]*?\)\n\{'
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef u16 __le16;typedef u32 __le32;typedef u64 __le64;typedef u64 dma_addr_t;
#define __packed __attribute__((packed))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_le64(x) ((u64)(x))
#define IPC_DRAM_MAP_ENTRY_NUM_MAX 64
#define UNFRAGMENTED_PNVM_PAYLOADS_NUMBER 2
#define IWL_DEBUG_FW(...) ((void)0)
#define WARN_ON(x) (!!(x))
#define IWL_DEVICE_FAMILY_AX210 210
#define IWL_UCODE_TLV_CAPA_FRAGMENTED_PNVM_IMG 32
struct iwl_dram_data {dma_addr_t physical;void *block;int size;};
"""
for n in ['iwl_pnvm_image','iwl_dram_regions']:
 prelude+=body(texts['iwl-trans.h'],n,True)+'\n'
v2=texts['pcie/iwl-context-info-v2.h']
for n in ['iwl_prph_scratch_version','iwl_prph_scratch_control','iwl_prph_scratch_pnvm_cfg','iwl_prph_scratch_mem_desc_addr_array','iwl_prph_scratch_hwm_cfg','iwl_prph_scratch_rbd_cfg','iwl_prph_scratch_uefi_cfg','iwl_prph_scratch_step_cfg','iwl_prph_scratch_ctrl_cfg']:
 prelude+=body(v2,n,True)+'\n'
prelude+=r"""
struct iwl_prph_scratch {struct iwl_prph_scratch_ctrl_cfg ctrl_cfg;};
struct iwl_trans_pcie {struct iwl_prph_scratch *prph_scratch;struct iwl_dram_regions pnvm_data,reduced_tables_data;};
struct mac_cfg {int device_family;};
struct iwl_trans {void *dev;bool pnvm_loaded,reduce_power_loaded;struct mac_cfg *mac_cfg;struct iwl_trans_pcie pcie;};
struct iwl_ucode_capabilities {bool fragmented;};
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
static bool fw_has_capa(const struct iwl_ucode_capabilities *c,int bit){if(bit!=32)abort();return c->fragmented;}
static u64 next_iova;
static void *iwl_pcie_ctxt_info_dma_alloc_coherent(struct iwl_trans *t,size_t size,dma_addr_t *address){(void)t;*address=next_iova;next_iova+=0x10000;return calloc(1,size);}
static void iwl_trans_pcie_free_pnvm_dram_regions(struct iwl_dram_regions *r,void *dev){(void)dev;for(unsigned i=0;i<r->n_regions;i++)free(r->drams[i].block);free(r->prph_scratch_mem_desc.block);}
"""
functions=body(texts['pcie/ctxt-info.c'],'iwl_pcie_ctxt_info_alloc_dma')+'\n'
for n in ['iwl_pcie_load_payloads_contig','iwl_pcie_load_payloads_segments','iwl_trans_pcie_ctx_info_v2_load_pnvm','iwl_dram_regions_size','iwl_pcie_set_pnvm_segments','iwl_pcie_set_contig_pnvm','iwl_trans_pcie_ctx_info_v2_set_pnvm','iwl_trans_pcie_ctx_info_v2_load_reduce_power','iwl_pcie_set_reduce_power_segments','iwl_pcie_set_contig_reduce_power','iwl_trans_pcie_ctx_info_v2_set_reduce_power']:
 functions+=body(texts['pcie/ctxt-info-v2.c'],n)+'\n'
main=r"""
static u32 le32(const u8 *b){return (u32)b[0]|(u32)b[1]<<8|(u32)b[2]<<16|(u32)b[3]<<24;}
static u64 fnv(const void *ptr,size_t n){const u8 *b=ptr;u64 h=0xcbf29ce484222325ULL;for(size_t i=0;i<n;i++){h^=b[i];h*=0x100000001b3ULL;}return h;}
static void run(struct iwl_pnvm_image *image,u32 sku){
 for(unsigned fragmented=0;fragmented<2;fragmented++){
  struct iwl_prph_scratch scratch={0};struct mac_cfg mac={.device_family=210};struct iwl_trans t={.mac_cfg=&mac,.pcie={.prph_scratch=&scratch}};struct iwl_ucode_capabilities capa={.fragmented=fragmented};next_iova=0x110000;
  if(iwl_trans_pcie_ctx_info_v2_load_pnvm(&t,image,&capa))abort();iwl_trans_pcie_ctx_info_v2_set_pnvm(&t,&capa);
  // The reduced-power transport consumes the same chunks format; these are
  // known valid payload bytes, not a claim about a platform's actual policy.
  if(iwl_trans_pcie_ctx_info_v2_load_reduce_power(&t,image,&capa))abort();iwl_trans_pcie_ctx_info_v2_set_reduce_power(&t,&capa);
  printf("case %x %u\n",sku,fragmented);
  for(unsigned kind=0;kind<2;kind++){
   struct iwl_dram_regions *r=kind?&t.pcie.reduced_tables_data:&t.pcie.pnvm_data;
   u64 address=kind?scratch.ctrl_cfg.reduce_power_cfg.base_addr:scratch.ctrl_cfg.pnvm_cfg.pnvm_base_addr;
   u32 size=kind?scratch.ctrl_cfg.reduce_power_cfg.size:scratch.ctrl_cfg.pnvm_cfg.pnvm_size;
   printf("table %u %llx %u %u\n",kind,(unsigned long long)address,size,r->n_regions);
   if(fragmented){printf("descriptor ");for(unsigned i=0;i<512;i++)printf("%02x",((u8*)r->prph_scratch_mem_desc.block)[i]);puts("");}
   for(unsigned i=0;i<r->n_regions;i++){struct iwl_dram_data *d=&r->drams[i];printf("payload %llx %d %016llx\n",(unsigned long long)d->physical,d->size,(unsigned long long)fnv(d->block,d->size));}
   iwl_trans_pcie_free_pnvm_dram_regions(r,NULL);
  }
 }
}
int main(int argc,char **argv){
 if(argc!=2)return 2;FILE *f=fopen(argv[1],"rb");if(!f)return 3;fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);u8 *data=malloc(size);if(fread(data,1,size,f)!=(size_t)size)abort();fclose(f);
 struct iwl_pnvm_image image={0};u32 sku=0;
 for(size_t off=0;off<(size_t)size;){if((size_t)size-off<8)abort();u32 kind=le32(data+off),len=le32(data+off+4);off+=8;if(len>(size_t)size-off)abort();
  if(kind==64){if(sku)run(&image,sku);memset(&image,0,sizeof(image));if(len!=12||le32(data+off+4)||le32(data+off+8))abort();sku=le32(data+off);}
  if(kind==19){if(len<=4||image.n_chunks==64)abort();image.chunks[image.n_chunks].data=data+off+4;image.chunks[image.n_chunks++].len=len-4;}
  off+=((size_t)len+3)&~(size_t)3;if(off>(size_t)size)abort();
 }
 if(sku)run(&image,sku);free(data);return 0;
}
"""
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-pnvm-dma.c';unit.write_text(prelude+functions+main);exe=out/'linux-iwlwifi-pnvm-dma'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve()),str(image.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
