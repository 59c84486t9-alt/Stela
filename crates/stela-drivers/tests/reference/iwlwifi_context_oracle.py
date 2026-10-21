#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2008-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Execute unchanged pinned AX200 Linux context/section helpers under sanitizers.

Usage: iwlwifi_context_oracle.py SOURCE_DIRECTORY AX200_IMAGE OUTPUT_DIRECTORY
The wrapper frames TLVs; it does NOT execute the full Linux firmware parser.
DMA, register and allocator stubs model addresses only, never physical hardware.
Generated C, executable, trace and firmware must remain ignored.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

source, image, out = map(Path, sys.argv[1:])
expected = {
    'pcie/ctxt-info.c': 'ceb5fd9d56027508b002bfea4fbba53492657e08229425dcf90385c0770d7a62',
    'pcie/iwl-context-info.h': 'a2febedf4f2cfb191bd7b2361308806f297bf09b20bf519ffcf53d209dcf664b',
    'pcie/gen1_2/internal.h': '572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
}
texts = {}
for name, digest in expected.items():
    data = (source/name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    texts[name] = data.decode()
assert hashlib.sha256(image.read_bytes()).hexdigest() == '1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab'


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


prelude = r'''// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Intel copyrights retained from pinned donor; see generating script.
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef u16 __le16; typedef u32 __le32; typedef u64 __le64; typedef u64 dma_addr_t;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_le64(x) ((u64)(x))
#define upper_32_bits(x) ((u32)((u64)(x)>>32))
#define WARN(x,...) (!!(x))
#define WARN_ON(x) (!!(x))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define kzalloc_objs(o,n) calloc((n),sizeof(o))
#define GFP_KERNEL 0
#define kfree(p) free(p)
#define CPU1_CPU2_SEPARATOR_SECTION 0xffffccccu
#define PAGING_SEPARATOR_SECTION 0xaaaabbbbu
#define RX_QUEUE_CB_SIZE(x) (31-__builtin_clz((unsigned)(x)))
#define TFD_QUEUE_CB_SIZE(x) (RX_QUEUE_CB_SIZE(x)-3)
#define u32_encode_bits(v,m) (((u32)(v)<<__builtin_ctz((unsigned)(m)))&(m))
#define IWL_CMD_QUEUE_SIZE 32
#define IWL_MAX_DRAM_ENTRY 64
#define CSR_CTXT_INFO_BA 0x40
#define IWL_CTXT_INFO_TFD_FORMAT_LONG 0x100
#define IWL_CTXT_INFO_RB_CB_SIZE 0xf0
#define IWL_CTXT_INFO_RB_SIZE 0x1e00
#define IWL_CTXT_INFO_RB_SIZE_2K 2
#define IWL_CTXT_INFO_RB_SIZE_4K 4
#define IWL_CTXT_INFO_RB_SIZE_8K 8
#define IWL_CTXT_INFO_RB_SIZE_16K 10
#define IWL_AMSDU_2K 2
#define IWL_AMSDU_4K 4
#define IWL_AMSDU_8K 8
#define IWL_AMSDU_12K 12
struct fw_desc { u32 offset; const void *data; u32 len; };
struct fw_img { struct fw_desc *sec; int num_sec; };
struct iwl_dram_data { dma_addr_t physical; void *block; int size; };
struct iwl_self_init_dram { struct iwl_dram_data *fw; int fw_cnt; struct iwl_dram_data *paging; int paging_cnt; };
'''
structs = '\n'.join(body(texts['pcie/iwl-context-info.h'], n, True) for n in [
    'iwl_context_info_version', 'iwl_context_info_control', 'iwl_context_info_dram_nonfseq',
    'iwl_context_info_rbd_cfg', 'iwl_context_info_hcmd_cfg', 'iwl_context_info_dump_cfg',
    'iwl_context_info_pnvm_cfg', 'iwl_context_info_early_dbg_cfg', 'iwl_context_info'])
stubs = r'''
struct rxq { dma_addr_t bd_dma,used_bd_dma,rb_stts_dma; };
struct txq { dma_addr_t dma_addr; };
struct iwl_trans_pcie { struct iwl_context_info *ctxt_info; dma_addr_t ctxt_info_dma_addr; struct rxq *rxq; struct { struct txq *txq[1]; } txqs; };
struct iwl_trans { void *dev; struct iwl_self_init_dram init_dram; struct { u32 hw_rev; } info; struct { int rx_buf_size,cmd_queue; } conf; unsigned rbds; struct iwl_trans_pcie pcie; };
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
static u64 next_iova;
static void *iwl_pcie_ctxt_info_dma_alloc_coherent(struct iwl_trans *t,size_t size,dma_addr_t *phys) {
    (void)t; *phys=next_iova; next_iova+=(size+4095)&~4095u; return calloc(1,size);
}
static void dma_free_coherent(void *d,size_t n,void *p,dma_addr_t a) { (void)d;(void)n;(void)a;free(p); }
static unsigned iwl_trans_get_num_rbds(struct iwl_trans *t) { return t->rbds; }
static void iwl_enable_fw_load_int_ctx_info(struct iwl_trans *t,bool b) { (void)t;(void)b; }
static bool iwl_pcie_dbg_on(struct iwl_trans *t) { (void)t;return false; }
static void iwl_pcie_apply_destination(struct iwl_trans *t) { (void)t;abort(); }
static void iwl_write64(struct iwl_trans *t,u32 reg,u64 addr) { if(reg!=CSR_CTXT_INFO_BA || addr!=t->pcie.ctxt_info_dma_addr) abort(); }
'''
functions = '\n'.join([
    body(texts['pcie/gen1_2/internal.h'], 'iwl_txq_crosses_4g_boundary'),
    body(texts['pcie/gen1_2/internal.h'], 'iwl_pcie_get_num_sections'),
    *(body(texts['pcie/ctxt-info.c'], n) for n in [
        'iwl_pcie_ctxt_info_alloc_dma', 'iwl_pcie_ctxt_info_free_paging',
        'iwl_pcie_init_fw_sec', 'iwl_pcie_ctxt_info_init'])])
main = r'''
static u32 le32(const u8 *b) { return (u32)b[0] | (u32)b[1]<<8 | (u32)b[2]<<16 | (u32)b[3]<<24; }
static u64 fnv(const void *ptr,size_t n) { const u8 *p=ptr;u64 h=0xcbf29ce484222325ULL;for(size_t i=0;i<n;i++){h^=p[i];h*=0x100000001b3ULL;}return h; }
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    FILE *f=fopen(argv[1],"rb");if(!f)return 3;
    fseek(f,0,SEEK_END);long bytes=ftell(f);rewind(f);if(bytes<88)return 4;
    u8 *data=malloc(bytes);if(fread(data,1,bytes,f)!=(size_t)bytes)return 5;fclose(f);
    struct fw_desc sections[256];struct fw_img fw={.sec=sections};
    for(size_t off=88;off<(size_t)bytes;) {
        if((size_t)bytes-off<8)abort();u32 kind=le32(data+off),len=le32(data+off+4);off+=8;
        if(len>(size_t)bytes-off)abort();
        if(kind==19||kind==24) {if(len<4||fw.num_sec==256)abort();sections[fw.num_sec++]=(struct fw_desc){.offset=le32(data+off),.data=data+off+4,.len=len-4};}
        off+=((size_t)len+3)&~(size_t)3;if(off>(size_t)bytes)abort();
    }
    int lm=iwl_pcie_get_num_sections(&fw,0),um=iwl_pcie_get_num_sections(&fw,lm+1),pg=iwl_pcie_get_num_sections(&fw,lm+um+2);
    printf("counts %d %d %d\n",lm,um,pg);
    for(unsigned count=8;count<=2048;count*=2) {
        struct rxq rx={.bd_dma=0x10000,.used_bd_dma=0x20000,.rb_stts_dma=0x30000};struct txq tx={.dma_addr=0x40000};
        struct iwl_trans t={.info={.hw_rev=0x340},.conf={.rx_buf_size=IWL_AMSDU_4K,.cmd_queue=0},.rbds=count,.pcie={.rxq=&rx,.txqs={.txq={&tx}}}};
        next_iova=0x100000;
        if(iwl_pcie_ctxt_info_init(&t,&fw))abort();
        printf("context %u ",count);for(size_t i=0;i<sizeof(*t.pcie.ctxt_info);i++)printf("%02x",((u8 *)t.pcie.ctxt_info)[i]);puts("");
        for(int i=0;i<t.init_dram.fw_cnt;i++){
            struct iwl_dram_data *d=&t.init_dram.fw[i];
            printf("section %u %c %d %d %016llx %016llx\n",count,i<lm?'L':'U',i<lm?i:i-lm,d->size,(unsigned long long)fnv(d->block,d->size),(unsigned long long)d->physical);free(d->block);
        }
        for(int i=0;i<t.init_dram.paging_cnt;i++){
            struct iwl_dram_data *d=&t.init_dram.paging[i];
            printf("section %u P %d %d %016llx %016llx\n",count,i,d->size,(unsigned long long)fnv(d->block,d->size),(unsigned long long)d->physical);free(d->block);
        }
        free(t.init_dram.fw);free(t.init_dram.paging);free(t.pcie.ctxt_info);
    }
    for(unsigned len=1;len<=65535;len++) {
        u64 a=(1ULL<<32)-len;
        printf("boundary %u %u%u%u\n",len,iwl_txq_crosses_4g_boundary(a-1,len),iwl_txq_crosses_4g_boundary(a,len),iwl_txq_crosses_4g_boundary(a+1,len));
    }
    free(data);return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
unit=out/'linux-iwlwifi-context.c'
unit.write_text(prelude+structs+stubs+functions+main)
exe=out/'linux-iwlwifi-context'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve()),str(image.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()}
import json
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
