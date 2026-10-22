#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2017-2026 Intel Corporation
"""Run unchanged AX210 context-v2 allocator and section helpers under sanitizers.
Usage: iwlwifi_context_v2_oracle.py SOURCE_DIRECTORY AX210_IMAGE OUTPUT_DIRECTORY
Firmware framing, deterministic allocation, normal no-debug selection and device
metadata are wrapper inputs. This does not run Linux I/O or physical hardware.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,image,out=map(Path,sys.argv[1:])
expected={
 'pcie/ctxt-info-v2.c':'7909fe854927a094b84ca84a94532229fe243cba2af2a2dd29a2ae3f021f007f',
 'pcie/iwl-context-info-v2.h':'fb618ab579a40cb5a0fb80c399479199e97b3d1c27761e05832c4a5fdadbf3b1',
 'pcie/ctxt-info.c':'ceb5fd9d56027508b002bfea4fbba53492657e08229425dcf90385c0770d7a62',
 'pcie/iwl-context-info.h':'a2febedf4f2cfb191bd7b2361308806f297bf09b20bf519ffcf53d209dcf664b',
 'pcie/gen1_2/internal.h':'572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
assert hashlib.sha256(image.read_bytes()).hexdigest()=='792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0'

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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef u16 __le16;typedef u32 __le32;typedef u64 __le64;typedef u64 dma_addr_t;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_le64(x) ((u64)(x))
#define BIT(n) (1u<<(n))
#define IWL_MAX_DRAM_ENTRY 64
#define IPC_DRAM_MAP_ENTRY_NUM_MAX 64
#define IWL_NUM_DRAM_FSEQ_ENTRIES 8
#define IWL_AMSDU_DEF 0
#define IWL_AMSDU_2K 2
#define IWL_AMSDU_4K 4
#define IWL_AMSDU_8K 8
#define IWL_AMSDU_12K 12
#define IWL_CMD_QUEUE_SIZE 32
#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define WARN_ON(x) (!!(x))
#define WARN(x,...) (!!(x))
#define BUILD_BUG_ON(x) _Static_assert(!(x),#x)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define CPU1_CPU2_SEPARATOR_SECTION 0xffffccccu
#define PAGING_SEPARATOR_SECTION 0xaaaabbbbu
#define RX_QUEUE_CB_SIZE(x) (31-__builtin_clz((unsigned)(x)))
#define TFD_QUEUE_CB_SIZE(x) (RX_QUEUE_CB_SIZE(x)-3)
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t*)0)->m))
#define IWL_CFG_MAC_TYPE_GL 0x44
#define IWL_DEVICE_FAMILY_SC 30000
#define CSR_HW_REV_TYPE(x) (((x)>>4)&0xfff)
#define IWL_DEBUG_FW(...) ((void)0)
#define kzalloc_objs(o,n) calloc((n),sizeof(o))
#define kfree(p) free(p)
struct fw_desc {u32 offset;const void *data;u32 len;};
struct fw_img {struct fw_desc *sec;int num_sec;};
struct iwl_fw {const void *iml;u32 iml_len;};
struct iwl_dram_data {dma_addr_t physical;void *block;int size;};
struct iwl_self_init_dram {struct iwl_dram_data *fw;int fw_cnt;struct iwl_dram_data *paging;int paging_cnt;};
"""
prelude+=body(texts['pcie/iwl-context-info.h'],'iwl_context_info_dram_nonfseq',True)
v2=texts['pcie/iwl-context-info-v2.h']
for n in ['iwl_prph_scratch_mtr_format','iwl_prph_scratch_flags','iwl_prph_scratch_ext_flags']:
 prelude+=re.search(r'enum '+n+r' \{.*?\};',v2,re.S).group(0)+'\n'
for n in ['iwl_prph_scratch_version','iwl_prph_scratch_control','iwl_prph_scratch_pnvm_cfg','iwl_prph_scratch_hwm_cfg','iwl_prph_scratch_rbd_cfg','iwl_prph_scratch_uefi_cfg','iwl_prph_scratch_step_cfg','iwl_prph_scratch_ctrl_cfg','iwl_context_info_dram_fseq','iwl_prph_scratch','iwl_prph_info','iwl_context_info_v2']:
 prelude+=body(v2,n,True)+'\n'
prelude+=r"""
struct rxq {dma_addr_t bd_dma,used_bd_dma,rb_stts_dma;};
struct txq {dma_addr_t dma_addr;};
struct iwl_trans_pcie {
 struct iwl_context_info_v2 *ctxt_info_v2;dma_addr_t ctxt_info_dma_addr;
 struct iwl_prph_scratch *prph_scratch;dma_addr_t prph_scratch_dma_addr;
 struct iwl_prph_info *prph_info;dma_addr_t prph_info_dma_addr;
 void *iml;dma_addr_t iml_dma_addr;u32 iml_len;
 struct rxq *rxq;struct {struct txq *txq[1];} txqs;
};
struct base {u32 min_txq_size;};
struct mac_cfg {struct base *base;bool imr_enabled;int device_family;};
struct iwl_trans {
 void *dev;struct iwl_self_init_dram init_dram;struct {u32 hw_rev;} info;
 struct {int rx_buf_size,cmd_queue;bool dsbr_urm_fw_dependent,dsbr_urm_permanent,ext_32khz_clock_valid;u32 mbx_addr_0_step,mbx_addr_1_step;} conf;
 bool do_top_reset;unsigned rbds;struct mac_cfg *mac_cfg;struct iwl_trans_pcie pcie;
};
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
static u64 next_iova;
static void *dma_alloc_coherent(void *dev,size_t size,dma_addr_t *addr,int flags){(void)dev;(void)flags;*addr=next_iova;next_iova+=(size+4095)&~4095u;return calloc(1,size);}
static void dma_free_coherent(void *dev,size_t size,void *p,dma_addr_t addr){(void)dev;(void)size;(void)addr;free(p);}
static void *iwl_pcie_ctxt_info_dma_alloc_coherent(struct iwl_trans *t,size_t size,dma_addr_t *addr){return dma_alloc_coherent(t->dev,size,addr,0);}
static unsigned iwl_trans_get_num_rbds(struct iwl_trans *t){return t->rbds;}
// No early debug destination selected: the unchanged allocator receives zero flags.
static void iwl_pcie_ctxt_info_dbg_enable(struct iwl_trans *t,struct iwl_prph_scratch_hwm_cfg *cfg,u32 *flags){(void)t;(void)cfg;(void)flags;}
static bool iwl_is_force_scu_active_approved(void){return false;}
"""
functions='\n'.join([
 body(texts['pcie/gen1_2/internal.h'],'iwl_pcie_get_num_sections'),
 *(body(texts['pcie/ctxt-info.c'],n) for n in ['iwl_pcie_ctxt_info_alloc_dma','iwl_pcie_ctxt_info_free_paging','iwl_pcie_init_fw_sec']),
 body(texts['pcie/ctxt-info-v2.c'],'iwl_pcie_ctxt_info_v2_alloc')])
main=r"""
static u32 le32(const u8 *b){return (u32)b[0]|(u32)b[1]<<8|(u32)b[2]<<16|(u32)b[3]<<24;}
static u64 fnv(const void *p,size_t n){const u8 *b=p;u64 h=0xcbf29ce484222325ULL;for(size_t i=0;i<n;i++){h^=b[i];h*=0x100000001b3ULL;}return h;}
static void hex(const char *tag,void *p,size_t n){printf("%s ",tag);for(size_t i=0;i<n;i++)printf("%02x",((u8*)p)[i]);puts("");}
int main(int argc,char **argv){
 if(argc!=2)return 2;FILE *f=fopen(argv[1],"rb");if(!f)return 3;fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);if(size<88)return 4;u8 *data=malloc(size);if(fread(data,1,size,f)!=(size_t)size)abort();fclose(f);
 struct fw_desc sections[256];struct fw_img img={.sec=sections};struct iwl_fw fw={0};
 for(size_t off=88;off<(size_t)size;){if((size_t)size-off<8)abort();u32 kind=le32(data+off),len=le32(data+off+4);off+=8;if(len>(size_t)size-off)abort();if(kind==19||kind==24){if(len<4||img.num_sec==256)abort();sections[img.num_sec++]=(struct fw_desc){.offset=le32(data+off),.data=data+off+4,.len=len-4};}if(kind==52){if(fw.iml||!len)abort();fw.iml=data+off;fw.iml_len=len;}off+=((size_t)len+3)&~(size_t)3;if(off>(size_t)size)abort();}
 int lm=iwl_pcie_get_num_sections(&img,0),um=iwl_pcie_get_num_sections(&img,lm+1),pg=iwl_pcie_get_num_sections(&img,lm+um+2);
 printf("layout %zu %zu %zu %zu %zu %zu %zu\n",sizeof(struct iwl_context_info_v2),sizeof(struct iwl_prph_scratch),offsetofend(struct iwl_prph_scratch,dram.common),offsetof(struct iwl_prph_scratch,dram.common.umac_img),offsetof(struct iwl_prph_scratch,dram.common.lmac_img),offsetof(struct iwl_prph_scratch,dram.common.virtual_img),sizeof(struct iwl_prph_info));
 for(unsigned count=16;count<=1024;count*=2)for(unsigned step=0;step<2;step++){
  struct rxq rx={.bd_dma=0x10000,.used_bd_dma=0x20000,.rb_stts_dma=0x30000};struct txq tx={.dma_addr=0x40000};struct base base={.min_txq_size=128};struct mac_cfg mac={.base=&base,.device_family=210};
  struct iwl_trans t={.info={.hw_rev=0x420},.conf={.rx_buf_size=4,.mbx_addr_0_step=step?0x56341201:0,.mbx_addr_1_step=step?0x78:0},.rbds=count,.mac_cfg=&mac,.pcie={.rxq=&rx,.txqs={.txq={&tx}}}};
  next_iova=0x100000;if(iwl_pcie_ctxt_info_v2_alloc(&t,&fw,&img))abort();
  printf("case %u %u\n",count,step);
  printf("memory %llx %llx %llx %llx %u\n",(unsigned long long)t.pcie.prph_info_dma_addr,(unsigned long long)t.pcie.prph_scratch_dma_addr,(unsigned long long)t.pcie.ctxt_info_dma_addr,(unsigned long long)t.pcie.iml_dma_addr,t.pcie.iml_len);
  for(int i=0;i<t.init_dram.fw_cnt;i++){struct iwl_dram_data *d=&t.init_dram.fw[i];printf("section %c %d %d %016llx %llx\n",i<lm?'L':'U',i<lm?i:i-lm,d->size,(unsigned long long)fnv(d->block,d->size),(unsigned long long)d->physical);free(d->block);}
  for(int i=0;i<t.init_dram.paging_cnt;i++){struct iwl_dram_data *d=&t.init_dram.paging[i];printf("section P %d %d %016llx %llx\n",i,d->size,(unsigned long long)fnv(d->block,d->size),(unsigned long long)d->physical);free(d->block);}
  printf("iml %016llx\n",(unsigned long long)fnv(t.pcie.iml,t.pcie.iml_len));hex("context",t.pcie.ctxt_info_v2,sizeof(*t.pcie.ctxt_info_v2));hex("scratch",t.pcie.prph_scratch,sizeof(*t.pcie.prph_scratch));
  free(t.init_dram.fw);free(t.init_dram.paging);free(t.pcie.ctxt_info_v2);free(t.pcie.prph_info);free(t.pcie.prph_scratch);free(t.pcie.iml);
 }
 free(data);return 0;
}
"""
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-context-v2.c';unit.write_text(prelude+functions+main);exe=out/'linux-iwlwifi-context-v2'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve()),str(image.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
