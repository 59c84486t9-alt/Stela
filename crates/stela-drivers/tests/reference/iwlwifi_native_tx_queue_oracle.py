#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
"""Original cc9de5d4 queue allocator/reply and TX response helpers. Fresh source receipt; the historical descendant oracle is preserved.
DMA allocation, HCMD transport and station ownership are explicit fixture mocks.
Usage: SCRIPT SOURCE_DIRECTORY OUTPUT_DIRECTORY
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'pcie/gen1_2/tx-gen2.c':'d6c9de307d2ea363be82f623989036e30a57de03c021e5d0f1ea496ed66ced3c',
 'mvm/tx.c':'925c237647eeaa1977703f4462374fb708e04c985b1953409dc674beefb5a59a',
 'mvm/mvm.h':'2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
 'fw/api/tx.h':'4cd296f5c4f4c9706745192247e7e531d996c5db8d6743e3367f438cf71fb886',
 'fw/api/txq.h':'99c49fca97b83a092ca3017c2c6ee34c52ee68ce2b7f016e10fa8b35d9aceeb5',
 'fw/api/datapath.h':'746573de706f6fbc936183670792d4a50ee72c7ceebd72140d7e91b15bbb1a54',
 'iwl-fh.h':'646b7150a6d88d07cbbac5a127e796ea61ec9b8132dcd9b3e6e6be5211293a1a',
 'cfg/22000.c':'fda65f1449a6bb20a7e586628ab0261286f651839621c98bbd40584018c3a76e',
 'cfg/ax210.c':'2586be15e4f4886341c956f2a182a8e4d58d04a82df5288aa72a159f3a6bdc37',
}
texts={}
for name,sha in expected.items():
 b=(source/name).read_bytes();assert hashlib.sha256(b).hexdigest()==sha,name;texts[name]=b.decode()
def extract(file,pattern):
 text=texts[file];m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
prelude='/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */\n'
for f in ['pcie/gen1_2/tx-gen2.c','mvm/tx.c','mvm/mvm.h','fw/api/tx.h','fw/api/txq.h','fw/api/datapath.h']:
 prelude+='\n'.join(l for l in texts[f][:texts[f].index('#include') if '#include' in texts[f] else texts[f].index('#ifndef')].splitlines() if not l.startswith('#'))+'\n'
prelude+=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpup(x) (*(x))
#define WARN_ON(x) (x)
#define WARN_ONCE(x,...) warn_observed(!!(x))
static bool warn_observed(bool value){return value;}
#define IWL_DEBUG_TX_QUEUES(...)
#define IWL_TRANS_GET_PCIE_TRANS(t) (&(t)->pcie)
#define IWL_DEVICE_FAMILY_AX210 1
#define IWL_DEVICE_FAMILY_BZ 2
#define SILICON_A_STEP 0
#define DATA_PATH_GROUP 5
#define SCD_QUEUE_CONFIG_CMD 0x17
#define SCD_QUEUE_CFG 0x1d
#define WIDE_ID(g,c) (((g)<<8)|(c))
#define CMD_WANT_SKB 1
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define rounddown_pow_of_two(n) (1U<<(31-__builtin_clz(n)))
#define ilog2(n) (31-__builtin_clz(n))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define hweight32(n) __builtin_popcount(n)
#define ffs(n) __builtin_ffs(n)
struct iwl_txq {unsigned id,read_ptr,write_ptr,n_window;u64 dma_addr;struct {u64 dma;}bc_tbl;};
struct iwl_rx_packet {unsigned len;u8 data[8];};
struct iwl_host_cmd {unsigned flags,id,len[1];const void *data[1];struct iwl_rx_packet *resp_pkt;};
struct base {unsigned max_tfd_queue_size;};struct cfg {int device_family;struct base *base;};
struct iwl_trans_pcie {struct {unsigned bc_tbl_size;struct iwl_txq *txq[512];unsigned char queue_used[512];}txqs;};
struct iwl_trans {struct iwl_trans_pcie pcie;struct cfg *mac_cfg;struct {int hw_rev_step;}info;struct {int queue_alloc_cmd_ver;}conf;};
struct iwl_mvm {struct iwl_trans *trans;};
#define iwl_mvm_has_new_tx_api(m) 1
static unsigned iwl_rx_packet_payload_len(struct iwl_rx_packet *p){return p->len;}
static bool test_and_set_bit(unsigned n,unsigned char *p){bool old=p[n];p[n]=1;return old;}
static void iwl_free_resp(struct iwl_host_cmd *h){(void)h;}
static unsigned failures,allocations,frees;static struct iwl_txq allocated;static struct iwl_rx_packet response;
static unsigned captured_id,captured_length;static u8 captured[64];
static struct iwl_txq *iwl_txq_dyn_alloc_dma(struct iwl_trans *t,int size,unsigned timeout){(void)t;(void)timeout;allocations++;if(failures){failures--;return ERR_PTR(-ENOMEM);}memset(&allocated,0,sizeof(allocated));allocated.n_window=size;allocated.dma_addr=0x12345678000ULL;allocated.bc_tbl.dma=0xabcde000ULL;return &allocated;}
static void iwl_txq_gen2_free_memory(struct iwl_trans *t,struct iwl_txq *q){(void)t;(void)q;frees++;}
static int iwl_trans_send_cmd(struct iwl_trans *t,struct iwl_host_cmd *h){(void)t;captured_id=h->id;captured_length=h->len[0];if(captured_length>sizeof(captured))abort();memcpy(captured,h->data[0],captured_length);h->resp_pkt=&response;return 0;}
'''
for n in ['TFD_QUEUE_CB_SIZE','TFD_QUEUE_SIZE_MAX','TFD_QUEUE_SIZE_BC_DUP','TFD_QUEUE_BC_SIZE','TFD_QUEUE_BC_SIZE_AX210']:
 prelude+=next(l for l in texts['iwl-fh.h'].splitlines() if re.match(r'^#define '+n+r'\b',l))+'\n'
for f,name in [('fw/api/txq.h','iwl_tx_queue_cfg_actions'),('fw/api/datapath.h','iwl_scd_queue_cfg_operation')]:prelude+=extract(f,r'^enum '+name+r'\s*\{')+';\n'
prelude+=extract('iwl-fh.h',r'^struct iwl_bc_tbl_entry\s*\{')+' __packed;\n'
for f,name in [('fw/api/txq.h','iwl_tx_queue_cfg_cmd'),('fw/api/txq.h','iwl_tx_queue_cfg_rsp'),('fw/api/datapath.h','iwl_scd_queue_cfg_cmd'),('fw/api/tx.h','agg_tx_status'),('fw/api/tx.h','iwl_tx_resp_v3'),('fw/api/tx.h','iwl_tx_resp')]:prelude+=extract(f,r'^struct '+name+r'\s*\{')+' __packed;\n'
for f,p in [('pcie/gen1_2/tx-gen2.c',r'^static int iwl_pcie_txq_alloc_response\([^{};]*?\)\n\{'),('pcie/gen1_2/tx-gen2.c',r'^int iwl_txq_dyn_alloc\([^{};]*?\)\n\{'),('mvm/mvm.h',r'^static inline struct agg_tx_status \*\niwl_mvm_get_agg_status\([^{};]*?\)\n\{'),('mvm/tx.c',r'^static inline u32 iwl_mvm_get_scd_ssn\([^{};]*?\)\n\{'),('mvm/tx.c',r'^static inline size_t iwl_mvm_tx_resp_min_len\([^{};]*?\)\n\{')]:prelude+=extract(f,p)+'\n'
# These numeric limits come from the exact hashed family configuration fields.
limits=[]
for f in ['cfg/22000.c','cfg/ax210.c']:
 limits.append(int(re.search(r'\.max_tfd_queue_size\s*=\s*(\d+)',texts[f])[1]))
prelude+='static const unsigned family_limits[]={'+','.join(map(str,limits))+'};\n'
main=r'''
int main(void){
 unsigned sizes[]={16,32,64,128,256,1024};u32 masks[]={1,0x80000000U,3};unsigned tids[]={0,7,15};
 struct base base={0};struct cfg cfg={0,&base};struct iwl_trans trans={.mac_cfg=&cfg,.conf={3}};struct iwl_mvm mvm={&trans};
 for(unsigned family=0;family<2;family++)for(unsigned size=0;size<6;size++)for(unsigned mask=0;mask<3;mask++)for(unsigned tid=0;tid<3;tid++)for(unsigned fail=0;fail<3;fail++){
  memset(&trans.pcie,0,sizeof(trans.pcie));cfg.device_family=family;base.max_tfd_queue_size=family_limits[family];trans.pcie.txqs.bc_tbl_size=sizeof(struct iwl_bc_tbl_entry)*(family?TFD_QUEUE_BC_SIZE_AX210:TFD_QUEUE_BC_SIZE);failures=fail;allocations=frees=0;allocated=(struct iwl_txq){0};captured_length=0;response.len=8;struct iwl_tx_queue_cfg_rsp rsp={.queue_number=511,.write_pointer=0xffff};memcpy(response.data,&rsp,8);
  int ret=iwl_txq_dyn_alloc(&trans,0,masks[mask],tids[tid],sizes[size],123);
  printf("queue %u %u %u %u %u %d %u %u %u %u %u ",family,sizes[size],masks[mask],tids[tid],fail,ret,allocations,frees,allocated.n_window,allocated.write_ptr,captured_id);for(unsigned i=0;i<captured_length;i++)printf("%02x",captured[i]);puts("");
 }
 unsigned queues[]={0,1,31,32,255,256,511,512,65535},flags[]={0,1,65535},writes[]={0,255,256,65535};
 for(unsigned family=0;family<2;family++)for(unsigned qi=0;qi<9;qi++)for(unsigned fi=0;fi<3;fi++)for(unsigned wi=0;wi<4;wi++)for(unsigned busy=0;busy<3;busy++){
  memset(&trans.pcie,0,sizeof(trans.pcie));cfg.device_family=family;base.max_tfd_queue_size=family_limits[family];allocated=(struct iwl_txq){0};frees=0;unsigned q=queues[qi];if(q<512){trans.pcie.txqs.queue_used[q]=busy==1;trans.pcie.txqs.txq[q]=busy==2?&allocated:NULL;}
  response.len=8;struct iwl_tx_queue_cfg_rsp rsp={q,flags[fi],writes[wi],0};memcpy(response.data,&rsp,8);struct iwl_host_cmd h={.resp_pkt=&response};int ret=iwl_pcie_txq_alloc_response(&trans,&allocated,&h);
  printf("reply %u %u %u %u %u %d %u %u\n",family,q,flags[fi],writes[wi],busy,ret,allocated.write_ptr,frees);
 }
 for(unsigned family=0;family<2;family++)for(unsigned sample=0;sample<512;sample++){
  cfg.device_family=family;base.max_tfd_queue_size=family_limits[family];u8 bytes[2048]={0};struct iwl_tx_resp *tx=(void*)bytes;unsigned frames=sample<256?1:sample-256;for(unsigned i=0;i<40+frames*4+4;i++)bytes[i]=(u8)(i*37+sample*19);tx->frame_count=frames;tx->tx_queue=sample;u32 ssn=0xfedc0000U|(sample*127U);memcpy(bytes+40+frames*4,&ssn,4);
  printf("tx %u %u %u %zu %u %zu %zu ",family,sample,frames,iwl_mvm_tx_resp_min_len(&mvm,tx),iwl_mvm_get_scd_ssn(&mvm,tx),sizeof(*tx),offsetof(struct iwl_tx_resp,status));for(unsigned i=0;i<40+frames*4+4;i++)printf("%02x",bytes[i]);puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=False);unit=out/'linux-iwlwifi-tx-queue.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-tx-queue'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'cc9de5d4b5ab6459f5774946aa3195ad51236fa8','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
