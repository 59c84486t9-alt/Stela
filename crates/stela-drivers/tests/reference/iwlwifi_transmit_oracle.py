#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2005-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2015-2017 Intel Deutschland GmbH
"""Complete unchanged new TX helper, non-QoS/CSUM_NONE/rates2 fixture.
Usage: iwlwifi_transmit_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
Allocation, header classification, selected antenna, station state and effective
host rate are fixture inputs. No DMA, queue, key, station or RF services execute.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'mvm/tx.c':'925c237647eeaa1977703f4462374fb708e04c985b1953409dc674beefb5a59a',
'mvm/utils.c':'a11dd446fd139871687c3f34b49030c104f0d5c3bd59ce4214a2d4722901cd7e',
'mvm/ops.c':'a1fb28ef29da10a524527cfc00f3a25a68252f88f1533328ee69a588c82ba24a',
'fw/api/tx.h':'4cd296f5c4f4c9706745192247e7e531d996c5db8d6743e3367f438cf71fb886',
'fw/api/rs.h':'d747d8143570c613208c30eb450eddb222546e4bad545d7d43791ebed95bb860',
'fw/api/cmdhdr.h':'702ed4cc19d4f29ca035f1af395298743c52d7b364fc5ec842dc5952ef4ef848',
'fw/api/datapath.h':'746573de706f6fbc936183670792d4a50ee72c7ceebd72140d7e91b15bbb1a54',
'pcie/gen1_2/tx-gen2.c':'ae940c3298e8024d98842833189077f0f7d079367679865d94618422933ba759',
'pcie/gen1_2/internal.h':'572df25a5a22b0dbd03a3b2e83d553768d0af4e09a9071e2b6002f276bd41d10',
'iwl-trans.h':'96d1daa1a251e4c1c4d96a3f625db7cc207d0051375010aa7790830cf730a3c4',
'iwl-fh.h':'646b7150a6d88d07cbbac5a127e796ea61ec9b8132dcd9b3e6e6be5211293a1a',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def extract(text,pattern):
 m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint64_t __le64;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define unlikely(x) (x)
#define likely(x) (x)
#define IS_ENABLED(x) 0
#define IWL_DEVICE_FAMILY_AX210 1
#define IWL_DEVICE_FAMILY_BZ 2
#define IEEE80211_STA_AUTHORIZED 1
#define IEEE80211_TX_CTRL_RATE_INJECT 1
#define IEEE80211_QOS_CTL_A_MSDU_PRESENT 0x80
#define ETH_ALEN 6
#define TX_CMD 0x1c
#define IWL_FIRST_CCK_RATE 0
#define IWL_LAST_CCK_RATE 3
#define IWL_FIRST_OFDM_RATE 4
#define IWL_RATE_COUNT_LEGACY 12
struct ieee80211_hdr {__le16 frame_control,duration;u8 addr1[6],addr2[6],addr3[6];__le16 seq;} __packed;
struct iwl_tx_cmd_v6 {int params;struct ieee80211_hdr hdr[];};
struct sk_buff {u8 *data;unsigned len;};
struct key {u32 cipher;u8 iv_len;};
#define WLAN_CIPHER_SUITE_WEP40 1
#define WLAN_CIPHER_SUITE_WEP104 2
struct ieee80211_tx_info {struct {struct key *hw_key;unsigned flags;int rate;}control;};
struct iwl_mvm_sta {int sta_state;};struct ieee80211_sta {struct iwl_mvm_sta mvm;};
struct iwl_fw {int unused;};struct mac_cfg {int device_family;};struct iwl_trans {struct mac_cfg *mac_cfg;};struct iwl_mvm {struct iwl_trans *trans;struct iwl_fw *fw;unsigned ant;};
static unsigned ieee80211_hdrlen(__le16 fc){(void)fc;return 24;}
static bool ieee80211_is_data_qos(__le16 fc){return (fc&0x8c)==0x88;}
static bool ieee80211_is_data(__le16 fc){return (fc&0x0c)==0x08;}
static u8 *ieee80211_get_qos_ctl(struct ieee80211_hdr *hdr){(void)hdr;abort();}
#define iwl_mvm_has_new_tx_api(mvm) 1
#define iwl_mvm_sta_from_mac80211(sta) (&(sta)->mvm)
#define iwl_mvm_set_tx_cmd_crypto(...) abort()
#define iwl_mvm_set_tx_cmd(...) abort()
#define iwl_mvm_set_tx_cmd_rate(...) abort()
static int iwl_mvm_mac_ctxt_get_lowest_rate(struct iwl_mvm *m,struct ieee80211_tx_info *i,void *v){(void)m;(void)i;(void)v;abort();}
'''
# Source converter's unreachable invalid-rate fallback still type-checks.
prelude=prelude.replace('unsigned flags;int rate;', 'unsigned flags;int rate;void *vif;')
for name in ['RATE_MCS_MOD_TYPE_POS','RATE_MCS_MOD_TYPE_CCK','RATE_MCS_MOD_TYPE_LEGACY_OFDM']:
 prelude+=next(l for l in texts['fw/api/rs.h'].splitlines() if re.match(r'^#define '+name+r'\b',l))+'\n'
prelude+='#define IWL_TFH_NUM_TBS 25\n#define WARN(x,...) ((x)?(abort(),1):0)\n#define WARN_ON(x) ((x)?(abort(),1):0)\n#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))\n'
for name in ['iwl_tfh_tb','iwl_tfh_tfd','iwl_bc_tbl_entry']:
 prelude+=extract(texts['iwl-fh.h'],r'^struct '+name+r'\s*\{')+' __packed;\n'
prelude+='struct iwl_txq {unsigned n_window,write_ptr;struct {void *addr;}bc_tbl;};\n'
prelude+=extract(texts['pcie/gen1_2/internal.h'],r'^static inline u16 iwl_txq_get_cmd_index\([^{};]*?\)\n\{')+'\n'
prelude+=extract(texts['pcie/gen1_2/tx-gen2.c'],r'^static void iwl_pcie_gen2_update_byte_tbl\([^{};]*?\)\n\{')+'\n'
prelude+=extract(texts['fw/api/tx.h'],r'^enum iwl_tx_cmd_flags\s*\{')+';\n'
prelude+=extract(texts['fw/api/tx.h'],r'^enum iwl_tx_offload_assist_flags_pos\s*\{')+';\n'
for file,name in [('fw/api/cmdhdr.h','iwl_cmd_header'),('fw/api/tx.h','iwl_dram_sec_info'),('fw/api/tx.h','iwl_tx_cmd_v9'),('fw/api/tx.h','iwl_tx_cmd')]:
 prelude+=extract(texts[file],r'^struct '+name+r'\s*\{')+' __packed;\n'
prelude+=extract(texts['iwl-trans.h'],r'^struct iwl_device_tx_cmd\s*\{')+' __packed;\n'
prelude+='static struct iwl_device_tx_cmd *iwl_trans_alloc_tx_cmd(struct iwl_trans *t){(void)t;return calloc(1,128);}\n'
prelude+=extract(texts['mvm/utils.c'],r'^u8 iwl_mvm_rate_idx_to_fw_idx\([^{};]*?\)\n\{')+'\n'
prelude+=extract(texts['mvm/tx.c'],r'^static u32 iwl_mvm_convert_rate_idx\([^{};]*?\)\n\{')+'\n'
# For rates2 legacy values NSS=0, so v3->v2 conversion is the identity. This
# fixture supplies the selected antenna and rate index, not a rate controller.
prelude+='static __le32 iwl_mvm_get_tx_rate_n_flags(struct iwl_mvm *m,struct ieee80211_tx_info *i,struct ieee80211_sta *s,__le16 fc){(void)s;(void)fc;return iwl_mvm_convert_rate_idx(m,i,i->control.rate)|(m->ant<<14);}\n'
for name,pattern in [
 ('iwl_mvm_tx_csum',r'^static u32 iwl_mvm_tx_csum\([^{};]*?\)\n\{'),
 ('iwl_mvm_use_host_rate',r'^static bool iwl_mvm_use_host_rate\([^{};]*?\)\n\{'),
 ('iwl_mvm_copy_hdr',r'^static void iwl_mvm_copy_hdr\([^{};]*?\)\n\{'),
 ('iwl_mvm_set_tx_params',r'^static struct iwl_device_tx_cmd \*\niwl_mvm_set_tx_params\([^{};]*?\)\n\{'),
]:prelude+=extract(texts['mvm/tx.c'],pattern)+'\n'
for name in ['QUEUE_TO_SEQ','INDEX_TO_SEQ']:
 prelude+=next(l for l in texts['fw/api/cmdhdr.h'].splitlines() if re.match(r'^#define '+name+r'\(',l))+'\n'
main=r'''
static void hex(const u8 *p,unsigned n){for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
int main(void){
 unsigned lengths[]={24,25,60,1514,4096};unsigned queues[]={0,31,32,255,511};unsigned indices[]={0,255,256,0xffff};
 for(unsigned family=0;family<2;family++)for(unsigned data=0;data<2;data++)for(unsigned key=0;key<2;key++){
  if(!data&&key)continue;
  for(unsigned state=0;state<3;state++)for(unsigned inject=0;inject<2;inject++)for(unsigned rate=0;rate<12;rate++)for(unsigned ant=1;ant<=2;ant++)for(unsigned size=0;size<5;size++){
   unsigned scene=(family*77+data*59+key*43+state*37+inject*31+rate*23+ant*17+size*13);
   unsigned queue=queues[scene%5],index=indices[(scene/5)%4],len=lengths[size];
   u8 frame[4096];for(unsigned i=0;i<len;i++)frame[i]=(u8)(i*29+scene);u16 fc=(data?0x108:0xb0)|(key?0x4000:0);memcpy(frame,&fc,2);frame[22]&=0xf0;
   struct mac_cfg cfg={family};struct iwl_trans tr={&cfg};struct iwl_fw fw={0};struct iwl_mvm m={&tr,&fw,ant};struct sk_buff skb={frame,len};struct ieee80211_tx_info info={.control={.hw_key=key?(void*)1:NULL,.flags=inject,.rate=rate}};struct ieee80211_sta sta={.mvm={state==2?1:0}};
   struct iwl_device_tx_cmd *cmd=iwl_mvm_set_tx_params(&m,&skb,&info,24,state?&sta:NULL,0,NULL);cmd->hdr.sequence=cpu_to_le16(QUEUE_TO_SEQ(queue)|INDEX_TO_SEQ(index));
   unsigned cmdlen=4+(family?sizeof(struct iwl_tx_cmd):sizeof(struct iwl_tx_cmd_v9))+24;
   printf("tx %u %u %u %u %u %u %u %u %u %u %u ",family,data,key,state,inject,rate,ant,size,scene,queue,index);hex((u8*)cmd,cmdlen);struct iwl_bc_tbl_entry entries[256]={0};struct iwl_txq q={.n_window=256,.write_ptr=index,.bc_tbl={entries}};iwl_pcie_gen2_update_byte_tbl(&tr,&q,len,len>24?3:2);printf(" %u\n",entries[index&255].tfd_offset);free(cmd);
  }
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-transmit.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-transmit'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
