#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2003, Jouni Malinen <jkmaline@cc.hut.fi>
# Copyright 2002-2005, Instant802 Networks, Inc.
# Copyright 2005-2006, Devicescape Software, Inc.
# Copyright 2006-2007 Jiri Benc <jbenc@suse.cz>
# Copyright 2007, Michael Wu <flamingice@sourmilk.net>
# Copyright 2007-2010, Intel Corporation
# Copyright 2017 Intel Deutschland GmbH
# Copyright(c) 2020-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2013-2014, 2018-2020, 2022-2026 Intel Corporation
"""Original cold single-link coexistence initialization, CI and antenna rules.

Usage: SCRIPT IWLWIFI_SOURCE OUTPUT_DIRECTORY
One actual source station-vif projection is unassociated, non-HT, link0/PHY0,
no reduced-power state, no RSSI events or second interface. Host enumeration,
transport and wiphy-work backends are explicit fixtures; unexpected work or
device effects abort. No firmware, frame, HCI state or physical RF executes.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'mvm/coex.c':'447f9e0de8fb3f1b62a168ae271866c8eb6762d8681c8d90b702fcab7f038fd0',
 'mvm/utils.c':'bf94624889244fa7f87a9295ea15b771235efbd7fb66e692305421270c1f57bc',
 'mvm/tx.c':'925c237647eeaa1977703f4462374fb708e04c985b1953409dc674beefb5a59a',
 'mvm/mvm.h':'2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
 'mvm/constants.h':'a4a1b1d917f3b5655e8057c298abca7cd2682eaaa28b77c23c320e68bbb3185f',
 'fw/api/coex.h':'63178c0d776ea57b517f7b13796ebf0775d44e3fae3ecbcf4d20184423ee36a6',
 'fw/api/commands.h':'4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
 'fw/api/rs.h':'d747d8143570c613208c30eb450eddb222546e4bad545d7d43791ebed95bb860',
 'fw/file.h':'148a5f3b2ac6afd9e6b0c2bbc255773482dd7fd6890e70ccd65bca17f3ea9a6c',
 'iwl-config.h':'b37b175d2b80eb7a9309792d22f41e8cc94a60246420948e1e7a5b5aff65c4c9',
 'mvm/ops.c':'ea3a9e828ff7d39bcb088644f430eb8834bcd0e9776faee711d7948f4fc7b108',
 'mvm/fw.c':'0b81a7a3febe192b14525ada360149cbf1dadc6aeecb5535db2badb7b7e8417f',
 'cfg/rf-hr.c':'07b5e6eb19d3afe2bef0867f9cc665e133c861c6c9c3ce4d80924d5b64c9e1af',
}
texts={}
for file,digest in expected.items():
 data=(source/file).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,file;texts[file]=data.decode()
root=source.parents[4]
headers={
 'include/net/mac80211.h':'aa6fab3b830cb56fcfa20b1090a6f947aeef19ad0f81ed9153b517944bd4a740',
 'include/uapi/linux/nl80211.h':'5b67257da9911fbffa2d5a3689c629f69e628dbf3147ddf30c65606b251f493b',
 'include/linux/ieee80211-eht.h':'1d947e2d744d9296a45d2481ecaca957d47aca4980ace0230c9b45f056e9526a',
 'net/mac80211/ht.c':'84ed5858ed5289e74cf15cd13dc4388d26e35789c890ea149f6b4dffa3df0ef3',
 'net/mac80211/link.c':'abb44c7cb5c5347356439b3f4e5f330d276fec7542363e5a3d3a103b3a44aab7',
 'net/mac80211/iface.c':'d202222b1534e1f0a6f255c05c2e5f514a08e62244e752989a75bbe8e4129733',
 'net/mac80211/ieee80211_i.h':'e179936d3584d8f4602590ce8f65c9afbcbec4a501b5feb533998b53ca260324',
 'net/mac80211/mlme.c':'470545ca564ab66f350afc1feea3d0d709cf0b4a8d39a08b1b719e352a84d463',
 'net/core/dev.c':'bb55b511911dde385bacda013afb615bd958f4bb84991b6578afc266532b77ff',
 'include/linux/netdevice.h':'75ffee3f1be5ae4874098ce54193725693aa16648d7998113224bb8fddbf0d79',
}
for file,digest in headers.items():
 data=(root/file).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,file;texts[file]=data.decode()
def extract(file,pattern):
 text=texts[file];m=re.search(pattern,text,re.M);assert m,(file,pattern)
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
def function(file,name):
 return extract(file,r'^(?:static\s+)?(?:inline\s+)?(?:void|int|bool|u8|u32|enum iwl_bt_coex_lut_type)\s+'+name+r'\([^{};]*?\)\s*\n\{')+'\n'
prelude='/* Combined fixture SPDX-License-Identifier: GPL-2.0-only.\n'+texts['net/mac80211/ht.c'].split('/*',1)[1].split('*/',1)[0]+'*/\n'+r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
#define __packed __attribute__((packed))
#define BIT(x) (1U<<(x))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_le64(x) ((u64)(x))
#define le32_to_cpu(x) (x)
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define IWL_DEBUG_COEX(...)
#define IWL_ERR(...)
#define lockdep_assert_held(...)
#define rcu_read_lock(...)
#define rcu_read_unlock(...)
#define rcu_dereference(x) (x)
#define unlikely(x) (x)
#define likely(x) (x)
#define trace_api_request_smps(...)
#define HZ 100
#define time_after(a,b) ((long)((b)-(a))<0)
#define swap(a,b) do{__typeof__(a) tmp=(a);(a)=(b);(b)=tmp;}while(0)
#define CMD_ASYNC 1
static unsigned long jiffies;
'''
for file,name in [('fw/api/coex.h','iwl_bt_coex_lut_type'),('fw/api/coex.h','iwl_bt_coex_mode'),
 ('fw/api/coex.h','iwl_bt_coex_enabled_modules'),('fw/api/coex.h','iwl_bt_activity_grading'),
 ('mvm/mvm.h','iwl_mvm_smps_type_request'),('mvm/mvm.h','iwl_bt_force_ant_mode'),
 ('iwl-config.h','iwl_device_family'),('include/net/mac80211.h','ieee80211_smps_mode'),
 ('include/net/mac80211.h','ieee80211_interface_iteration_flags'),
 ('include/uapi/linux/nl80211.h','nl80211_band'),('include/uapi/linux/nl80211.h','nl80211_iftype'),
 ('include/uapi/linux/nl80211.h','nl80211_chan_width')]:
 prelude+=extract(file,r'^enum '+name+r'\s*\{')+';\n'
for file,name in [('mvm/utils.c','MAX_ANT_NUM'),('mvm/coex.c','MVM_COEX_TCM_PERIOD'),('fw/api/rs.h','RATE_MCS_ANT_POS'),
 ('fw/api/coex.h','BT_REDUCED_TX_POWER_BIT'),('include/linux/ieee80211-eht.h','IEEE80211_MLD_MAX_NUM_LINKS')]:
 prelude+=re.search(r'^#define '+name+r'[^\n]+',texts[file],re.M)[0]+'\n'
for name in ['IWL_MVM_BT_COEX_SYNC2SCO','IWL_MVM_BT_COEX_MPLUT','IWL_MVM_BT_COEX_EN_RED_TXP_THRESH','IWL_MVM_BT_COEX_DIS_RED_TXP_THRESH']:
 prelude+=re.search(r'^#define '+name+r'[^\n]+',texts['mvm/constants.h'],re.M)[0]+'\n'
for name in ['IWL_UCODE_TLV_CAPA_BT_MPLUT_SUPPORT','IWL_UCODE_TLV_CAPA_COEX_SCHEMA_2']:
 m=re.search(name+r'\s*=\s*\(__force iwl_ucode_tlv_capa_t\)(\d+)',texts['fw/file.h']);assert m;prelude+=f'#define {name} {m[1]}\n'
for name in ['BT_CONFIG','BT_COEX_CI','BT_COEX_UPDATE_REDUCED_TXP']:
 m=re.search(name+r'\s*=\s*(0x[0-9a-fA-F]+)',texts['fw/api/commands.h']);assert m;prelude+=f'#define {name} {m[1]}\n'
for name in ['iwl_bt_coex_cmd','iwl_bt_coex_ci_cmd','iwl_bt_coex_reduced_txp_update_cmd','iwl_bt_coex_prof_old_notif']:
 prelude+=extract('fw/api/coex.h',r'^struct '+name+r'\s*\{')+' __packed;\n'
prelude+=r'''
struct caps{bool mplut,schema2;};struct fw{struct caps ucode_capa;};
struct cfg{unsigned device_family;u8 non_shared_ant;};struct trans{struct cfg *mac_cfg;};
struct ieee80211_channel{enum nl80211_band band;u16 hw_value,center_freq;};
struct ieee80211_chanctx_conf{u8 drv_priv[2];struct{struct ieee80211_channel *chan;enum nl80211_chan_width width;unsigned center_freq1;}def;};
struct ieee80211_bss_conf{struct ieee80211_chanctx_conf *chanctx_conf;};
struct iwl_mvm_phy_ctxt{u16 id;};
struct iwl_mvm_vif_link_info{unsigned fw_link_id,ap_sta_id;struct iwl_mvm_phy_ctxt *phy_ctxt;
 struct{int ave_beacon_signal,last_bt_coex_event,bt_coex_max_thold,bt_coex_min_thold;}bf_data;
 enum ieee80211_smps_mode smps_requests[NUM_IWL_MVM_SMPS_REQ];};
struct iwl_mvm_vif{unsigned id;bool ap_ibss_active;struct iwl_mvm_vif_link_info *link[IEEE80211_MLD_MAX_NUM_LINKS];};
struct ieee80211_link_data{struct{struct{enum ieee80211_smps_mode driver_smps_mode;unsigned request_smps_work;}mgd;}u;};
struct local{struct{void *wiphy;}hw;};struct ieee80211_sub_if_data{struct ieee80211_link_data *link[IEEE80211_MLD_MAX_NUM_LINKS];struct local *local;};
struct ieee80211_vif{enum nl80211_iftype type;struct{bool assoc;}cfg;struct ieee80211_bss_conf bss_conf;
 struct ieee80211_bss_conf *link_conf[IEEE80211_MLD_MAX_NUM_LINKS];struct iwl_mvm_vif *priv;struct ieee80211_sub_if_data *sdata;};
struct ieee80211_sta{struct iwl_mvm_sta *priv;};struct ieee80211_tx_info{enum nl80211_band band;};
struct iwl_mvm_sta{bool bt_reduced_txpower;struct{u8 sta_id;}deflink;u8 tx_ant;};
struct ieee80211_hw{struct ieee80211_vif *vif;};
struct iwl_mvm{struct fw *fw;struct trans *trans;struct cfg *cfg;struct ieee80211_hw *hw;unsigned bt_force_ant_mode;
 struct iwl_bt_coex_prof_old_notif last_bt_notif;struct iwl_bt_coex_ci_cmd last_bt_ci_cmd;
 unsigned long bt_coex_last_tcm_ts;struct{struct{u8 load[1];}result;}tcm;struct iwl_mvm_sta sta;u8 valid_ant,mgmt_last_antenna_idx;};
static struct iwl_mvm_vif *iwl_mvm_vif_from_mac80211(const struct ieee80211_vif *v){return v->priv;}
static struct ieee80211_sub_if_data *vif_to_sdata(struct ieee80211_vif *v){return v->sdata;}
static struct iwl_mvm_sta *iwl_mvm_sta_from_staid_protected(struct iwl_mvm *m,u8 s){if(s)abort();return &m->sta;}
static struct iwl_mvm_sta *iwl_mvm_sta_from_mac80211(struct ieee80211_sta *s){return s->priv;}
static bool fw_has_capa(struct caps *c,unsigned bit){if(bit==IWL_UCODE_TLV_CAPA_BT_MPLUT_SUPPORT)return c->mplut;if(bit==IWL_UCODE_TLV_CAPA_COEX_SCHEMA_2)return c->schema2;abort();}
static bool iwl_mvm_has_rlc_offload(struct iwl_mvm *m){(void)m;return false;}
static unsigned num_of_ant(unsigned v){return __builtin_popcount(v);}
static unsigned iwl_mvm_get_valid_rx_ant(struct iwl_mvm *m){(void)m;return 3;}
static u8 iwl_mvm_get_valid_tx_ant(struct iwl_mvm *m){return m->valid_ant;}
static bool iwl_mvm_vif_low_latency(struct iwl_mvm_vif *v){(void)v;return false;}
static bool ieee80211_is_data(__le16 fc){return (fc&12)==8;}
static void wiphy_work_queue(void *w,unsigned *work){(void)w;(void)work;abort();}
static void ieee80211_iterate_active_interfaces_atomic(struct ieee80211_hw *hw,unsigned flags,void(*iter)(void*,u8*,struct ieee80211_vif*),void *data){if(flags!=IEEE80211_IFACE_ITER_NORMAL)abort();iter(data,NULL,hw->vif);}
static unsigned sends,length,last_id;static u8 wire[64];static int failure;
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,unsigned id,unsigned flags,unsigned n,const void *bytes){
 (void)m;if(flags||n>sizeof(wire))abort();if(id!=BT_CONFIG&&id!=BT_COEX_CI)abort();sends++;length=n;last_id=id;memcpy(wire,bytes,n);return failure;}
'''
prelude+=extract('mvm/coex.c',r'^static const __le64 iwl_ci_mask\[\]\[3\] = \{')+';\n'
prelude+=extract('mvm/coex.c',r'^struct iwl_bt_iterator_data\s*\{')+';\n'
functions=[('mvm/mvm.h','iwl_mvm_is_mplut_supported'),('net/mac80211/ht.c','ieee80211_request_smps'),
 ('mvm/utils.c','iwl_mvm_update_smps'),('mvm/utils.c','iwl_mvm_next_antenna'),
 ('mvm/coex.c','iwl_get_coex_type'),('mvm/coex.c','iwl_mvm_send_bt_init_conf'),
 ('mvm/coex.c','iwl_mvm_bt_coex_reduced_txp'),('mvm/coex.c','iwl_mvm_bt_coex_enable_rssi_event'),
 ('mvm/coex.c','iwl_mvm_bt_coex_tcm_based_ci'),('mvm/coex.c','iwl_mvm_bt_notif_per_link'),
 ('mvm/coex.c','iwl_mvm_bt_notif_iterator'),('mvm/coex.c','iwl_mvm_bt_coex_notif_handle'),
 ('mvm/coex.c','iwl_mvm_bt_coex_is_shared_ant_avail'),('mvm/tx.c','iwl_mvm_get_tx_ant')]
for file,name in functions:prelude+=function(file,name)
main=r'''
static void hex(void){if(!length){printf("-");return;}for(unsigned i=0;i<length;i++)printf("%02x",wire[i]);}
int main(void){
 struct fw fw={0};struct cfg cfg={.device_family=IWL_DEVICE_FAMILY_22000,.non_shared_ant=2};struct trans trans={.mac_cfg=&cfg};
 struct ieee80211_channel channel={0};struct ieee80211_chanctx_conf chan={.def={.chan=&channel,.width=NL80211_CHAN_WIDTH_20_NOHT}};
 struct ieee80211_bss_conf bss={.chanctx_conf=&chan};struct iwl_mvm_phy_ctxt phy={0};struct iwl_mvm_vif_link_info link={.phy_ctxt=&phy};
 struct iwl_mvm_vif mvif={.link={&link}};struct ieee80211_link_data host_link={0};struct local local={0};
 struct ieee80211_sub_if_data sdata={.link={&host_link},.local=&local};
 struct ieee80211_vif vif={.type=NL80211_IFTYPE_STATION,.priv=&mvif,.sdata=&sdata,.bss_conf={.chanctx_conf=&chan},.link_conf={&bss}};
 struct ieee80211_hw hw={.vif=&vif};struct iwl_mvm m={.fw=&fw,.cfg=&cfg,.trans=&trans,.hw=&hw,.valid_ant=3};
 for(unsigned mplut=0;mplut<2;mplut++)for(unsigned failed=0;failed<2;failed++){
  fw.ucode_capa.mplut=mplut;failure=failed?-5:0;sends=length=last_id=0;memset(&m.last_bt_notif,255,sizeof(m.last_bt_notif));memset(&m.last_bt_ci_cmd,255,sizeof(m.last_bt_ci_cmd));
  int result=iwl_mvm_send_bt_init_conf(&m);if(sends!=1||memcmp(&m.last_bt_notif,&(struct iwl_bt_coex_prof_old_notif){0},sizeof(m.last_bt_notif)))abort();
  printf("I %u %u %d %u ",mplut,failed,result,length);hex();puts("");
 }
 failure=0;
 for(unsigned schema=0;schema<2;schema++)for(unsigned band=0;band<2;band++)for(unsigned ch=1;ch<=14;ch++)for(unsigned grade=0;grade<BT_MAX_AG;grade++)for(unsigned repeat=0;repeat<2;repeat++){
  if(!repeat)memset(&m.last_bt_ci_cmd,0,sizeof(m.last_bt_ci_cmd));fw.ucode_capa.schema2=schema;channel.band=band;channel.hw_value=ch;
  m.last_bt_notif.bt_activity_grading=grade;sends=length=last_id=0;
  iwl_mvm_bt_coex_notif_handle(&m);if(m.sta.bt_reduced_txpower||host_link.u.mgd.driver_smps_mode!=IEEE80211_SMPS_AUTOMATIC)abort();
  printf("C %u %u %u %u %u %u %u ",schema,band,ch,grade,repeat,sends,length);hex();puts("");
 }
 for(unsigned valid=1;valid<=3;valid++)for(unsigned last=0;last<2;last++)printf("N %u %u %u\n",valid,last,iwl_mvm_next_antenna(&m,valid,last));
 for(unsigned band=0;band<2;band++)for(unsigned grade=0;grade<BT_MAX_AG;grade++)for(unsigned last=0;last<2;last++){
  struct ieee80211_tx_info info={.band=band};m.last_bt_notif.bt_activity_grading=grade;m.mgmt_last_antenna_idx=last;
  printf("A %u %u %u %u\n",band,grade,last,iwl_mvm_get_tx_ant(&m,&info,NULL,cpu_to_le16(0xb0)));
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=False);unit=out/'linux-iwlwifi-coexistence.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-coexistence'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True,timeout=60)
with(out/'trace.txt').open('wb')as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True,timeout=60)
data=(out/'trace.txt').read_bytes();manifest={'linux_commit':'cc9de5d4b5ab6459f5774946aa3195ad51236fa8','sources':expected,'headers':headers,'whole_functions':functions,'records':len(data.splitlines()),'trace_sha256':hashlib.sha256(data).hexdigest(),'scope':__doc__}
review_functions=[('mvm/coex.c','iwl_mvm_rx_bt_coex_old_notif'),('mvm/coex.c','iwl_mvm_bt_coex_vif_change'),('mvm/ops.c','iwl_mvm_start_post_nvm'),('mvm/fw.c','iwl_mvm_up')]
review=out/'original-callbacks-source-review.c'
review.write_text('/* Complete original callbacks; retained for review, NOT compiled or executed. */\n'+''.join(function(file,name) for file,name in review_functions))
manifest['source_review_only_functions']=review_functions
manifest['source_review_only_sha256']=hashlib.sha256(review.read_bytes()).hexdigest()
construction_functions=[('net/mac80211/iface.c','ieee80211_if_add'),('net/mac80211/iface.c','ieee80211_sdata_init'),('net/mac80211/iface.c','ieee80211_setup_sdata'),('net/mac80211/mlme.c','ieee80211_sta_setup_sdata'),('net/mac80211/mlme.c','ieee80211_mgd_setup_link'),('net/mac80211/link.c','ieee80211_link_init'),('net/mac80211/link.c','ieee80211_link_setup')]
construction=out/'original-host-construction-source-review.c'
construction_text='/* GPL-2.0-only. Complete original construction spans; NOT compiled/executed. */\n'
for file in ['net/mac80211/iface.c','net/mac80211/mlme.c','net/mac80211/link.c','net/core/dev.c','include/linux/netdevice.h']:
 construction_text+='/* Original header from '+file+' */\n'+texts[file].split('\n#include',1)[0]+'\n'
construction_text+=''.join(function(file,name) for file,name in construction_functions)
construction_text+=extract('net/core/dev.c',r'^struct net_device \*alloc_netdev_mqs\([^{};]*?\)\s*\n\{')+'\n'
construction_text+=extract('include/linux/netdevice.h',r'^static inline void \*netdev_priv\([^{};]*?\)\s*\n\{')+'\n'
for name in ['ieee80211_link_data_managed','ieee80211_link_data','ieee80211_sub_if_data']:
 construction_text+=extract('net/mac80211/ieee80211_i.h',r'^struct '+name+r'\s*\{')+';\n'
construction.write_text(construction_text)
manifest['construction_review_only_functions']=construction_functions+[['net/core/dev.c','alloc_netdev_mqs'],['include/linux/netdevice.h','netdev_priv']]
manifest['construction_review_only_sha256']=hashlib.sha256(construction.read_bytes()).hexdigest()
manifest['cold_smps_initialization']='if_add→setup_sdata explicitly zeroes deflink.u (containing driver_smps_mode), then station setup. link_init/mgd_setup_link leave that field unchanged; req_smps is distinct. AUTOMATIC enum0 therefore remains initial driver request. Allocator and separate-link kzalloc path retained as additional source-only provenance.'
manifest['generated_fixture_license']='GPL-2.0-only: includes complete net/mac80211/ht.c function; Intel iwlwifi spans retain their dual-license provenance.'
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
